"""Destroying secrets: permanently deleting every version and the metadata of KV v2 secrets.

  POST /api/destroy   destroy the listed secrets on one side. Needs confirm=true

This is the one thing in Lockstep that can't be undone: `vault kv undelete` can't bring a
destroyed secret back. So:
  * It's off unless LOCKSTEP_ALLOW_DESTROY is true (the default), and always needs `confirm`.
    The web app also makes the user type a confirmation phrase.
  * Each secret is checked against the version the user saw when comparing: if it changed
    since (a new version was written), it's a conflict and isn't destroyed.
  * Every attempt is audit-logged (who, what, where, the version, the outcome). No values are
    read: only the metadata.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, model_validator

from ..config import Settings, get_settings
from ..session import SessionData, load_session
from ..vault import VaultError
from .compare import Side
from .connections import client_for, get_connection
from .guard import require_writable
from .. import writepolicy

router = APIRouter(prefix="/api", tags=["destroy"])
audit = logging.getLogger("lockstep.audit")

Sess = Annotated[SessionData, Depends(load_session)]
Conf = Annotated[Settings, Depends(get_settings)]

MAX_DESTROY = 5000  # the most secrets one comparison lists per side (LOCKSTEP_MAX_TREE_SECRETS default)


class DestroyItem(BaseModel):
    path: str = Field(min_length=1, max_length=4096)  # relative to the side's prefix
    expected_version: int | None = None  # the current version the user saw; None: don't check


class DestroyRequest(BaseModel):
    side: Side  # a Vault: an export file can't be changed
    secrets: list[DestroyItem] = Field(min_length=1, max_length=MAX_DESTROY)
    confirm: bool

    @model_validator(mode="after")
    def _check(self):
        paths = [s.path for s in self.secrets]
        if len(set(paths)) != len(paths):
            raise ValueError("a secret is listed more than once")
        if any(p.startswith("/") or p.endswith("/") or "//" in p for p in paths):
            raise ValueError("secret paths can't start or end with / or contain //")
        return self


class DestroyResult(BaseModel):
    path: str
    target: str  # "<conn name> · <mount>/<path>"
    status: Literal["destroyed", "absent", "conflict", "denied", "error"]
    version: int | None = None  # the current version when destroyed
    versions: int | None = None  # how many versions were destroyed
    message: str = ""


class DestroyOut(BaseModel):
    results: list[DestroyResult]
    summary: dict[str, int]


@router.post("/destroy", response_model=DestroyOut)
async def destroy(body: DestroyRequest, session: Sess, settings: Conf):
    require_writable(settings)
    if not settings.allow_destroy:
        raise HTTPException(403, detail={"message": "Destroying secrets is turned off on this server (LOCKSTEP_ALLOW_DESTROY)."})
    if not body.confirm:
        raise HTTPException(400, detail={"message": "Destroying secrets requires confirm=true"})
    conn = get_connection(session, body.side.conn_id)
    mount, prefix = body.side.norm()
    writepolicy.check(settings, conn, [f"{mount}/{prefix}{i.path}" for i in body.secrets], "destroy", "destroy")
    if why := writepolicy.needs_plan(settings, conn):
        writepolicy.log_refusal(conn, f"{mount}/{prefix}", "destroy", "destroy", why)
        raise HTTPException(403, detail={"message": why, "write_policy": True})
    sem = asyncio.Semaphore(8)

    async with client_for(conn, settings) as v:
        async def one(item: DestroyItem) -> DestroyResult:
            path = prefix + item.path
            res = DestroyResult(path=item.path, target=f"{conn.name} · {mount}/{path}", status="error")
            async with sem:
                try:
                    meta = await v.kv_metadata(mount, path)
                except VaultError as e:
                    if e.status == 404:
                        res.status, res.message = "absent", "Not there (already destroyed?)"
                    else:
                        res.status, res.message = ("denied" if e.denied else "error"), e.message
                    _audit(conn, mount, path, res)
                    return res
                res.version = meta.get("current_version")
                res.versions = len(meta.get("versions") or {})
                if item.expected_version is not None and res.version != item.expected_version:
                    res.status = "conflict"
                    res.message = (f"Changed since you compared (expected v{item.expected_version}, now "
                                   f"v{res.version}). Compare again before destroying.")
                else:
                    try:
                        await v.kv_destroy_all(mount, path)
                        res.status = "destroyed"
                    except VaultError as e:
                        res.status, res.message = ("denied" if e.denied else "error"), e.message
            _audit(conn, mount, path, res)
            return res

        results = list(await asyncio.gather(*(one(s) for s in body.secrets)))
    summary = {s: sum(r.status == s for r in results) for s in ("destroyed", "absent", "conflict", "denied", "error")}
    return DestroyOut(results=results, summary=summary)


def _audit(conn, mount: str, path: str, res: DestroyResult) -> None:
    audit.info(json.dumps({
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "event": "destroy",
        "outcome": res.status,
        "actor": {"identity": conn.display_name, "auth": conn.auth_method, "entity_id": conn.entity_id, "accessor": conn.accessor},
        "target": {"vault": conn.name, "url": conn.url, "mount": mount,
                   "path": path, "version": res.version, "versions": res.versions},
        "message": res.message,
    }, sort_keys=True))
