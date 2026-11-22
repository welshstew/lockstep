"""Leases: browse the lease tree, look one up, renew or revoke.

  GET  /api/leases?conn_id=&prefix=     one level of sys/leases/lookup (folders and lease IDs)
  POST /api/leases/lookup               {conn_id, lease_ids}: expiry, TTL, renewable, for up to 100 leases
  POST /api/leases/renew                {conn_id, lease_id, increment?}
  POST /api/leases/revoke               {conn_id, lease_ids}: revoke each (never by prefix)

Listing needs `sudo` on sys/leases/lookup; lookup, renew and revoke need update on
sys/leases/*. Renew and revoke are refused when LOCKSTEP_READ_ONLY is on, and audit-logged.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ..config import Settings, get_settings
from ..session import SessionData, load_session
from ..vault import VaultError
from .connections import client_for, get_connection, vault_http_error
from .guard import require_writable

router = APIRouter(prefix="/api/leases", tags=["leases"])
audit = logging.getLogger("lockstep.audit")

Sess = Annotated[SessionData, Depends(load_session)]
Conf = Annotated[Settings, Depends(get_settings)]
MAX_LIST = 2000


def _clean(prefix: str) -> str:
    prefix = prefix.strip().lstrip("/")
    if ".." in prefix.split("/"):
        raise HTTPException(400, detail={"message": "Invalid prefix"})
    return prefix if not prefix or prefix.endswith("/") else prefix + "/"


@router.get("")
async def tree(session: Sess, settings: Conf, conn_id: str, prefix: str = ""):
    prefix = _clean(prefix)
    note = None
    async with client_for(get_connection(session, conn_id), settings) as v:
        try:
            keys = ((await v.request("LIST", f"sys/leases/lookup/{prefix}")).get("data") or {}).get("keys") or []
        except VaultError as e:
            if e.status == 404:
                keys = []
            elif e.denied and not prefix:
                # The default policy's exact rule on sys/leases/lookup (update only) hides the top level
                # even from tokens with sudo below it: try each mount instead
                keys = await _per_mount(v)
                if keys is None:
                    raise HTTPException(403, detail={"message": "Listing leases needs sudo on sys/leases/lookup/*",
                                                     "denied": True}) from e
                note = "Listed mount by mount: the top level of sys/leases/lookup isn't listable with these policies."
            elif e.denied:
                raise HTTPException(403, detail={"message": "Listing leases needs sudo on sys/leases/lookup/*",
                                                 "denied": True}) from e
            else:
                raise vault_http_error(e) from e
    folders = sorted(k for k in keys if k.endswith("/"))
    leases = sorted(k for k in keys if not k.endswith("/"))
    return {"prefix": prefix, "folders": folders, "leases": [prefix + k for k in leases[:MAX_LIST]],
            "truncated": len(leases) > MAX_LIST, "note": note}


async def _per_mount(v) -> list[str] | None:
    """Top-level lease folders found by listing under each secrets engine and auth method.
    None when none of them can be listed either."""
    roots: list[str] = []
    for path, prefix in (("sys/mounts", ""), ("sys/auth", "auth/")):
        try:
            roots += [prefix + p for p in ((await v.request("GET", path)).get("data") or {})]
        except VaultError:
            pass
    if not roots:
        try:
            ui = (await v.request("GET", "sys/internal/ui/mounts")).get("data") or {}
            roots = list(ui.get("secret") or {}) + ["auth/" + p for p in ui.get("auth") or {}]
        except VaultError:
            return None
    sem = asyncio.Semaphore(16)
    allowed = False

    async def probe(r: str) -> str | None:
        nonlocal allowed
        async with sem:
            try:
                keys = ((await v.request("LIST", f"sys/leases/lookup/{r}")).get("data") or {}).get("keys") or []
                allowed = True
                return r if keys else None
            except VaultError as e:
                if e.status == 404:
                    allowed = True
                return None
    found = [r for r in await asyncio.gather(*(probe(r) for r in roots)) if r]
    if not allowed:
        return None
    # auth/token/ -> show as auth/ then token/, like Vault's own tree
    return sorted({(f.split("/", 1)[0] + "/") for f in found})


class LeaseIds(BaseModel):
    conn_id: str
    lease_ids: list[str] = Field(min_length=1, max_length=100)


@router.post("/lookup")
async def lookup(body: LeaseIds, session: Sess, settings: Conf):
    async with client_for(get_connection(session, body.conn_id), settings) as v:
        sem = asyncio.Semaphore(16)

        async def one(lid: str) -> dict:
            async with sem:
                try:
                    d = (await v.request("PUT", "sys/leases/lookup", json={"lease_id": lid}))["data"]
                    return {"id": lid, **{k: d.get(k) for k in ("issue_time", "expire_time", "last_renewal", "ttl", "renewable")}}
                except VaultError as e:
                    return {"id": lid, "error": e.message}
        return {"leases": list(await asyncio.gather(*(one(x) for x in body.lease_ids)))}


def _audit(event: str, conn, **fields) -> None:
    audit.info(json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "event": event,
                           "actor": {"identity": conn.display_name, "auth": conn.auth_method},
                           "target": {"vault": conn.name, "url": conn.url}, **fields}, sort_keys=True))


class Renew(BaseModel):
    conn_id: str
    lease_id: str = Field(min_length=1)
    increment: int | None = Field(default=None, ge=1, le=10 * 365 * 86400)  # seconds


@router.post("/renew")
async def renew(body: Renew, session: Sess, settings: Conf):
    require_writable(settings)
    conn = get_connection(session, body.conn_id)
    async with client_for(conn, settings) as v:
        try:
            res = await v.request("PUT", "sys/leases/renew", json={"lease_id": body.lease_id,
                                                                  **({"increment": body.increment} if body.increment else {})})
        except VaultError as e:
            _audit("lease.renew", conn, outcome="failed", lease_id=body.lease_id, error=e.message)
            raise vault_http_error(e) from e
    _audit("lease.renew", conn, outcome="applied", lease_id=body.lease_id, ttl=res.get("lease_duration"))
    return {"lease_id": res.get("lease_id") or body.lease_id, "ttl": res.get("lease_duration"),
            "renewable": res.get("renewable")}


@router.post("/revoke")
async def revoke(body: LeaseIds, session: Sess, settings: Conf):
    require_writable(settings)
    conn = get_connection(session, body.conn_id)
    results = []
    async with client_for(conn, settings) as v:
        for lid in body.lease_ids:
            try:
                await v.request("PUT", "sys/leases/revoke", json={"lease_id": lid})
                results.append({"id": lid, "revoked": True})
            except VaultError as e:
                results.append({"id": lid, "revoked": False, "error": e.message})
    _audit("lease.revoke", conn, outcome="applied" if all(r["revoked"] for r in results) else "partial",
           lease_ids=[r["id"] for r in results if r["revoked"]],
           failed=[r["id"] for r in results if not r["revoked"]])
    return {"results": results, "revoked": sum(r["revoked"] for r in results)}
