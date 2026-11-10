"""Secret-engine export and import (see exports.py for the format).

  POST /api/exports          export a mount/prefix with values (encrypted with a one-time key, by default)
  POST /api/exports/open     check an export file (decrypting it with its key) and return its contents
  POST /api/import/preview   apply import rules to an export, and plan writing it into a Vault
  POST /api/import/apply     write it, with check-and-set against the versions the preview saw

The server keeps nothing: the browser holds the opened export in memory and sends it with
each request. Imports merge into the target (keys only on the target are kept, nothing is
deleted) and every write is audit-logged without values, exactly like copies.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from .. import exports as ex
from ..config import Settings, get_settings
from ..session import SessionData, load_session
from ..vault import VaultError
from .compare import FileSide, Side
from .connections import client_for, get_connection, vault_http_error
from .sync import ApplyOut, Change, ChangePlan, _Ctx, apply_changes, evaluate

router = APIRouter(tags=["exports"])
audit = logging.getLogger("lockstep.audit")

Sess = Annotated[SessionData, Depends(load_session)]
Conf = Annotated[Settings, Depends(get_settings)]


def _tool() -> str:
    from importlib.metadata import PackageNotFoundError, version
    try:
        return f"lockstep {version('lockstep')}"
    except PackageNotFoundError:
        return "lockstep"


# --------------------------------------------------------------------------- export


class ExportRequest(BaseModel):
    side: Side
    rules: ex.ExportRules = Field(default_factory=ex.ExportRules)
    encrypt: bool = True


class ExportOut(BaseModel):
    filename: str
    file: dict[str, Any]  # the file's JSON (an encrypted envelope, or the plain export)
    key: str | None  # the one-time key: shown once, never stored
    secrets: int
    keys: int
    skipped: ex.ExportSkipped


@router.post("/api/exports", response_model=ExportOut)
async def create_export(body: ExportRequest, session: Sess, settings: Conf):
    if settings.export_mode == "off":
        raise HTTPException(403, detail={"message": "Exporting is turned off on this server."})
    if settings.export_mode == "encrypted" and not body.encrypt:
        raise HTTPException(403, detail={"message": "This server only allows encrypted exports."})
    conn = get_connection(session, body.side.conn_id)
    mount, prefix = body.side.norm()
    source = ex.ExportSource(vault=conn.name, url=None if conn.preset_id is not None else conn.url,
                             namespace=conn.namespace, mount=mount, identity=conn.display_name or conn.auth_method)
    async with client_for(conn, settings) as v:
        try:
            doc = await ex.build(v, mount=mount, prefix=prefix, rules=body.rules, source=source,
                                 max_secrets=settings.max_tree_secrets, tool=_tool())
        except VaultError as e:
            raise vault_http_error(e) from e
    key = None
    if body.encrypt:
        env, key = await asyncio.to_thread(ex.encrypt, doc)
        file = env.dump()
    else:
        file = doc.dump()
    n_keys = sum(len(s.data) for s in doc.secrets)
    audit.info(json.dumps({
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "event": "export", "outcome": "created",
        "actor": {"identity": conn.display_name, "auth": conn.auth_method},
        "source": {"vault": conn.name, "url": conn.url, "mount": mount, "prefix": prefix.rstrip("/")},
        "encrypted": body.encrypt, "secrets": len(doc.secrets), "keys": n_keys,
        "rules": body.rules.model_dump(mode="json"),
    }, sort_keys=True))
    return ExportOut(filename=ex.file_name(doc, body.encrypt), file=file, key=key, secrets=len(doc.secrets),
                     keys=n_keys, skipped=doc.skipped)


class OpenRequest(BaseModel):
    file: dict[str, Any]
    key: str | None = Field(default=None, max_length=200)


class OpenOut(BaseModel):
    export: ex.ExportDoc
    encrypted: bool


@router.post("/api/exports/open", response_model=OpenOut)
async def open_export(body: OpenRequest):
    try:
        doc = await asyncio.to_thread(ex.load, body.file, body.key)
    except ex.ExportError as e:
        raise HTTPException(400, detail={"message": str(e),
                                         "needs_key": body.file.get("format") == ex.ENCRYPTED_FORMAT}) from e
    return OpenOut(export=doc, encrypted=body.file.get("format") == ex.ENCRYPTED_FORMAT)


# --------------------------------------------------------------------------- import


class ImportRequest(BaseModel):
    export: ex.ExportDoc
    name: str = Field(default="export file", max_length=200)
    rules: ex.ImportRules = Field(default_factory=ex.ImportRules)
    target: Side


class ImportPreviewRequest(ImportRequest):
    reveal: bool = False


class Problem(BaseModel):
    path: str
    message: str


class Prepared(BaseModel):
    secrets: int
    ignored_paths: int
    ignored_keys: int
    paths_changed: int
    keys_changed: int
    values_changed: int
    problems: list[Problem]


class ImportPreviewOut(BaseModel):
    prepared: Prepared
    plans: list[ChangePlan]


class ImportApplyRequest(ImportRequest):
    # target version per (prepared) path, from the preview: the CAS check for each write
    expected: dict[str, int | None]
    confirm: bool


def _summary(prep: ex.Prepared) -> Prepared:
    return Prepared(secrets=len(prep.doc.secrets), ignored_paths=prep.ignored_paths, ignored_keys=prep.ignored_keys,
                    paths_changed=prep.paths_changed, keys_changed=prep.keys_changed,
                    values_changed=prep.values_changed,
                    problems=[Problem(path=p, message=m) for p, m in sorted(prep.problems.items())])


def _ctx(body: ImportRequest, prep: ex.Prepared, session: SessionData, settings: Settings) -> _Ctx:
    """Import = copying from the prepared export (left) into the target Vault (right)."""
    from .sync import SyncRequest
    req = SyncRequest.model_construct(left=FileSide(export=prep.doc, name=body.name), right=body.target, changes=[])
    return _Ctx(req, session, settings)


@router.post("/api/import/preview", response_model=ImportPreviewOut)
async def import_preview(body: ImportPreviewRequest, session: Sess, settings: Conf):
    prep = await asyncio.to_thread(ex.prepare, body.export, body.rules)
    async with _ctx(body, prep, session, settings) as ctx:
        sem = asyncio.Semaphore(16)

        async def one(path: str):
            async with sem:
                ch = Change(path=path, direction="left_to_right")
                return (await evaluate(ctx, ch, body.reveal, any_target_version=True))[0]

        plans = list(await asyncio.gather(*(one(s.path) for s in prep.doc.secrets)))
    return ImportPreviewOut(prepared=_summary(prep), plans=plans)


@router.post("/api/import/apply", response_model=ApplyOut)
async def import_apply(body: ImportApplyRequest, session: Sess, settings: Conf):
    if not body.confirm:
        raise HTTPException(400, detail={"message": "Importing requires confirm=true"})
    prep = await asyncio.to_thread(ex.prepare, body.export, body.rules)
    paths = {s.path for s in prep.doc.secrets}
    unknown = sorted(set(body.expected) - paths)
    if unknown:
        raise HTTPException(400, detail={"message": "The rules or the file changed since the preview: "
                                                    f"{', '.join(unknown[:5])} no longer in it. Preview again."})
    changes = [Change(path=p, direction="left_to_right", expected_target_version=v)
               for p, v in sorted(body.expected.items())]
    if not changes:
        raise HTTPException(400, detail={"message": "Nothing to import."})
    async with _ctx(body, prep, session, settings) as ctx:
        return await apply_changes(ctx, changes)
