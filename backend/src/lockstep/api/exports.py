"""Secret-engine export and import (see exports.py for the format).

  POST /api/exports          export a mount/prefix with values (encrypted with a one-time key, by default)
  POST /api/exports/open     check an export file (decrypting it with its key) and return its contents
  POST /api/import/preview   apply import rules to an export, and plan writing it into a Vault
  POST /api/import/apply     write it, with check-and-set against the versions the preview saw

With delete_missing, an import makes the target match the file: each imported secret is
written with only the file's keys, and secrets under the target prefix that the file doesn't
have are soft-deleted, except paths the file marks `keep`. Apply only deletes what the preview
listed, at the version the preview saw.

The server keeps nothing: the browser holds the opened export in memory and sends it with
each request. Imports merge into the target (keys only on the target are kept, nothing is
deleted) and every write is audit-logged without values, exactly like copies.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import time
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field, ValidationError

from .. import exports as ex
from .. import kvdump, writepolicy
from ..config import Settings, get_settings
from ..session import SessionData, load_session
from ..reveal import reveal
from ..vault import VaultError
from .compare import FileSide, Side
from .connections import client_for, get_connection, vault_http_error
from .guard import require_writable
from .sync import ApplyOut, Change, ChangePlan, _Ctx, apply_changes, evaluate, shown_in

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
    # How to encrypt (with encrypt=true): a passphrase, or age public keys (pasted, or the teams
    # in LOCKSTEP_EXPORT_RECIPIENTS by name). Neither: a one-time key.
    passphrase: str | None = Field(default=None, max_length=1024)
    recipients: list[str] = Field(default_factory=list, max_length=ex.MAX_RECIPIENTS)
    teams: list[str] = Field(default_factory=list, max_length=20)


class ExportOut(BaseModel):
    filename: str
    file: dict[str, Any]  # the file's JSON (an encrypted envelope, or the plain export)
    scheme: Literal["key", "passphrase", "age", "none"] = "key"
    key: str | None  # the one-time key: shown once, never stored
    secrets: int
    keys: int
    skipped: ex.ExportSkipped


def _check(body: ExportRequest, session: SessionData, settings: Settings):
    """The connection and age keys for an export, after the export policy and the protection asked for."""
    conn = get_connection(session, body.side.conn_id)
    recipients = _recipients(body, settings) if body.encrypt else []
    if body.encrypt and body.passphrase is not None:
        if recipients:
            raise HTTPException(400, detail={"message": "Choose a passphrase or age keys, not both."})
        try:
            ex.check_passphrase(body.passphrase)
        except ex.ExportError as e:
            raise HTTPException(400, detail={"message": str(e)}) from e
    mode, preset = writepolicy.export_mode(settings, conn)
    where = f" for {preset.name}" if preset else ""
    if mode == "off":
        raise HTTPException(403, detail={"message": f"Exporting is turned off{where} on this Lockstep server."})
    if mode == "encrypted" and not body.encrypt:
        raise HTTPException(403, detail={"message": f"This Lockstep server only allows encrypted exports{where}."})
    return conn, recipients


def _scheme(body: ExportRequest, recipients: list[str]) -> str:
    return "none" if not body.encrypt else "age" if recipients else "passphrase" if body.passphrase is not None else "key"


def _source(conn, mount: str) -> ex.ExportSource:
    return ex.ExportSource(vault=conn.name, url=None if conn.preset_id is not None else conn.url,
                           namespace=conn.namespace, mount=mount, identity=conn.display_name or conn.auth_method)


def _seal(packed: ex.Packed, scheme: str, body: ExportRequest, recipients: list[str]) -> tuple[dict, str | None]:
    if scheme == "age":
        return ex.seal_age(packed, recipients).dump(), None
    if scheme == "passphrase":
        return ex.seal_passphrase(packed, body.passphrase or "").dump(), None
    env, key = ex.seal_key(packed)
    return env.dump(), key


def _audit(conn, mount: str, prefix: str, body: ExportRequest, scheme: str, recipients: list[str],
           secrets: int, keys: int, outcome: str = "created") -> None:
    audit.info(json.dumps({
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "event": "export", "outcome": outcome,
        "actor": {"identity": conn.display_name, "auth": conn.auth_method, "entity_id": conn.entity_id, "accessor": conn.accessor},
        "source": {"vault": conn.name, "url": conn.url, "mount": mount, "prefix": prefix.rstrip("/")},
        "encrypted": body.encrypt, "scheme": scheme, "secrets": secrets, "keys": keys,
        **({"recipients": recipients, "teams": body.teams} if scheme == "age" else {}),
        "rules": body.rules.model_dump(mode="json"),
    }, sort_keys=True))


@router.post("/api/exports", response_model=ExportOut)
async def create_export(body: ExportRequest, session: Sess, settings: Conf):
    """The export in one response. /api/exports/stream sends the same, without holding it in memory."""
    conn, recipients = _check(body, session, settings)
    scheme = _scheme(body, recipients)
    mount, prefix = body.side.norm()
    async with client_for(conn, settings) as v:
        try:
            doc = await ex.build(v, mount=mount, prefix=prefix, rules=body.rules, source=_source(conn, mount),
                                 max_secrets=settings.max_tree_secrets, tool=_tool())
        except VaultError as e:
            raise vault_http_error(e) from e
    key = None
    if scheme == "none":
        file = doc.dump()
    else:
        try:
            file, key = await asyncio.to_thread(_seal, ex.pack(doc), scheme, body, recipients)
        except ex.ExportError as e:
            raise HTTPException(400, detail={"message": str(e)}) from e
    n_keys = sum(len(s.data or {}) for s in doc.secrets)
    _audit(conn, mount, prefix, body, scheme, recipients, len(doc.secrets), n_keys)
    return ExportOut(filename=ex.file_name(doc, body.encrypt), file=file, scheme=scheme, key=key,
                     secrets=len(doc.secrets), keys=n_keys, skipped=doc.skipped)


@router.post("/api/exports/stream")
async def stream_export(body: ExportRequest, session: Sess, settings: Conf):
    """The export as NDJSON, for big mounts: progress lines ({"progress": {"done", "total"}}), then
    {"result": <as /api/exports>} (or {"error": …}). A plain export streams straight into the result
    line as secrets are read; an encrypted one holds only the compressed export until it's sealed.
    Either way the server never holds the export as a document, and bytes keep flowing for proxies."""
    conn, recipients = _check(body, session, settings)
    scheme = _scheme(body, recipients)
    mount, prefix = body.side.norm()
    stack = contextlib.AsyncExitStack()
    v = await stack.enter_async_context(client_for(conn, settings))
    try:  # listing errors become a normal HTTP error, not a stream
        base = ex._norm(prefix)
        tree = await v.kv_tree(mount, f"{base}/" if base else "", max_secrets=settings.max_tree_secrets)
    except VaultError as e:
        await stack.aclose()
        raise vault_http_error(e) from e
    except BaseException:
        await stack.aclose()
        raise

    queue: asyncio.Queue[bytes | None] = asyncio.Queue(maxsize=64)

    async def put(b: bytes) -> None:
        await queue.put(b)

    async def progress(done: int, total: int) -> None:
        await queue.put(json.dumps({"progress": {"done": done, "total": total}}).encode() + b"\n")

    def summary(built: ex.Built, key: str | None) -> dict:
        return {"filename": ex.file_name(built, body.encrypt), "scheme": scheme, "key": key,
                "secrets": built.secrets, "keys": built.keys, "skipped": built.skipped.model_dump(mode="json")}

    state = {"outcome": "interrupted", "secrets": 0, "keys": 0}

    async def produce() -> None:
        common = dict(mount=mount, prefix=prefix, rules=body.rules, source=_source(conn, mount),
                      max_secrets=settings.max_tree_secrets, tool=_tool(), tree=tree)
        try:
            if scheme == "none":
                await put(b'{"result":{"file":')
                built = await ex.stream(v, write=put, **common)
                await put(b"," + json.dumps(summary(built, None))[1:].encode() + b"}\n")
            else:
                packer = ex.Packer()
                built = await ex.stream(v, write=packer.write, progress=progress, **common)
                try:
                    file, key = await asyncio.to_thread(_seal, packer.done(built), scheme, body, recipients)
                except ex.ExportError as e:
                    await put(json.dumps({"error": {"status": 400, "message": str(e)}}).encode() + b"\n")
                    state["outcome"] = "failed"
                    return
                await put(json.dumps({"result": {"file": file, **summary(built, key)}}).encode() + b"\n")
            state.update(outcome="created", secrets=built.secrets, keys=built.keys)
        except VaultError as e:
            state["outcome"] = "failed"
            await put(json.dumps({"error": {"status": 502, "message": f"The export failed: {e}"}}).encode() + b"\n")
        finally:
            await queue.put(None)

    async def body_iter():
        task = asyncio.create_task(produce())
        try:
            while (chunk := await queue.get()) is not None:
                yield chunk
            await task
        finally:
            if not task.done():
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await task
            await stack.aclose()
            _audit(conn, mount, prefix, body, scheme, recipients, state["secrets"], state["keys"], state["outcome"])

    return StreamingResponse(body_iter(), media_type="application/x-ndjson",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


def _recipients(body: ExportRequest, settings: Settings) -> list[str]:
    """The age public keys to encrypt to: the named teams' and the pasted ones, checked."""
    teams = {t.name: t for t in settings.export_recipients}
    unknown = [n for n in body.teams if n not in teams]
    if unknown:
        raise HTTPException(400, detail={"message": f"No team called {unknown[0]} on this Lockstep server."})
    keys = [k for n in body.teams for k in teams[n].recipients] + list(body.recipients)
    if not keys:
        return []
    try:
        return ex.parse_recipients(keys)
    except ex.ExportError as e:
        raise HTTPException(400, detail={"message": str(e)}) from e


class OpenRequest(BaseModel):
    file: dict[str, Any]
    # The one-time key, the passphrase, or an age identity (or a whole age key file)
    key: str | None = Field(default=None, max_length=8000)


class OpenOut(BaseModel):
    export: ex.ExportDoc
    encrypted: bool


@router.post("/api/exports/open", response_model=OpenOut)
async def open_export(body: OpenRequest):
    try:
        doc = await asyncio.to_thread(ex.load, body.file, body.key)
    except ex.ExportError as e:
        raise HTTPException(400, detail={"message": str(e),
                                         "needs_key": body.file.get("format") == ex.ENCRYPTED_FORMAT,
                                         "scheme": body.file.get("scheme", "key")}) from e
    return OpenOut(export=doc, encrypted=body.file.get("format") == ex.ENCRYPTED_FORMAT)


class KvGetFile(BaseModel):
    name: str = Field(min_length=1, max_length=1000)  # the file name, or its path in a folder
    content: Any


class KvGetRequest(BaseModel):
    files: list[KvGetFile] = Field(min_length=1, max_length=kvdump.MAX_FILES)
    name: str = Field(default="vault kv get", max_length=200)  # shown as where the export came from


@router.post("/api/exports/from-kv-get", response_model=OpenOut)
async def from_kv_get(body: KvGetRequest):
    """Read `vault kv get -format=json` output (one file, a folder's files, or an object of
    path: output) as an export, to compare against or import. Nothing is kept."""
    try:
        doc = await asyncio.to_thread(kvdump.convert, [(f.name, f.content) for f in body.files], body.name, _tool())
    except ex.ExportError as e:
        raise HTTPException(400, detail={"message": str(e)}) from e
    except ValidationError as e:
        raise HTTPException(400, detail={"message": f"Couldn't read it: {e.errors()[0]['msg']}"}) from e
    return OpenOut(export=doc, encrypted=False)


# --------------------------------------------------------------------------- import


class ImportRequest(BaseModel):
    export: ex.ExportDoc
    name: str = Field(default="export file", max_length=200)
    rules: ex.ImportRules = Field(default_factory=ex.ImportRules)
    target: Side
    # Make the target match the file: remove keys it doesn't have, delete secrets it doesn't have
    delete_missing: bool = False


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
    kept: int = 0  # keep entries: target secrets left as they are
    problems: list[Problem]


class ImportPreviewOut(BaseModel):
    prepared: Prepared
    plans: list[ChangePlan]  # writes, then (with delete_missing) deletes
    warnings: list[str] = []


class ImportApplyRequest(ImportRequest):
    # target version per (prepared) path, from the preview: the CAS check for each write
    expected: dict[str, int | None]
    confirm: bool


def _summary(prep: ex.Prepared) -> Prepared:
    return Prepared(secrets=len(prep.doc.secrets), ignored_paths=prep.ignored_paths, ignored_keys=prep.ignored_keys,
                    paths_changed=prep.paths_changed, keys_changed=prep.keys_changed,
                    values_changed=prep.values_changed, kept=len(prep.kept),
                    problems=[Problem(path=p, message=m) for p, m in sorted(prep.problems.items())])


def _ctx(body: ImportRequest, prep: ex.Prepared, session: SessionData, settings: Settings) -> _Ctx:
    """Import = copying from the prepared export (left) into the target Vault (right)."""
    from .sync import SyncRequest
    req = SyncRequest.model_construct(left=FileSide(export=prep.doc, name=body.name), right=body.target, changes=[])
    return _Ctx(req, session, settings)


class ImportScopeError(Exception):
    """The target can't be listed completely, so what to delete can't be worked out."""


async def deletions(ctx: _Ctx, prep: ex.Prepared, max_secrets: int) -> tuple[list[str], list[str]]:
    """Target paths (relative to its prefix) that the import doesn't have, keep or hold, and
    warnings about folders that couldn't be listed (nothing in those is deleted)."""
    tree = await ctx.rv.kv_tree(ctx.rmount, ctx.rprefix, max_secrets=max_secrets)
    where = f"{ctx.rmount}/{ctx.rprefix}".rstrip("/")
    if tree.truncated:
        raise ImportScopeError(f"{where} has more than {max_secrets} secrets, so Lockstep can't list them all to "
                               "work out what to delete. Import under a narrower prefix.")
    protected = {s.path for s in prep.doc.secrets} | set(prep.kept) | prep.held
    rel = [p[len(ctx.rprefix):] for p in tree.secrets]
    warnings = [f"Couldn't list {ctx.rmount}/{d}: nothing in it is deleted." for d in tree.denied]
    return [p for p in rel if p not in protected], warnings


async def plan_import(ctx: _Ctx, prep: ex.Prepared, delete_missing: bool, reveal: bool,
                      max_secrets: int) -> tuple[list[ChangePlan], list[str]]:
    """Plans for every write (and, with delete_missing, every delete), from fresh reads.
    Used by the preview and by the CLI."""
    changes = [Change(path=s.path, direction="left_to_right", exact=delete_missing) for s in prep.doc.secrets]
    warnings: list[str] = []
    if delete_missing:
        gone, warnings = await deletions(ctx, prep, max_secrets)
        changes += [Change(path=p, direction="left_to_right", delete=True) for p in gone]
    sem = asyncio.Semaphore(16)

    async def one(ch: Change):
        async with sem:
            return (await evaluate(ctx, ch, reveal, any_target_version=True))[0]

    return list(await asyncio.gather(*(one(c) for c in changes))), warnings


def import_changes(prep: ex.Prepared, expected: dict[str, int | None], delete_missing: bool) -> list[Change]:
    """The changes to apply: the previewed paths with the versions the preview saw. Writes
    first, then deletes. Raises ValueError for a path that's no longer one or the other."""
    imported = {s.path for s in prep.doc.secrets}
    protected = imported | set(prep.kept) | prep.held
    writes, deletes, unknown = [], [], []
    for p, v in sorted(expected.items()):
        if p in imported:
            writes.append(Change(path=p, direction="left_to_right", expected_target_version=v, exact=delete_missing))
        elif delete_missing and p not in protected:
            deletes.append(Change(path=p, direction="left_to_right", expected_target_version=v, delete=True))
        else:
            unknown.append(p)
    if unknown:
        raise ValueError(f"The rules or the file changed since the preview: {', '.join(unknown[:5])} "
                         "no longer in it. Preview again.")
    return writes + deletes


@router.post("/api/import/preview", response_model=ImportPreviewOut)
async def import_preview(body: ImportPreviewRequest, session: Sess, settings: Conf):
    prep = await asyncio.to_thread(ex.prepare, body.export, body.rules)
    async with _ctx(body, prep, session, settings) as ctx:
        try:
            plans, warnings = await plan_import(ctx, prep, body.delete_missing, body.reveal, settings.max_tree_secrets)
        except ImportScopeError as e:
            raise HTTPException(400, detail={"message": str(e)}) from e
        except VaultError as e:
            raise vault_http_error(e) from e
        if body.reveal:  # the target's current values (the file's were already the user's)
            reveal(settings, "import.preview", shown_in(ctx, plans, ("target",)))
    return ImportPreviewOut(prepared=_summary(prep), plans=plans, warnings=warnings)


@router.post("/api/import/apply", response_model=ApplyOut)
async def import_apply(body: ImportApplyRequest, session: Sess, settings: Conf):
    require_writable(settings)
    if not body.confirm:
        raise HTTPException(400, detail={"message": "Importing requires confirm=true"})
    prep = await asyncio.to_thread(ex.prepare, body.export, body.rules)
    try:
        changes = import_changes(prep, body.expected, body.delete_missing)
    except ValueError as e:
        raise HTTPException(400, detail={"message": str(e)}) from e
    if not changes:
        raise HTTPException(400, detail={"message": "Nothing to import."})
    async with _ctx(body, prep, session, settings) as ctx:
        return await apply_changes(ctx, changes)
