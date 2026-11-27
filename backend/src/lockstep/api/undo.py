"""Undo plans: put back what an apply changed, without Lockstep ever keeping old values.

After a copy or a plan is applied, **Make an undo plan** turns the results into a signed file.
For each secret written, it records the version the apply replaced and the version it left. When
the undo plan is applied, the old version is read from Vault's own KV history and written back
with check-and-set against the version the apply left. A secret the apply created is
soft-deleted, and one it soft-deleted is undeleted.

Undo stops cleanly, with nothing written for that secret, when the secret has moved on since
(someone wrote it again) or the old version has been deleted or destroyed. Like a sync plan,
applying stops at the first secret that isn't put back.

  POST /api/undo          make an undo plan from apply results
  POST /api/undo/check    check it against the Vaults now
  POST /api/undo/apply    put the old versions back (confirm=true)
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, ValidationError

from .. import plansign, writepolicy
from ..config import Settings, get_settings
from ..plansign import Issuer
from ..session import Connection, SessionData, load_session
from ..vault import VaultError
from .connections import client_for, get_connection
from .guard import require_writable
from .plans import PlanVault, _describe, _matches, _vault_of

router = APIRouter(prefix="/api/undo", tags=["plans"])
audit = logging.getLogger("lockstep.audit")

Sess = Annotated[SessionData, Depends(load_session)]
Conf = Annotated[Settings, Depends(get_settings)]

FORMAT = "lockstep.undo-plan"
VERSION = 1
MAX_ENTRIES = 500


class UndoEntry(BaseModel):
    vault: PlanVault  # the Vault and mount written (prefix unused)
    path: str  # within the mount
    # restore: write `restore_version` back; delete: the apply created the secret, so soft-delete it;
    # undelete: the apply soft-deleted `restore_version`, so undelete it
    action: Literal["restore", "delete", "undelete"]
    restore_version: int | None = None
    current_version: int  # the version the apply left: undo only while it's still the current one


class UndoPlan(BaseModel):
    format: Literal["lockstep.undo-plan"] = FORMAT
    version: Literal[1] = VERSION
    id: str
    created_at: str
    issuer: Issuer | None = None
    audience: list[str] = []
    not_before: str | None = None
    expires_at: str | None = None
    created_by: str = ""
    created_by_entity: str = ""
    undoes: str | None = None  # the sync plan this undoes, if it was one
    entries: list[UndoEntry] = Field(min_length=1, max_length=MAX_ENTRIES)
    signature: str = ""


class AppliedWrite(BaseModel):
    """One applied result, as /api/sync/apply or /api/plans/apply returned it."""
    conn_id: str
    mount: str = Field(min_length=1)
    path: str = Field(min_length=1)
    action: Literal["write", "delete"] = "write"
    old_version: int | None = None
    new_version: int | None = None


class CreateRequest(BaseModel):
    writes: list[AppliedWrite] = Field(min_length=1, max_length=MAX_ENTRIES)
    undoes: str | None = Field(default=None, max_length=100)


class PlanRequest(BaseModel):
    plan: dict[str, Any]
    conn_ids: list[str] = Field(min_length=1, max_length=4)  # signed-in connections to the Vaults it names


class ApplyRequest(PlanRequest):
    confirm: bool


class EntryCheck(BaseModel):
    target: str  # "<vault> · <mount>/<path>"
    action: str
    status: Literal["ready", "stale", "denied", "error", "applied", "skipped"]
    message: str = ""
    new_version: int | None = None


class CheckOut(BaseModel):
    status: Literal["ready", "stale", "denied", "error"]
    message: str
    entries: list[EntryCheck]


class ApplyOut(BaseModel):
    plan_id: str
    outcome: Literal["applied", "partially_applied", "not_applied"]
    message: str
    entries: list[EntryCheck]


# --------------------------------------------------------------------------- signing


def _key(settings: Settings) -> bytes:
    return hashlib.sha256(b"lockstep-undo-plan-v1\0" + settings.session_key.encode()).digest()


def _canonical(data: dict) -> bytes:
    body = {k: v for k, v in data.items() if k != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def load(raw: dict[str, Any], settings: Settings) -> UndoPlan:
    if raw.get("format") != FORMAT:
        raise HTTPException(400, detail={"message": "This isn't a Lockstep undo plan file."})
    try:
        issuer = Issuer.model_validate(raw["issuer"]) if raw.get("issuer") else None
    except ValidationError as e:
        raise HTTPException(400, detail={"message": plansign.TAMPERED}) from e
    plansign.verify(_canonical(raw), str(raw.get("signature", "")), issuer, settings, _key(settings))
    try:
        plan = UndoPlan.model_validate(raw)
    except ValidationError as e:
        raise HTTPException(400, detail={"message": f"The undo plan is malformed: {e.errors()[0]['msg']}"}) from e
    plansign.check_valid(settings, plan.not_before, plan.expires_at, plan.audience)
    return plan


# --------------------------------------------------------------------------- checking


def _where(e: UndoEntry) -> str:
    return f"{_describe(e.vault)} · {e.vault.mount}/{e.path}"


async def _state(v, e: UndoEntry) -> tuple[str, str]:
    """("ready" | "stale", why) for one entry, from the secret's metadata now."""
    try:
        meta = await v.kv_metadata(e.vault.mount, e.path)
    except VaultError as err:
        if err.status == 404:
            return "stale", "The secret isn't there any more."
        raise
    current = meta.get("current_version")
    versions = meta.get("versions") or {}
    if current != e.current_version:
        return "stale", (f"Changed since the apply (it left v{e.current_version}, now v{current}): "
                         "undoing would overwrite someone else's change.")
    if e.action == "restore":
        old = versions.get(str(e.restore_version)) or {}
        if not old or old.get("destroyed"):
            return "stale", f"v{e.restore_version} has been destroyed, so it can't be put back."
        if old.get("deletion_time"):
            return "stale", f"v{e.restore_version} has been deleted. Undelete it in Browse first, or leave it."
    if e.action == "undelete" and not (versions.get(str(e.restore_version)) or {}).get("deletion_time"):
        return "stale", f"v{e.restore_version} isn't deleted any more."
    if e.action == "delete" and (versions.get(str(current)) or {}).get("deletion_time"):
        return "stale", "It's already deleted."
    return "ready", ""


def _connection_for(e: UndoEntry, conns: list[Connection], settings: Settings) -> Connection:
    for c in conns:
        if _matches(c, e.vault, settings):
            return c
    raise HTTPException(409, detail={"message": f"This undo plan writes to {_describe(e.vault)}: sign in to it on one side first."})


async def _check(plan: UndoPlan, conns: list[Connection], settings: Settings) -> list[EntryCheck]:
    out = []
    for e in plan.entries:
        conn = _connection_for(e, conns, settings)
        async with client_for(conn, settings) as v:
            try:
                status, why = await _state(v, e)
            except VaultError as err:
                status, why = ("denied" if err.denied else "error"), err.message
        if status == "ready" and (refused := writepolicy.refusal(settings, conn, f"{e.vault.mount}/{e.path}")):
            status, why = "denied", refused
        out.append(EntryCheck(target=_where(e), action=e.action, status=status, message=why))  # type: ignore[arg-type]
    return out


def _summary(checks: list[EntryCheck]) -> tuple[str, str]:
    for status, text in (("stale", "changed since the apply"), ("denied", "can't be written"), ("error", "couldn't be checked")):
        n = sum(c.status == status for c in checks)
        if n:
            return status, f"{n} of {len(checks)} secret(s) {text}. Nothing will be put back."
    return "ready", f"All {len(checks)} secret(s) are as the apply left them, and their old versions are there."


# --------------------------------------------------------------------------- routes


@router.post("", response_model=UndoPlan)
async def create(body: CreateRequest, session: Sess, settings: Conf):
    entries: list[UndoEntry] = []
    for w in body.writes:
        conn = get_connection(session, w.conn_id)
        vault, preset = _vault_of(conn, settings)
        pv = PlanVault(vault=vault, preset=preset, namespace=conn.namespace or None, mount=w.mount.strip("/"),
                       identity=conn.display_name or conn.auth_method, entity_id=conn.entity_id, accessor=conn.accessor)
        if w.action == "delete":
            if w.old_version is None:
                continue
            entries.append(UndoEntry(vault=pv, path=w.path, action="undelete", restore_version=w.old_version,
                                     current_version=w.old_version))
        elif w.new_version is not None:
            entries.append(UndoEntry(vault=pv, path=w.path, action="restore" if w.old_version else "delete",
                                     restore_version=w.old_version or None, current_version=w.new_version))
    if not entries:
        raise HTTPException(400, detail={"message": "Nothing to undo: no secret was written."})
    plan = UndoPlan(id=str(uuid.uuid4()), created_at=plansign.now_iso(), undoes=body.undoes, entries=entries,
                    created_by=entries[0].vault.identity, created_by_entity=entries[0].vault.entity_id,
                    **plansign.validity(settings))
    conns = [get_connection(session, w.conn_id) for w in body.writes]
    problems = [f"{c.target}: {c.message}" for c in await _check(plan, conns, settings) if c.status != "ready"]
    if problems:
        raise HTTPException(409, detail={"message": "Some of these can't be undone: " + " | ".join(problems)})
    plan.signature = plansign.sign(_canonical(plan.model_dump(mode="json")), settings, _key(settings))
    return plan


@router.post("/check", response_model=CheckOut)
async def check(body: PlanRequest, session: Sess, settings: Conf):
    plan = load(body.plan, settings)
    checks = await _check(plan, [get_connection(session, c) for c in body.conn_ids], settings)
    status, message = _summary(checks)
    return CheckOut(status=status, message=message, entries=checks)  # type: ignore[arg-type]


@router.post("/apply", response_model=ApplyOut)
async def apply(body: ApplyRequest, session: Sess, settings: Conf):
    require_writable(settings)
    if not body.confirm:
        raise HTTPException(400, detail={"message": "Applying an undo plan requires confirm=true"})
    plan = load(body.plan, settings)
    conns = [get_connection(session, c) for c in body.conn_ids]
    checks = await _check(plan, conns, settings)
    status, message = _summary(checks)
    if status != "ready":
        raise HTTPException(409, detail={"message": message, "entries": [c.model_dump() for c in checks]})
    results: list[EntryCheck] = []
    stopped = False
    for e in plan.entries:  # one at a time, stopping at the first that isn't put back
        res = EntryCheck(target=_where(e), action=e.action, status="skipped",
                         message="Not attempted: an earlier secret wasn't put back.")
        if not stopped:
            conn = _connection_for(e, conns, settings)
            res.status, res.message = "error", ""
            async with client_for(conn, settings) as v:
                try:
                    state, why = await _state(v, e)  # again, just before writing
                    if state != "ready":
                        res.status, res.message = "stale", why
                    elif e.action == "restore":
                        old = await v.kv_read(e.vault.mount, e.path, version=e.restore_version)
                        if old.state != "present":
                            res.status, res.message = "stale", f"v{e.restore_version} can't be read any more."
                        else:
                            res.new_version = await v.kv_write(e.vault.mount, e.path, old.data or {}, cas=e.current_version)
                            res.status = "applied"
                    elif e.action == "delete":
                        await v.kv_delete(e.vault.mount, e.path)
                        res.status = "applied"
                    else:
                        await v.kv_undelete(e.vault.mount, e.path, [e.restore_version or 0])
                        res.status = "applied"
                except VaultError as err:
                    if err.status == 400 and "check-and-set" in err.message:
                        res.status, res.message = "stale", "Changed while undoing; nothing written."
                    else:
                        res.status, res.message = ("denied" if err.denied else "error"), err.message
            _audit(conn, plan, e, res)
            stopped = res.status != "applied"
        results.append(res)
    done = sum(r.status == "applied" for r in results)
    if not stopped:
        return ApplyOut(plan_id=plan.id, outcome="applied", entries=results,
                        message=f"Undone: {done} of {len(results)} secret(s) put back.")
    bad = next(r for r in results if r.status not in ("applied", "skipped"))
    return ApplyOut(plan_id=plan.id, outcome="partially_applied" if done else "not_applied", entries=results,
                    message=(f"{'Partially undone' if done else 'Not undone'}: {done} of {len(results)} secret(s) put back. "
                             f"Stopped at {bad.target}: {bad.message or bad.status}."))


def _audit(conn: Connection, plan: UndoPlan, e: UndoEntry, res: EntryCheck) -> None:
    audit.info(json.dumps({
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "event": "undo.apply", "outcome": res.status,
        "undo_plan": plan.id, "undoes": plan.undoes, "action": e.action,
        "actor": {"identity": conn.display_name, "auth": conn.auth_method, "entity_id": conn.entity_id,
                  "accessor": conn.accessor},
        "target": {"vault": conn.name, "url": conn.url, "mount": e.vault.mount, "path": e.path,
                   "from_version": e.current_version, "restored_version": e.restore_version,
                   "new_version": res.new_version},
        "message": res.message,
    }, sort_keys=True))
