"""Copying selected values from one side of a comparison to the other.

Two calls, both stateless:
  POST /api/sync/preview  what would change, per target secret (values only if reveal=true)
  POST /api/sync/apply    do it. Needs confirm=true

A change copies keys from the source side, sets values the user typed (an override), or
both, in one write to the target secret.

Safety rules, applied the same way by preview and apply:
  * Copied values always come from a fresh read of the SOURCE Vault, never from the browser.
    A comparison profile's rewrites (`test` ⇄ `dev`) are applied to them on the way, in the
    direction of the copy, so what's written is what the comparison counted as equal.
    Override values are the only values the browser sends, and only to be written.
  * Each target write uses KV v2 check-and-set (CAS) against the target version the user
    saw when comparing. If the target changed since, the item is a conflict and isn't written.
  * Keys that exist only on the target are kept, unless a change says `exact` (an import that
    deletes what isn't in the file): then the new version holds only the copied keys.
  * A change can `remove` named keys from the target: the new version doesn't have them (older
    versions still do). Removing every key soft-deletes the latest version instead of writing
    an empty one.
  * A `delete` change soft-deletes the target's latest version (KV v2; `vault kv undelete`
    brings it back). It's checked against the version the user saw, like a write.
  * Every attempted write is audit-logged (who, what, where, versions, outcome), never values.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, model_validator

from ..config import Settings, get_settings
from ..rules import Rewrite, Rules
from ..session import Connection, SessionData, load_session
from ..reveal import Shown, reveal
from ..vault import VaultClient, VaultError
from .compare import AnySide, Side, side_client, side_connection
from .guard import require_writable
from .. import writepolicy

router = APIRouter(prefix="/api/sync", tags=["sync"])
audit = logging.getLogger("lockstep.audit")

Sess = Annotated[SessionData, Depends(load_session)]
Conf = Annotated[Settings, Depends(get_settings)]

Direction = Literal["left_to_right", "right_to_left"]
MAX_CHANGES = 500
MAX_SET_KEYS = 200
MAX_SET_BYTES = 1024 * 1024  # all override values in one change, as JSON (Vault's default request limit is ~32 MB)
WRITE_CAPS = {"create", "update", "root", "sudo"}
DELETE_CAPS = {"delete", "root", "sudo"}


# --------------------------------------------------------------------------- models


class Change(BaseModel):
    path: str = Field(min_length=1)  # the LEFT side's path, relative to its prefix
    right_path: str | None = None  # the right side's path, if a profile mapping differs (default: path)
    direction: Direction  # which way: left_to_right writes the right side
    keys: list[str] | None = None  # keys to copy from the source; None = all, [] = none (override only)
    # Override: values typed by the user, written to the target as they are (any JSON type)
    set: dict[str, Any] | None = Field(default=None, max_length=MAX_SET_KEYS)
    expected_target_version: int | None = None  # from the compare; None means the target was absent
    expected_source_version: int | None = None  # informational: warns if the source moved
    exact: bool = False  # the new version holds only the copied/set keys: other target keys are removed
    remove: list[str] | None = Field(default=None, max_length=MAX_SET_KEYS)  # target keys to drop
    delete: bool = False  # soft-delete the target's latest version (nothing is copied)

    @model_validator(mode="after")
    def _check(self):
        if self.delete:
            if self.keys or self.set or self.exact or self.remove:
                raise ValueError(f"{self.path}: a delete can't also copy or set values")
            return self
        if self.keys is not None and not self.keys and not self.set and not self.remove:
            raise ValueError(f"nothing to do for {self.path}: no keys to copy, set or remove")
        if self.remove:
            both = set(self.remove) & (set(self.keys or []) | set(self.set or {}))
            if both:
                raise ValueError(f"{', '.join(sorted(both))}: both removed and written in {self.path}")
        if self.set:
            if any(not k or len(k) > 512 for k in self.set):
                raise ValueError("override key names must be 1-512 characters")
            if len(json.dumps(self.set)) > MAX_SET_BYTES:
                raise ValueError(f"override values for {self.path} are too large")
            both = set(self.set) & set(self.keys or [])
            if both:
                raise ValueError(f"{', '.join(sorted(both))}: both copied and overridden in {self.path}")
        return self

    @property
    def copies(self) -> bool:
        return not self.delete and (self.keys is None or bool(self.keys))


class SyncRequest(BaseModel):
    left: AnySide  # an export file can be the source of a copy (it can't be written)
    right: AnySide
    changes: list[Change] = Field(min_length=1, max_length=MAX_CHANGES)
    reveal: bool = False  # preview only: include values
    rewrites: list[Rewrite] = Field(default=[], max_length=50)  # the comparison profile's, applied to copied values

    @model_validator(mode="after")
    def _unique(self):
        seen = set()
        for c in self.changes:
            if c.delete or c.exact:  # only an import that deletes what isn't in its file does these
                raise ValueError(f"{c.path}: deleting or removing keys is only possible when importing")
            k = (c.path, c.right_path or c.path, c.direction)
            if k in seen:
                raise ValueError(f"duplicate change for {c.path} ({c.direction})")
            seen.add(k)
        return self


class ApplyRequest(SyncRequest):
    confirm: bool


class Endpoint(BaseModel):
    conn_id: str
    name: str
    mount: str
    path: str  # full path within the mount
    version: int | None
    state: str


class KeyPlan(BaseModel):
    key: str
    action: Literal["add", "update", "unchanged", "remove"]
    type_change: bool = False
    override: bool = False  # a value the user typed, not copied from the source
    rewritten: bool = False  # the profile's rewrites changed the copied value (e.g. test → dev)
    source_value: Any = None  # only when reveal=true (for an override: the new value)
    target_value: Any = None


class ChangePlan(BaseModel):
    path: str
    right_path: str
    direction: Direction
    action: Literal["write", "delete"] = "write"
    source: Endpoint
    target: Endpoint
    keys: list[KeyPlan]
    can_write: bool
    problems: list[str]
    warnings: list[str]
    status: Literal["ready", "noop", "conflict", "denied", "invalid", "error"]


class ChangeResult(BaseModel):
    path: str
    right_path: str
    direction: Direction
    target: str  # "<conn name> · <mount>/<path>"
    target_conn_id: str = ""  # where it was written, for an undo plan
    target_mount: str = ""
    target_path: str = ""  # within the mount
    action: Literal["write", "delete"] = "write"
    # skipped: not attempted, because an earlier change wasn't written (plans stop there)
    status: Literal["applied", "noop", "conflict", "denied", "invalid", "error", "skipped"]
    overridden: list[str] = []  # keys set from typed values
    old_version: int | None = None
    new_version: int | None = None
    keys: list[str] = []
    message: str = ""


class ApplyOut(BaseModel):
    results: list[ChangeResult]
    summary: dict[str, int]
    stopped: bool = False  # stopped at the first change that wasn't written; the rest are "skipped"


# --------------------------------------------------------------------------- core


class _Ctx:
    """Both sides' connections and clients for one request."""

    def __init__(self, req: SyncRequest, session: SessionData, settings: Settings):
        self._setup(side_connection(req.left, session), side_connection(req.right, session),
                    req.left, req.right, settings, req.rewrites)

    @classmethod
    def direct(cls, lconn: Connection, rconn: Connection, left: Side, right: Side,
               settings: Settings, rewrites: list[Rewrite] | None = None) -> "_Ctx":
        """A context from two connections, without a web session (the CLI)."""
        ctx = cls.__new__(cls)
        ctx._setup(lconn, rconn, left, right, settings, rewrites)
        return ctx

    def _setup(self, lconn: Connection, rconn: Connection, left: AnySide, right: AnySide, settings: Settings,
               rewrites: list[Rewrite] | None = None):
        self.rules = Rules(rewrites=list(rewrites or []))
        self.lconn, self.rconn = lconn, rconn
        self.left, self.right = left, right
        self.lmount, self.lprefix = left.norm()
        self.rmount, self.rprefix = right.norm()
        self.settings = settings

    async def __aenter__(self):
        self.lv = side_client(self.left, self.lconn, self.settings)
        self.rv = side_client(self.right, self.rconn, self.settings)
        return self

    async def __aexit__(self, *exc):
        await asyncio.gather(self.lv.__aexit__(None, None, None), self.rv.__aexit__(None, None, None))

    def ends(self, direction: Direction):
        left = (self.lconn, self.lv, self.lmount, self.lprefix)
        right = (self.rconn, self.rv, self.rmount, self.rprefix)
        return (left, right) if direction == "left_to_right" else (right, left)


def _type(v: Any) -> str:
    return type(v).__name__


async def evaluate(ctx: _Ctx, change: Change, reveal: bool,
                   any_target_version: bool = False, strict_source: bool = False) -> tuple[ChangePlan, dict | None, int]:
    """See _evaluate. On a Vault whose secrets change only through approved plans, a direct write
    is "denied" like one the user has no permission for: it can still go into a plan."""
    (_, _, _, _), (tconn, _, _, _) = ctx.ends(change.direction)
    plan_only = None if getattr(ctx, "via_plan", False) else writepolicy.needs_plan(ctx.settings, tconn)
    out = await _evaluate(ctx, change, reveal, any_target_version, strict_source, plan_only is not None)
    if plan_only and out[0].status == "denied":
        out[0].problems = [plan_only if "can't write" in p or "can't delete" in p else p for p in out[0].problems]
    return out


async def _evaluate(ctx: _Ctx, change: Change, reveal: bool, any_target_version: bool = False,
                    strict_source: bool = False, plan_only: bool = False) -> tuple[ChangePlan, dict | None, int]:
    """Plan one change from fresh reads. Returns (plan, new target data, CAS version).
    `any_target_version`: take the target as it is now (an import preview, which has no
    earlier comparison to hold it to); the version found is what apply will expect.
    `strict_source`: a source that moved since `expected_source_version` is a conflict, not a
    warning (sync plans: what was reviewed is what gets written)."""
    (sconn, sv, smount, sprefix), (tconn, tv, tmount, tprefix) = ctx.ends(change.direction)
    lrel, rrel = change.path, change.right_path or change.path
    srel, trel = (lrel, rrel) if change.direction == "left_to_right" else (rrel, lrel)
    spath, tpath = sprefix + srel, tprefix + trel
    problems: list[str] = []
    warnings: list[str] = []

    def endpoint(conn: Connection, mount: str, path: str, version, state) -> Endpoint:
        return Endpoint(conn_id=conn.id, name=conn.name, mount=mount, path=path, version=version, state=state)

    async def read(v: VaultClient, mount: str, path: str):
        try:
            return await v.kv_read(mount, path), None
        except VaultError as e:
            return None, ("denied" if e.denied else "error", e.message)

    async def caps_for(path: str) -> list[str]:
        try:
            return (await tv.capabilities([path]))[path]
        except VaultError:
            return []  # can't tell: treat as no write permission; the write itself is the final check

    async def no_source():
        return None, None

    # An override on its own doesn't need the source (it may not even exist there).
    (src, serr), (tgt, terr), caps = await asyncio.gather(
        read(sv, smount, spath) if change.copies else no_source(), read(tv, tmount, tpath),
        caps_for(f"{tmount}/data/{tpath}"))
    src_ep = endpoint(sconn, smount, spath, src.version if src else None,
                      src.state if src else ("no_access" if change.copies else "unused"))
    tgt_ep = endpoint(tconn, tmount, tpath, tgt.version if tgt else None, tgt.state if tgt else "no_access")

    deleting = change.delete

    def plan(status, keys=(), can_write=False) -> ChangePlan:
        return ChangePlan(path=lrel, right_path=rrel, direction=change.direction,
                          action="delete" if deleting else "write", source=src_ep, target=tgt_ep,
                          keys=list(keys), can_write=can_write, problems=problems, warnings=warnings,
                          status=status)

    if isinstance(tv, VaultClient) and await tv.kv_version(tmount) == "1":
        problems.append(f"{tmount}/ is a KV v1 mount: Lockstep only reads KV v1. Copy into a KV v2 mount instead.")
        return plan("invalid"), None, 0
    if why := writepolicy.refusal(ctx.settings, tconn, f"{tmount}/{tpath}", "write"):
        problems.append(why)
        return plan("invalid"), None, 0
    if plan_only:
        caps = []  # no direct writes here: reported as "denied", which a plan can still carry
    if serr or terr:
        kind, msg = serr or terr
        problems.append(f"Can't read the {'source' if serr else 'target'}: {msg}")
        return plan("denied" if kind == "denied" else "error"), None, 0
    if change.delete:
        return _evaluate_delete(change, tgt, caps, reveal, any_target_version, problems, plan, tconn, tmount, tpath)
    if change.copies and src.state != "present":
        problems.append("The source has no current data (missing or deleted).")
        return plan("invalid"), None, 0
    if tgt.state == "deleted" and not change.copies:
        warnings.append("The target's latest version is deleted. Setting values writes a new version with "
                        "only these keys.")

    overrides = change.set or {}
    source_data = (src.data or {}) if change.copies else {}
    removing = set(change.remove or [])
    keys = change.keys if change.keys is not None else sorted(
        k for k in source_data if k not in overrides and k not in removing)
    missing = [k for k in keys if k not in source_data]
    if missing:
        problems.append(f"Not in the source: {', '.join(missing)}")
        return plan("invalid"), None, 0

    # CAS: 0 means "must not exist yet". A soft-deleted latest version still counts as the
    # current version for CAS purposes.
    actual = tgt.version if tgt.state in ("present", "deleted") and tgt.version else 0
    expected = actual if any_target_version else (change.expected_target_version or 0)
    if change.copies and change.expected_source_version is not None and src.version != change.expected_source_version:
        if strict_source:
            problems.append(f"The source changed since the plan was made (v{change.expected_source_version} → "
                            f"v{src.version}). Nothing written: make the plan again.")
            return plan("conflict"), None, actual
        warnings.append(f"The source changed since you compared (v{change.expected_source_version} → "
                        f"v{src.version}). The current source value will be copied.")

    target_data = dict(tgt.data or {}) if tgt.state == "present" else {}
    to = "right" if change.direction == "left_to_right" else "left"
    copied = {k: ctx.rules.rewrite(source_data[k], to, key=k, paths=(lrel, rrel)) for k in keys}
    rewritten = {k for k in keys if json.dumps(copied[k], sort_keys=True) != json.dumps(source_data[k], sort_keys=True)}
    new_values = copied | overrides
    key_plans = []
    for k in sorted(new_values):
        new = new_values[k]
        if k not in target_data:
            action = "add"
        elif json.dumps(target_data[k], sort_keys=True) == json.dumps(new, sort_keys=True):
            action = "unchanged"
        else:
            action = "update"
        key_plans.append(KeyPlan(
            key=k, action=action, override=k in overrides, rewritten=k in rewritten and k not in overrides,
            type_change=action == "update" and _type(target_data[k]) != _type(new),
            source_value=new if reveal else None,
            target_value=target_data.get(k) if reveal else None))
    if change.exact:  # target keys the import doesn't have
        removing |= set(target_data) - set(new_values)
    removing &= set(target_data)  # removing a key the target doesn't have changes nothing
    key_plans += [KeyPlan(key=k, action="remove", target_value=target_data[k] if reveal else None)
                  for k in sorted(removing)]
    if removing and not set(target_data) - removing and not new_values:
        # Nothing would be left: soft-delete the latest version rather than write an empty one.
        deleting = True
        warnings.append("Every key is removed, so the secret's latest version is deleted (`vault kv undelete` "
                        "brings it back) instead of writing an empty version.")
        return _evaluate_delete(change, tgt, caps, reveal, any_target_version, problems, plan, tconn, tmount, tpath)

    can_write = bool(WRITE_CAPS & set(caps))
    if actual != expected:
        problems.append(f"The target changed since you compared (expected v{expected or '—'}, now "
                        f"v{actual or '—'}). Compare again before copying.")
        return plan("conflict", key_plans, can_write), None, actual
    if not can_write:
        problems.append(f"{tconn.display_name or tconn.name} can't write to {tmount}/{tpath}.")
        return plan("denied", key_plans, can_write), None, actual
    if all(k.action == "unchanged" for k in key_plans):
        return plan("noop", key_plans, can_write), None, actual

    kept = {k: v for k, v in target_data.items() if k not in removing}
    return plan("ready", key_plans, can_write), new_values if change.exact else kept | new_values, actual


def _evaluate_delete(change: Change, tgt, caps, reveal, any_target_version, problems, plan, tconn, tmount, tpath):
    """A delete: the target's current keys all go (soft delete of the latest version)."""
    if tgt.state != "present":
        return plan("noop"), None, tgt.version or 0  # absent, or already deleted
    key_plans = [KeyPlan(key=k, action="remove", target_value=v if reveal else None)
                 for k, v in sorted((tgt.data or {}).items())]
    actual = tgt.version or 0
    expected = actual if any_target_version else (change.expected_target_version or 0)
    can_delete = bool(DELETE_CAPS & set(caps))
    if actual != expected:
        problems.append(f"The target changed since the preview (expected v{expected or '—'}, now "
                        f"v{actual or '—'}). Preview again before deleting.")
        return plan("conflict", key_plans, can_delete), None, actual
    if not can_delete:
        problems.append(f"{tconn.display_name or tconn.name} can't delete {tmount}/{tpath}.")
        return plan("denied", key_plans, can_delete), None, actual
    return plan("ready", key_plans, can_delete), None, actual


def shown_in(ctx: _Ctx, plans: list[ChangePlan], sides: tuple[str, ...] = ("source", "target")) -> list[Shown]:
    """The secrets whose values a revealed preview carried, for the secret.reveal event. Values
    the user typed (overrides) aren't from Vault, so they don't count."""
    conns = {c.id: c for c in (getattr(ctx, "lconn", None), getattr(ctx, "rconn", None)) if isinstance(c, Connection)}
    out = []
    for p in plans:
        for side in sides:
            ep = getattr(p, side)
            keys = [k.key for k in p.keys if getattr(k, f"{side}_value") is not None and not (side == "source" and k.override)]
            if ep.conn_id in conns and keys:
                out.append(Shown(conns[ep.conn_id], ep.mount, ep.path, keys, ep.version))
    return out


def _audit(ctx: _Ctx, plan: ChangePlan, result: ChangeResult, plan_id: str | None = None) -> None:
    (sconn, *_), (tconn, *_) = ctx.ends(plan.direction)
    audit.info(json.dumps({
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "event": "sync.apply",
        "outcome": result.status,
        "actor": {"target_identity": tconn.display_name, "target_auth": tconn.auth_method,
                  "target_entity_id": tconn.entity_id, "target_accessor": tconn.accessor,
                  "source_identity": sconn.display_name, "source_auth": sconn.auth_method},
        "source": {"vault": sconn.name, "url": sconn.url, "mount": plan.source.mount,
                   "path": plan.source.path, "version": plan.source.version},
        "target": {"vault": tconn.name, "url": tconn.url, "mount": plan.target.mount,
                   "path": plan.target.path, "old_version": result.old_version,
                   "new_version": result.new_version},
        "action": plan.action,
        "keys": result.keys,
        "overridden": result.overridden,  # names only: typed values are never logged
        "message": result.message,
        **({"plan_id": plan_id} if plan_id else {}),
    }, sort_keys=True))


# --------------------------------------------------------------------------- routes


@router.post("/preview", response_model=list[ChangePlan])
async def preview(body: SyncRequest, session: Sess, settings: Conf):
    async with _Ctx(body, session, settings) as ctx:
        sem = asyncio.Semaphore(16)

        async def one(c: Change):
            async with sem:
                return (await evaluate(ctx, c, body.reveal))[0]

        plans = list(await asyncio.gather(*(one(c) for c in body.changes)))
        if body.reveal:
            reveal(settings, "sync.preview", shown_in(ctx, plans))
        return plans


@router.post("/apply", response_model=ApplyOut)
async def apply(body: ApplyRequest, session: Sess, settings: Conf):
    require_writable(settings)
    if not body.confirm:
        raise HTTPException(400, detail={"message": "Applying changes requires confirm=true"})
    async with _Ctx(body, session, settings) as ctx:
        return await apply_changes(ctx, body.changes)


FAILED = ("conflict", "denied", "invalid", "error")


async def apply_changes(ctx: _Ctx, changes: list[Change], plan_id: str | None = None,
                        strict: bool = False) -> ApplyOut:
    """Re-check and write each change in turn (CAS), audit-logging every attempt.
    `strict` (sync plans): a moved source is a conflict, and the first change that isn't written
    stops the run; the changes after it are reported as "skipped", never attempted."""
    results: list[ChangeResult] = []
    stopped = False
    for c in changes:  # one at a time: predictable order, simple audit trail
        if stopped:
            (_, _, _, _), (tconn, _, tmount, tprefix) = ctx.ends(c.direction)
            tpath = tprefix + ((c.right_path or c.path) if c.direction == "left_to_right" else c.path)
            results.append(ChangeResult(path=c.path, right_path=c.right_path or c.path, direction=c.direction,
                                        action="delete" if c.delete else "write", target=f"{tconn.name} · {tmount}/{tpath}",
                                        target_conn_id=tconn.id, target_mount=tmount, target_path=tpath,
                                        status="skipped", message="Not attempted: an earlier secret wasn't written."))
            continue
        plan, new_data, cas = await evaluate(ctx, c, reveal=False, strict_source=strict)
        (_, _, _, _), (tconn, tv, tmount, _) = ctx.ends(c.direction)
        changed = [k.key for k in plan.keys if k.action != "unchanged"]
        res = ChangeResult(path=c.path, right_path=c.right_path or c.path, direction=c.direction, action=plan.action,
                           target=f"{tconn.name} · {tmount}/{plan.target.path}",
                           target_conn_id=tconn.id, target_mount=tmount, target_path=plan.target.path,
                           overridden=[k.key for k in plan.keys if k.override and k.action != "unchanged"],
                           # "ready" becomes applied/conflict/denied/error once the write is attempted
                           status="error" if plan.status == "ready" else plan.status,  # type: ignore[arg-type]
                           old_version=plan.target.version, keys=changed,
                           message="; ".join(plan.problems))
        if plan.status == "ready":
            try:
                if plan.action == "delete":
                    await tv.kv_delete(tmount, plan.target.path)
                else:
                    res.new_version = await tv.kv_write(tmount, plan.target.path, new_data or {}, cas=cas)
                res.status = "applied"
            except VaultError as e:
                if e.status == 400 and "check-and-set" in e.message:
                    res.status, res.message = "conflict", "The target changed while applying; nothing written."
                elif e.denied:
                    res.status, res.message = "denied", e.message
                else:
                    res.status, res.message = "error", e.message
        results.append(res)
        if res.status != "noop":
            _audit(ctx, plan, res, plan_id)
        stopped = strict and res.status in FAILED
    summary = {s: sum(r.status == s for r in results)
               for s in ("applied", "noop", "conflict", "denied", "invalid", "error", "skipped")}
    return ApplyOut(results=results, summary=summary, stopped=stopped)
