"""Saved sync plans: a reviewed set of copies, downloaded as a file and applied later.

One person (who may only have read access) reviews staged copies and saves them as a plan.
The plan is a signed JSON file: which secrets and keys go from where to where, and the
source and target version each was at. Copied values are never in it: they're read fresh
from the source when the plan is applied. Values the creator typed (overrides) aren't in it
either: the plan keeps a check code per typed key (an HMAC with this server's key, which
can't be turned back into the value), and whoever applies the plan types the values again.
A value that doesn't match what the creator typed is refused. Plans made before this held
the typed values themselves (`set`, `holds_values`); they still apply as they are. Anyone
with write access to the targets can later open the file, check it and apply it.

A plan is all or nothing: if any source or target has changed since the plan was made, or
the plan file was edited, nothing is written and the plan has to be made again.

  POST /api/plans          create a plan from staged changes (returns the plan JSON)
  POST /api/plans/verify   check a plan file's signature and parse it (no Vault access)
  POST /api/plans/report   the plan as a Markdown report
  POST /api/plans/check    check a plan against both Vaults now
  POST /api/plans/apply    check again, then write every change (confirm=true)

Possible future change: a four-eyes rule (the person applying a plan must not be the person
who created it). The plan already records the creator's identities to make that possible.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import time
import uuid
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field, PrivateAttr, ValidationError

from .. import approvals, plansign
from ..approvals import Approval, ApprovalsOut
from ..config import Settings, get_settings
from ..plansign import Issuer
from ..rules import Rewrite
from ..session import Connection, SessionData, load_session
from .compare import FileSide, Side
from .connections import get_connection
from .guard import require_writable
from .. import writepolicy
from .sync import MAX_CHANGES, ApplyOut, Change, Direction, SyncRequest, _Ctx, apply_changes, evaluate

router = APIRouter(prefix="/api/plans", tags=["plans"])

Sess = Annotated[SessionData, Depends(load_session)]
Conf = Annotated[Settings, Depends(get_settings)]

audit = logging.getLogger("lockstep.audit")
FORMAT = "lockstep.sync-plan"
VERSION = 2  # 2: issuer, audience, not_before, expires_at, and the creators' entity IDs


# --------------------------------------------------------------------------- models


class PlanVault(BaseModel):
    vault: str  # the preset's name, or the address of a custom connection
    preset: bool  # True: matched by preset name; False: matched by address
    namespace: str | None = None
    mount: str
    prefix: str = ""
    identity: str = ""  # who the creator was signed in as on this side (informational)
    entity_id: str = ""  # the creator's Vault entity ID and token accessor on this side (from lookup-self,
    accessor: str = ""   # which a token can't choose): to check against Vault's audit log


class PlanKey(BaseModel):
    key: str
    action: Literal["add", "update", "remove"]
    override: bool = False  # written from a typed value (in the change's `set`), not copied


class PlanChange(BaseModel):
    path: str  # left path, relative to the left prefix
    right_path: str
    direction: Direction
    source_path: str  # full path within the source mount (for people reading the plan)
    target_path: str
    source_version: int
    target_version: int | None  # None: the target didn't exist
    keys: list[PlanKey] = Field(min_length=1)
    set: dict[str, Any] | None = None  # typed values, in plans made before typed values were asked again
    typed: dict[str, str] | None = None  # per typed key, a check code for the value (never the value)

    @property
    def copies(self) -> bool:
        return any(not k.override and k.action != "remove" for k in self.keys)


class Plan(BaseModel):
    format: Literal["lockstep.sync-plan"] = FORMAT
    version: Literal[1, 2] = VERSION
    id: str
    created_at: str
    issuer: Issuer | None = None  # the installation that made it (version 2)
    audience: list[str] = []  # the installations that may apply it (empty: any that trusts the issuer)
    not_before: str | None = None
    expires_at: str | None = None
    note: str = ""
    profile: str | None = None
    rewrites: list[Rewrite] = []  # the profile's value rewrites, applied again when the plan is applied
    left: PlanVault
    right: PlanVault
    changes: list[PlanChange] = Field(min_length=1, max_length=MAX_CHANGES)
    holds_values: bool = False  # some changes carry typed values: the file is as sensitive as they are
    signature: str = ""
    approvals: list[Approval] = []  # outside the plan's signature (each is signed on its own)
    _local: bool = PrivateAttr(default=True)  # issued by this installation (typed values can be checked)


class CreateRequest(SyncRequest):
    note: str = Field(default="", max_length=2000)
    profile: str | None = Field(default=None, max_length=100)
    audience: list[str] = Field(default=[], max_length=20)  # installations that may apply it


class PlanFile(BaseModel):
    plan: dict[str, Any]


class CheckRequest(PlanFile):
    left_conn_id: str
    right_conn_id: str
    # The typed values, entered again: {"<change index>": {"<key>": value}}. Check works without
    # them (it can't tell whether they match yet); apply needs every one.
    values: dict[str, dict[str, Any]] = {}


class ApplyPlanRequest(CheckRequest):
    confirm: bool


class VerifyOut(BaseModel):
    plan: Plan
    local: bool  # made by this installation: typed values are checked against the creator's here


class ChangeCheck(BaseModel):
    path: str
    right_path: str
    direction: Direction
    source: str  # "<vault> · <mount>/<path>"
    target: str
    status: Literal["ready", "stale", "denied", "error"]
    problems: list[str]


class CheckOut(BaseModel):
    status: Literal["ready", "stale", "denied", "error"]
    message: str
    changes: list[ChangeCheck]
    approvals: ApprovalsOut | None = None


class ApplyPlanOut(ApplyOut):
    plan_id: str
    outcome: Literal["applied", "partially_applied", "not_applied"] = "applied"
    message: str = ""


# --------------------------------------------------------------------------- signing


def _key(settings: Settings) -> bytes:
    return hashlib.sha256(b"lockstep-sync-plan-v1\0" + settings.session_key.encode()).digest()


def _canonical(data: dict) -> bytes:
    body = {k: v for k, v in data.items() if k not in ("signature", "approvals")}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _written_sides(plan: Plan) -> list[str]:
    return sorted({"right" if c.direction == "left_to_right" else "left" for c in plan.changes})


def _approvals(plan: Plan, conns: dict[str, Connection], settings: Settings) -> ApprovalsOut:
    """How many approvals the plan needs here, and which of its approvals count."""
    sides = _written_sides(plan)
    required = max(writepolicy.approvals_for(settings, conns[s]) for s in sides)
    return approvals.count("sync", plan.id, plan.signature, plan.approvals,
                           {s: getattr(plan, s).entity_id for s in sides},
                           {s: _describe(getattr(plan, s)) for s in sides}, required, settings,
                           {s: writepolicy.approver_policies_for(settings, conns[s]) for s in sides})


def sign(plan: Plan, settings: Settings) -> Plan:
    data = plan.model_dump(mode="json")
    plan.signature = plansign.sign(_canonical(data), settings, _key(settings))
    return plan


def _typed_key(settings: Settings) -> bytes:
    return hashlib.sha256(b"lockstep-typed-value-v1\0" + settings.session_key.encode()).digest()


def typed_check(settings: Settings, plan_id: str, target_path: str, key: str, value: Any) -> str:
    """A check code for a typed value: keyed with this server's secret, so the plan file can't be
    used to guess the value offline. Bound to the plan, the target and the key."""
    msg = "\0".join((plan_id, target_path, key, json.dumps(value, sort_keys=True, separators=(",", ":"))))
    return hmac.new(_typed_key(settings), msg.encode(), hashlib.sha256).hexdigest()[:32]


def match_typed(settings: Settings, plan_id: str, target_path: str, key: str, code: str, value: Any) -> tuple[bool, Any]:
    """Does a value typed at apply time match the creator's? A text that holds JSON (a number, a
    list) also matches the JSON value the creator typed. Returns (matches, the value to write)."""
    candidates = [value]
    if isinstance(value, str):
        try:
            candidates.append(json.loads(value))
        except ValueError:
            pass
    for v in candidates:
        if hmac.compare_digest(typed_check(settings, plan_id, target_path, key, v), code):
            return True, v
    return False, value


PLACEHOLDER = "\0lockstep: typed when the plan is applied\0"  # stands in for a value not entered yet (check only)


def load_plan(raw: dict[str, Any], settings: Settings) -> Plan:
    """Parse an uploaded plan and check it was made by this server and not edited."""
    if raw.get("format") != FORMAT:
        raise HTTPException(400, detail={"message": "This isn't a Lockstep sync plan file."})
    if raw.get("version") not in (1, 2):
        raise HTTPException(400, detail={"message": f"Unsupported plan version {raw.get('version')!r}."})
    try:
        issuer = Issuer.model_validate(raw["issuer"]) if raw.get("issuer") else None
    except ValidationError as e:
        raise HTTPException(400, detail={"message": plansign.TAMPERED}) from e
    local = plansign.verify(_canonical(raw), str(raw.get("signature", "")), issuer, settings, _key(settings))
    try:
        plan = Plan.model_validate(raw)
    except ValidationError as e:
        raise HTTPException(400, detail={"message": f"The plan file is malformed: {e.errors()[0]['msg']}"}) from e
    plansign.check_valid(settings, plan.not_before, plan.expires_at, plan.audience)
    plan._local = local
    return plan


# --------------------------------------------------------------------------- helpers


def _ns(ns: str | None) -> str:
    return (ns or "").strip("/")


def _vault_of(conn: Connection, settings: Settings) -> tuple[str, bool]:
    if conn.preset_id is not None and conn.preset_id < len(settings.preset_connections):
        return settings.preset_connections[conn.preset_id].name, True
    return conn.url.rstrip("/"), False


def _plan_vault(conn: Connection, side: Side, settings: Settings) -> PlanVault:
    vault, preset = _vault_of(conn, settings)
    mount, prefix = side.norm()
    return PlanVault(vault=vault, preset=preset, namespace=conn.namespace or None, mount=mount,
                     prefix=prefix.rstrip("/"), identity=conn.display_name or conn.auth_method,
                     entity_id=conn.entity_id, accessor=conn.accessor)


def _matches(conn: Connection, pv: PlanVault, settings: Settings) -> bool:
    return _vault_of(conn, settings) == (pv.vault, pv.preset) and _ns(conn.namespace) == _ns(pv.namespace)


def _describe(pv: PlanVault) -> str:
    return pv.vault + (f" (namespace {pv.namespace})" if pv.namespace else "")


def typed_keys(plan: Plan) -> list[tuple[int, PlanChange, str]]:
    """The (change index, change, key) of every value to type again when applying."""
    return [(i, c, k.key) for i, c in enumerate(plan.changes) for k in c.keys
            if k.override and k.key in (c.typed or {})]


def _typed_values(plan: Plan, values: dict[str, dict[str, Any]], settings: Settings, require: bool) -> list[dict]:
    """Each change's typed values: from an older plan's file, or entered again and checked
    against the creator's. Missing ones are a placeholder when only checking."""
    out: list[dict] = [dict(c.set or {}) for c in plan.changes]
    missing, wrong = [], []
    for i, c, key in typed_keys(plan):
        where = f"{c.target_path} · {key}"
        given = (values.get(str(i)) or {}).get(key)
        if given is None or given == "":
            if require:
                missing.append(where)
            out[i][key] = PLACEHOLDER
            continue
        if not plan._local:  # made elsewhere: the check code needs that installation's key
            out[i][key] = given
            continue
        ok, value = match_typed(settings, plan.id, c.target_path, key, (c.typed or {})[key], given)
        if not ok:
            wrong.append(where)
        out[i][key] = value
    if wrong:
        raise HTTPException(400, detail={"message": (
            "These values don't match what the plan's creator typed: " + ", ".join(wrong)
            + ". Nothing was written. Check them with whoever made the plan."), "typed": "mismatch"})
    if missing:
        raise HTTPException(400, detail={"message": "This plan writes values typed by hand, and they aren't in the file: "
                                                    "type them again for " + ", ".join(missing) + ".", "typed": "missing"})
    return out


def _request(plan: Plan, left_conn_id: str, right_conn_id: str, typed: list[dict] | None = None) -> SyncRequest:
    typed = typed or [dict(c.set or {}) for c in plan.changes]
    changes = [Change(path=c.path, right_path=c.right_path, direction=c.direction,
                      keys=[k.key for k in c.keys if not k.override and k.action != "remove"],
                      set={k.key: t[k.key] for k in c.keys if k.override and k.key in t} or None,
                      remove=[k.key for k in c.keys if k.action == "remove"] or None,
                      expected_target_version=c.target_version,
                      expected_source_version=c.source_version if c.copies else None)
               for c, t in zip(plan.changes, typed)]
    return SyncRequest(left=Side(conn_id=left_conn_id, mount=plan.left.mount, prefix=plan.left.prefix),
                       right=Side(conn_id=right_conn_id, mount=plan.right.mount, prefix=plan.right.prefix),
                       changes=changes, rewrites=plan.rewrites)


def _ends(plan: Plan, c: PlanChange) -> tuple[PlanVault, PlanVault]:
    return (plan.left, plan.right) if c.direction == "left_to_right" else (plan.right, plan.left)


async def _check(plan: Plan, req: SyncRequest, session: SessionData, settings: Settings) -> CheckOut:
    for which, conn_id, pv in (("left", req.left.conn_id, plan.left), ("right", req.right.conn_id, plan.right)):
        conn = get_connection(session, conn_id)
        if not _matches(conn, pv, settings):
            raise HTTPException(409, detail={"message": (
                f"This plan's {which} side is {_describe(pv)}, but the {which} connection is "
                f"{_vault_of(conn, settings)[0]}{f' (namespace {_ns(conn.namespace)})' if _ns(conn.namespace) else ''}. "
                f"Connect the {which} side to {_describe(pv)}.")})

    async with _Ctx(req, session, settings) as ctx:
        ctx.via_plan = True
        sem = asyncio.Semaphore(16)

        async def one(pc: PlanChange, c: Change) -> ChangeCheck:
            async with sem:
                ev, _, _ = await evaluate(ctx, c, reveal=False)
            src, tgt = _ends(plan, pc)
            problems: list[str] = []
            moved = pc.copies and ev.source.version != pc.source_version
            if ev.status in ("conflict", "invalid") or moved:
                status = "stale"
                if moved and ev.source.state != "no_access":
                    problems.append(f"The source changed since the plan was made (v{pc.source_version} → "
                                    f"v{ev.source.version or '—'}).")
                problems += [p for p in ev.problems if "Compare again" not in p]
                if ev.status == "conflict":
                    problems.append(f"The target changed since the plan was made (v{pc.target_version or '—'} → "
                                    f"v{ev.target.version or '—'}).")
            elif ev.status == "denied":
                status, problems = "denied", list(ev.problems)
            elif ev.status == "error":
                status, problems = "error", list(ev.problems)
            elif ev.status == "noop":  # same versions but nothing to change: can't happen for a valid plan
                status, problems = "stale", ["The target already has these values."]
            else:
                status = "ready"
            return ChangeCheck(path=pc.path, right_path=pc.right_path, direction=pc.direction,
                               source=f"{src.vault} · {src.mount}/{pc.source_path}",
                               target=f"{tgt.vault} · {tgt.mount}/{pc.target_path}",
                               status=status, problems=problems)

        checks = list(await asyncio.gather(*(one(pc, c) for pc, c in zip(plan.changes, req.changes))))

    n = {s: sum(c.status == s for c in checks) for s in ("stale", "denied", "error")}
    if n["stale"]:
        return CheckOut(status="stale", changes=checks, message=(
            f"This plan is out of date: {n['stale']} of {len(checks)} secret(s) changed since it was made. "
            "Nothing will be written. Ask for the plan to be created again from a new comparison."))
    if n["denied"]:
        return CheckOut(status="denied", changes=checks, message=(
            f"You can't write {n['denied']} of {len(checks)} secret(s) in this plan. Applying it needs "
            "write access to every target. Nothing will be written."))
    if n["error"]:
        return CheckOut(status="error", changes=checks, message=(
            f"{n['error']} secret(s) couldn't be checked. Nothing will be written; try again."))
    return CheckOut(status="ready", changes=checks,
                    message=f"All {len(checks)} secret(s) are exactly as they were when the plan was made.")


# --------------------------------------------------------------------------- routes


@router.post("", response_model=Plan)
async def create(body: CreateRequest, session: Sess, settings: Conf):
    if isinstance(body.left, FileSide) or isinstance(body.right, FileSide):
        raise HTTPException(400, detail={"message": "A plan needs a Vault on both sides, not an export file."})
    lconn = get_connection(session, body.left.conn_id)
    rconn = get_connection(session, body.right.conn_id)
    async with _Ctx(body, session, settings) as ctx:
        ctx.via_plan = True  # a Vault that changes only through approved plans still takes plans
        sem = asyncio.Semaphore(16)

        async def one(c: Change):
            async with sem:
                return await evaluate(ctx, c, reveal=False)

        evaluated = await asyncio.gather(*(one(c) for c in body.changes))

    plan_id = str(uuid.uuid4())
    changes: list[PlanChange] = []
    problems: list[str] = []
    for c, (ev, _, cas) in zip(body.changes, evaluated):
        where = f"{ev.target.name} · {ev.target.mount}/{ev.target.path}"
        # "denied" with key plans means the creator can't write the target: fine, someone else applies it.
        if ev.status in ("conflict", "invalid", "error") or (ev.status == "denied" and not ev.keys):
            problems.append(f"{where}: {'; '.join(ev.problems) or ev.status}")
            continue
        keys = [PlanKey(key=k.key, action=k.action, override=k.override) for k in ev.keys if k.action != "unchanged"]
        if not keys:
            continue  # already the same: nothing to plan
        # Typed values stay out of the file: a check code each, and they're typed again when applying
        typed = {k.key: typed_check(settings, plan_id, ev.target.path, k.key, c.set[k.key])
                 for k in keys if k.override and c.set and k.key in c.set}
        changes.append(PlanChange(path=ev.path, right_path=ev.right_path, direction=ev.direction,
                                  source_path=ev.source.path, target_path=ev.target.path,
                                  source_version=ev.source.version or 0, target_version=cas or None, keys=keys,
                                  typed=typed or None))
    if problems:
        raise HTTPException(409, detail={"message": "Some changes can't go into a plan. Compare again, then retry: "
                                                    + " | ".join(problems)})
    if not changes:
        raise HTTPException(400, detail={"message": "Nothing to plan: the targets already have these values."})

    plan = Plan(id=plan_id, created_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                audience=[a.strip() for a in body.audience if a.strip()], **plansign.validity(settings),
                note=body.note.strip(), profile=body.profile or None, rewrites=body.rewrites,
                left=_plan_vault(lconn, body.left, settings), right=_plan_vault(rconn, body.right, settings),
                changes=changes)
    return sign(plan, settings)


@router.post("/verify", response_model=VerifyOut)
async def verify(body: PlanFile, settings: Conf):
    plan = load_plan(body.plan, settings)
    return VerifyOut(plan=plan, local=plan._local)


@router.get("/key")
async def signing_key(settings: Conf):
    """This installation's name and public key, for other installations' LOCKSTEP_PLAN_TRUSTED_KEYS."""
    return plansign.public_key(settings)


@router.post("/report", response_class=PlainTextResponse)
async def report(body: PlanFile, settings: Conf):
    plan = load_plan(body.plan, settings)
    return PlainTextResponse(render_report(plan), media_type="text/markdown; charset=utf-8",
                             headers={"Content-Disposition": f'attachment; filename="lockstep-plan-{plan.id[:8]}.md"'})


@router.post("/check", response_model=CheckOut)
async def check(body: CheckRequest, session: Sess, settings: Conf):
    plan = load_plan(body.plan, settings)
    typed = _typed_values(plan, body.values, settings, require=False)
    out = await _check(plan, _request(plan, body.left_conn_id, body.right_conn_id, typed), session, settings)
    out.approvals = _approvals(plan, _conns(body, session), settings)
    return out


def _conns(body: CheckRequest, session: SessionData) -> dict[str, Connection]:
    return {"left": get_connection(session, body.left_conn_id), "right": get_connection(session, body.right_conn_id)}


class ApproveOut(BaseModel):
    plan: Plan


@router.post("/approve", response_model=ApproveOut)
async def approve(body: CheckRequest, session: Sess, settings: Conf):
    """Check the plan against the Vaults now and, if it's ready, add an approval from whoever is
    signed in to the Vaults it writes. The approval is signed on its own: the plan is unchanged."""
    plan = load_plan(body.plan, settings)
    typed = _typed_values(plan, body.values, settings, require=False)
    checked = await _check(plan, _request(plan, body.left_conn_id, body.right_conn_id, typed), session, settings)
    if checked.status not in ("ready", "denied"):  # an approver needn't be able to write the targets
        raise HTTPException(409, detail={"message": "Only a plan that checks out can be approved. " + checked.message})
    conns = _conns(body, session)
    sides = _written_sides(plan)
    a = approvals.approve("sync", plan.id, plan.signature, {s: conns[s] for s in sides},
                          {s: getattr(plan, s).entity_id for s in sides},
                          {s: _describe(getattr(plan, s)) for s in sides}, settings,
                          {s: writepolicy.approver_policies_for(settings, conns[s]) for s in sides}, plan.approvals)
    plan.approvals = [*plan.approvals, a]
    return ApproveOut(plan=plan)


@router.post("/apply", response_model=ApplyPlanOut)
async def apply(body: ApplyPlanRequest, session: Sess, settings: Conf):
    require_writable(settings)
    if not body.confirm:
        raise HTTPException(400, detail={"message": "Applying a plan requires confirm=true"})
    plan = load_plan(body.plan, settings)
    req = _request(plan, body.left_conn_id, body.right_conn_id, _typed_values(plan, body.values, settings, require=True))
    checked = await _check(plan, req, session, settings)
    if checked.status != "ready":
        raise HTTPException(409, detail={"message": checked.message, "check": checked.model_dump()})
    approvals.require("sync", _approvals(plan, _conns(body, session), settings))
    async with _Ctx(req, session, settings) as ctx:
        ctx.via_plan = True
        out = await apply_changes(ctx, req.changes, plan_id=plan.id, strict=True)
    written, total = out.summary["applied"], len(out.results)
    if not out.stopped:
        outcome, message = "applied", f"Plan applied: {written} of {total} secret(s) written."
    else:
        bad = next(r for r in out.results if r.status not in ("applied", "noop", "skipped"))
        where = f"{bad.target}: {bad.message or bad.status}"
        outcome = "partially_applied" if written else "not_applied"
        message = (f"{'Partially applied' if written else 'Not applied'}: {written} of {total} secret(s) written. "
                   f"Stopped at {where}. The {out.summary['skipped']} after it weren't attempted. "
                   "Compare again and make a new plan for what's left.")
    return ApplyPlanOut(plan_id=plan.id, outcome=outcome, message=message, **out.model_dump())


# --------------------------------------------------------------------------- report


def _md(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def render_report(plan: Plan) -> str:
    n_keys = sum(len(c.keys) for c in plan.changes)
    lines = [
        "# Lockstep sync plan",
        "",
        f"- **Plan ID:** `{plan.id}`",
        f"- **Created:** {plan.created_at}" + (f" by {_md(plan.issuer.name)}" if plan.issuer else ""),
        *([f"- **Valid until:** {plan.expires_at}"] if plan.expires_at else []),
        *([f"- **For:** {_md(', '.join(plan.audience))}"] if plan.audience else []),
        f"- **Left:** {_md(_describe(plan.left))} · `{plan.left.mount}/{plan.left.prefix}` "
        f"(created by {_md(plan.left.identity) or 'unknown'})",
        f"- **Right:** {_md(_describe(plan.right))} · `{plan.right.mount}/{plan.right.prefix}` "
        f"(created by {_md(plan.right.identity) or 'unknown'})",
    ]
    if plan.profile:
        lines.append(f"- **Comparison profile:** {_md(plan.profile)}")
    lines += [f"- **Changes:** {n_keys} key(s) in {len(plan.changes)} secret(s)", ""]
    if plan.note:
        lines += ["> " + plan.note.replace("\n", "\n> "), ""]
    lines += [
        "Copied values are not part of this plan: they're read from the source when it's applied. "
        + ("Keys marked *typed* are written with values typed by the plan's creator: the plan file "
           "holds them (this report doesn't). " if plan.holds_values else
           "Keys marked *typed* are written with values typed by hand. They aren't in the plan: whoever "
           "applies it types them again, and Lockstep checks they match the creator's. "
           if typed_keys(plan) else "")
        + "If any secret below has changed since the plan was created, the plan can't be applied "
        "and has to be created again.",
        "",
        "| From | To | Key | Action |",
        "|---|---|---|---|",
    ]
    for c in plan.changes:
        src, tgt = _ends(plan, c)
        frm = (f"{_md(src.vault)} · `{src.mount}/{c.source_path}` (v{c.source_version})" if c.copies
               else "typed values / removals")
        to = f"{_md(tgt.vault)} · `{tgt.mount}/{c.target_path}` " + (f"(v{c.target_version})" if c.target_version else "(new)")
        for i, k in enumerate(c.keys):
            action = f"{k.action} (typed)" if k.override else k.action
            lines.append(f"| {frm if i == 0 else ''} | {to if i == 0 else ''} | `{_md(k.key)}` | {action} |")
    lines.append("")
    return "\n".join(lines)
