"""Saved sync plans: a reviewed set of copies, downloaded as a file and applied later.

One person (who may only have read access) reviews staged copies and saves them as a plan.
The plan is a signed JSON file: which secrets and keys go from where to where, and the
source and target version each was at. It never holds values. Anyone with write access to
the targets can later open the file, check it and apply it. Values are read fresh from the
source when the plan is applied.

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
import time
import uuid
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field, ValidationError

from ..config import Settings, get_settings
from ..session import Connection, SessionData, load_session
from .compare import Side
from .connections import get_connection
from .sync import MAX_CHANGES, ApplyOut, Change, Direction, SyncRequest, _Ctx, apply_changes, evaluate

router = APIRouter(prefix="/api/plans", tags=["plans"])

Sess = Annotated[SessionData, Depends(load_session)]
Conf = Annotated[Settings, Depends(get_settings)]

FORMAT = "lockstep.sync-plan"
VERSION = 1


# --------------------------------------------------------------------------- models


class PlanVault(BaseModel):
    vault: str  # the preset's name, or the address of a custom connection
    preset: bool  # True: matched by preset name; False: matched by address
    namespace: str | None = None
    mount: str
    prefix: str = ""
    identity: str = ""  # who the creator was signed in as on this side (informational)


class PlanKey(BaseModel):
    key: str
    action: Literal["add", "update"]


class PlanChange(BaseModel):
    path: str  # left path, relative to the left prefix
    right_path: str
    direction: Direction
    source_path: str  # full path within the source mount (for people reading the plan)
    target_path: str
    source_version: int
    target_version: int | None  # None: the target didn't exist
    keys: list[PlanKey] = Field(min_length=1)


class Plan(BaseModel):
    format: Literal["lockstep.sync-plan"] = FORMAT
    version: Literal[1] = VERSION
    id: str
    created_at: str
    note: str = ""
    profile: str | None = None
    left: PlanVault
    right: PlanVault
    changes: list[PlanChange] = Field(min_length=1, max_length=MAX_CHANGES)
    signature: str = ""


class CreateRequest(SyncRequest):
    note: str = Field(default="", max_length=2000)
    profile: str | None = Field(default=None, max_length=100)


class PlanFile(BaseModel):
    plan: dict[str, Any]


class CheckRequest(PlanFile):
    left_conn_id: str
    right_conn_id: str


class ApplyPlanRequest(CheckRequest):
    confirm: bool


class VerifyOut(BaseModel):
    plan: Plan


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


class ApplyPlanOut(ApplyOut):
    plan_id: str


# --------------------------------------------------------------------------- signing


def _key(settings: Settings) -> bytes:
    return hashlib.sha256(b"lockstep-sync-plan-v1\0" + settings.session_key.encode()).digest()


def _canonical(data: dict) -> bytes:
    body = {k: v for k, v in data.items() if k != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sign(plan: Plan, settings: Settings) -> Plan:
    data = plan.model_dump(mode="json")
    plan.signature = hmac.new(_key(settings), _canonical(data), hashlib.sha256).hexdigest()
    return plan


def load_plan(raw: dict[str, Any], settings: Settings) -> Plan:
    """Parse an uploaded plan and check it was made by this server and not edited."""
    if raw.get("format") != FORMAT:
        raise HTTPException(400, detail={"message": "This isn't a Lockstep sync plan file."})
    if raw.get("version") != VERSION:
        raise HTTPException(400, detail={"message": f"Unsupported plan version {raw.get('version')!r}."})
    want = hmac.new(_key(settings), _canonical(raw), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(want, str(raw.get("signature", ""))):
        raise HTTPException(400, detail={"message": (
            "This plan file was changed after it was created, or was made by a different Lockstep "
            "server. Nothing can be applied from it: create the plan again.")})
    try:
        return Plan.model_validate(raw)
    except ValidationError as e:
        raise HTTPException(400, detail={"message": f"The plan file is malformed: {e.errors()[0]['msg']}"}) from e


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
                     prefix=prefix.rstrip("/"), identity=conn.display_name or conn.auth_method)


def _matches(conn: Connection, pv: PlanVault, settings: Settings) -> bool:
    return _vault_of(conn, settings) == (pv.vault, pv.preset) and _ns(conn.namespace) == _ns(pv.namespace)


def _describe(pv: PlanVault) -> str:
    return pv.vault + (f" (namespace {pv.namespace})" if pv.namespace else "")


def _request(plan: Plan, left_conn_id: str, right_conn_id: str) -> SyncRequest:
    changes = [Change(path=c.path, right_path=c.right_path, direction=c.direction, keys=[k.key for k in c.keys],
                      expected_target_version=c.target_version, expected_source_version=c.source_version)
               for c in plan.changes]
    return SyncRequest(left=Side(conn_id=left_conn_id, mount=plan.left.mount, prefix=plan.left.prefix),
                       right=Side(conn_id=right_conn_id, mount=plan.right.mount, prefix=plan.right.prefix),
                       changes=changes)


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
        sem = asyncio.Semaphore(16)

        async def one(pc: PlanChange, c: Change) -> ChangeCheck:
            async with sem:
                ev, _, _ = await evaluate(ctx, c, reveal=False)
            src, tgt = _ends(plan, pc)
            problems: list[str] = []
            if ev.status in ("conflict", "invalid") or ev.source.version != pc.source_version:
                status = "stale"
                if ev.source.version != pc.source_version and ev.source.state != "no_access":
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
    lconn = get_connection(session, body.left.conn_id)
    rconn = get_connection(session, body.right.conn_id)
    async with _Ctx(body, session, settings) as ctx:
        sem = asyncio.Semaphore(16)

        async def one(c: Change):
            async with sem:
                return await evaluate(ctx, c, reveal=False)

        evaluated = await asyncio.gather(*(one(c) for c in body.changes))

    changes: list[PlanChange] = []
    problems: list[str] = []
    for c, (ev, _, cas) in zip(body.changes, evaluated):
        where = f"{ev.target.name} · {ev.target.mount}/{ev.target.path}"
        # "denied" with key plans means the creator can't write the target: fine, someone else applies it.
        if ev.status in ("conflict", "invalid", "error") or (ev.status == "denied" and not ev.keys):
            problems.append(f"{where}: {'; '.join(ev.problems) or ev.status}")
            continue
        keys = [PlanKey(key=k.key, action=k.action) for k in ev.keys if k.action != "unchanged"]
        if not keys:
            continue  # already the same: nothing to plan
        changes.append(PlanChange(path=ev.path, right_path=ev.right_path, direction=ev.direction,
                                  source_path=ev.source.path, target_path=ev.target.path,
                                  source_version=ev.source.version or 0, target_version=cas or None, keys=keys))
    if problems:
        raise HTTPException(409, detail={"message": "Some changes can't go into a plan. Compare again, then retry: "
                                                    + " | ".join(problems)})
    if not changes:
        raise HTTPException(400, detail={"message": "Nothing to plan: the targets already have these values."})

    plan = Plan(id=str(uuid.uuid4()), created_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                note=body.note.strip(), profile=body.profile or None,
                left=_plan_vault(lconn, body.left, settings), right=_plan_vault(rconn, body.right, settings),
                changes=changes)
    return sign(plan, settings)


@router.post("/verify", response_model=VerifyOut)
async def verify(body: PlanFile, settings: Conf):
    return VerifyOut(plan=load_plan(body.plan, settings))


@router.post("/report", response_class=PlainTextResponse)
async def report(body: PlanFile, settings: Conf):
    plan = load_plan(body.plan, settings)
    return PlainTextResponse(render_report(plan), media_type="text/markdown; charset=utf-8",
                             headers={"Content-Disposition": f'attachment; filename="lockstep-plan-{plan.id[:8]}.md"'})


@router.post("/check", response_model=CheckOut)
async def check(body: CheckRequest, session: Sess, settings: Conf):
    plan = load_plan(body.plan, settings)
    return await _check(plan, _request(plan, body.left_conn_id, body.right_conn_id), session, settings)


@router.post("/apply", response_model=ApplyPlanOut)
async def apply(body: ApplyPlanRequest, session: Sess, settings: Conf):
    if not body.confirm:
        raise HTTPException(400, detail={"message": "Applying a plan requires confirm=true"})
    plan = load_plan(body.plan, settings)
    req = _request(plan, body.left_conn_id, body.right_conn_id)
    checked = await _check(plan, req, session, settings)
    if checked.status != "ready":
        raise HTTPException(409, detail={"message": checked.message, "check": checked.model_dump()})
    async with _Ctx(req, session, settings) as ctx:
        out = await apply_changes(ctx, req.changes, plan_id=plan.id)
    return ApplyPlanOut(plan_id=plan.id, **out.model_dump())


# --------------------------------------------------------------------------- report


def _md(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def render_report(plan: Plan) -> str:
    n_keys = sum(len(c.keys) for c in plan.changes)
    lines = [
        "# Lockstep sync plan",
        "",
        f"- **Plan ID:** `{plan.id}`",
        f"- **Created:** {plan.created_at}",
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
        "Values are not part of this plan: they're read from the source when it's applied. "
        "If any secret below has changed since the plan was created, the plan can't be applied "
        "and has to be created again.",
        "",
        "| From | To | Key | Action |",
        "|---|---|---|---|",
    ]
    for c in plan.changes:
        src, tgt = _ends(plan, c)
        frm = f"{_md(src.vault)} · `{src.mount}/{c.source_path}` (v{c.source_version})"
        to = f"{_md(tgt.vault)} · `{tgt.mount}/{c.target_path}` " + (f"(v{c.target_version})" if c.target_version else "(new)")
        for i, k in enumerate(c.keys):
            lines.append(f"| {frm if i == 0 else ''} | {to if i == 0 else ''} | `{_md(k.key)}` | {k.action} |")
    lines.append("")
    return "\n".join(lines)
