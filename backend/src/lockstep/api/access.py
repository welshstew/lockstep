"""Writing ACL policies and auth roles from Lockstep (policy builder phase 5).

  POST /api/access/preview   what each change would do: new, change (with a diff), same, delete;
                             whether the token may do it; a hash of what's there now
  POST /api/access/apply     do it. Each item is re-read first and skipped as a conflict if it
                             changed since the preview (Vault has no check-and-set for policies
                             or roles). Policies are written before roles, deletes last.
  POST /api/access/plans         save the changes as a signed access plan (no secrets in it), for
                                 someone with the rights to check and apply
  POST /api/access/plans/check   verify a plan, find the connection to its Vault, preview it
                                 against what's there now (what changed since it was made)
  POST /api/access/plans/apply   apply a plan, skipping anything that changed since it was made

Refused when LOCKSTEP_READ_ONLY is on or LOCKSTEP_POLICY_APPLY is off. `root` and `default`
can't be written or deleted. Every attempt is audit-logged with a hash of the content.
"""

from __future__ import annotations

import difflib
import hashlib
import hmac
import json
import uuid
import logging
import time
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, ValidationError, model_validator

from ..config import Settings, get_settings
from ..policy.bundle import NAME, BundlePolicy
from ..policy.explain import lint as lint_policy
from ..policy.hcl import PolicyParseError, parse_policy
from ..policy.roles import FIELDS, RoleSpec, lint as lint_role, normalise
from ..session import Connection, SessionData, load_session
from ..vault import VaultClient, VaultError
from .connections import client_for, get_connection, vault_http_error
from .guard import require_writable

router = APIRouter(prefix="/api/access", tags=["access"])
audit = logging.getLogger("lockstep.audit")

Sess = Annotated[SessionData, Depends(load_session)]
Conf = Annotated[Settings, Depends(get_settings)]
PROTECTED = {"root", "default"}


class RoleRef(BaseModel):
    mount: str = Field(min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=128, pattern=NAME.pattern)


class Changes(BaseModel):
    policies: list[BundlePolicy] = Field(default=[], max_length=200)
    roles: list[RoleSpec] = Field(default=[], max_length=200)
    delete_policies: list[str] = Field(default=[], max_length=200)
    delete_roles: list[RoleRef] = Field(default=[], max_length=200)

    @model_validator(mode="after")
    def _check(self):
        if not (self.policies or self.roles or self.delete_policies or self.delete_roles):
            raise ValueError("nothing to do")
        touched = [p.name for p in self.policies] + self.delete_policies
        if PROTECTED & set(touched):
            raise ValueError("the root and default policies can't be changed from Lockstep")
        if len(set(touched)) != len(touched):
            raise ValueError("a policy appears twice")
        rk = [(r.mount.strip("/"), r.name) for r in self.roles] + [(r.mount.strip("/"), r.name) for r in self.delete_roles]
        if len(set(rk)) != len(rk):
            raise ValueError("a role appears twice")
        return self


class AccessChanges(Changes):
    conn_id: str


class ApplyRequest(AccessChanges):
    expected: dict[str, str | None] = {}  # item id -> hash from the preview (None: didn't exist)
    confirm: bool


class Item(BaseModel):
    id: str  # "policy:<name>" or "role:<mount>/<name>"
    kind: Literal["policy", "role"]
    name: str
    action: Literal["new", "change", "same", "delete", "absent"]
    hash: str | None  # what's in Vault now (None: nothing)
    diff: str = ""  # unified diff (policies) or field list (roles)
    allowed: bool | None = None  # may the token do it (None: can't tell)
    status: Literal["ready", "noop", "denied", "invalid", "conflict", "applied", "error"] = "ready"
    problems: list[str] = []
    warnings: list[str] = []


def _hash(text: str | None) -> str | None:
    return None if text is None else hashlib.sha256(text.encode()).hexdigest()[:16]


def _role_text(kind: str, role: dict) -> str:
    return json.dumps(normalise(kind, role), sort_keys=True, indent=2)  # type: ignore[arg-type]


def _full_role(spec: RoleSpec) -> dict:
    """Every field, at its value or its default, so a write replaces the role rather than merging."""
    norm = normalise(spec.kind, spec.body)
    return {k: norm.get(k, default) for k, default in FIELDS[spec.kind].items()
            if not (spec.kind == "kubernetes" and k == "bound_service_account_namespace_selector" and not norm.get(k))}


class Unreadable(Exception):
    """The token may not read what's there now, so it can't be previewed (or safely replaced)."""


async def _read_policy(v: VaultClient, name: str) -> str | None:
    try:
        return await v.policy_text(name)
    except VaultError as e:
        if e.status == 404:
            return None
        if e.denied:
            raise Unreadable(f"Can't read the current policy (needs read on sys/policies/acl/{name})") from e
        raise


async def _read_role(v: VaultClient, mount: str, name: str) -> dict | None:
    try:
        return (await v.request("GET", f"auth/{mount}/role/{name}"))["data"]
    except VaultError as e:
        if e.status == 404:
            return None
        if e.denied:
            raise Unreadable(f"Can't read the current role (needs read on auth/{mount}/role/{name})") from e
        raise


async def _kinds(v: VaultClient) -> dict[str, str]:
    from .roles import auth_mounts
    return {m["path"]: m["kind"] for m in await auth_mounts(v)}


async def plan(v: VaultClient, body: Changes) -> list[Item]:
    items: list[Item] = []
    me = await v.lookup_self()
    mine = set(me.get("policies") or []) | set(me.get("identity_policies") or [])
    paths = [f"sys/policies/acl/{p.name}" for p in body.policies] + [f"sys/policies/acl/{n}" for n in body.delete_policies]
    paths += [f"auth/{r.mount.strip('/')}/role/{r.name}" for r in body.roles + body.delete_roles]  # type: ignore[operator]
    try:
        caps = await v.capabilities(paths)
    except VaultError:
        caps = {}

    def may(path: str, *want: str) -> bool | None:
        c = caps.get(path)
        return None if c is None else ("root" in c or any(w in c for w in want))

    for p in body.policies:
        it = Item(id=f"policy:{p.name}", kind="policy", name=p.name, action="new", hash=None,
                  allowed=may(f"sys/policies/acl/{p.name}", "create", "update"))
        try:
            parsed = parse_policy(p.text, p.name)
            errors = [f.message for f in lint_policy([parsed]) if f.level == "error"]
            if errors:
                it.status, it.problems = "invalid", errors
        except PolicyParseError as e:
            it.status, it.problems = "invalid", [f"can't be parsed: {e}"]
        try:
            current = await _read_policy(v, p.name)
        except Unreadable as e:
            it.status, it.problems = "denied", [str(e)]
            items.append(it)
            continue
        it.hash = _hash(current)
        text = p.text if p.text.endswith("\n") else p.text + "\n"
        if current is not None:
            same = current.strip() == text.strip()
            it.action = "same" if same else "change"
            it.diff = "".join(difflib.unified_diff(current.splitlines(True) if current.endswith("\n") else (current + "\n").splitlines(True),
                                                   text.splitlines(True), f"vault: {p.name}", f"new: {p.name}"))
            if same and it.status == "ready":
                it.status = "noop"
        if p.name in mine:
            it.warnings.append("Your own sign-in holds this policy: changing it changes what you can do.")
        items.append(it)

    kinds = await _kinds(v) if (body.roles or body.delete_roles) else {}
    existing = None
    for r in body.roles:
        mount = r.mount.strip("/")
        it = Item(id=f"role:{mount}/{r.name}", kind="role", name=f"{mount}/{r.name}", action="new", hash=None)
        if kinds.get(mount) != r.kind:
            it.status, it.problems = "invalid", [f"auth/{mount} isn't a { {"kubernetes": "Kubernetes", "jwt": "JWT/OIDC", "approle": "AppRole"}[r.kind] } auth mount here"]
        else:
            if existing is None:
                try:
                    existing = set(await v.policy_names())
                except VaultError:
                    existing = set()
            findings = lint_role(r.kind, normalise(r.kind, r.body), existing or None)
            if errs := [f.message for f in findings if f.level == "error"]:
                it.status, it.problems = "invalid", errs
            it.warnings += [f.message for f in findings if f.level == "warn"]
            try:
                current = await _read_role(v, mount, r.name)
            except Unreadable as e:
                it.status, it.problems = "denied", [str(e)]
                items.append(it)
                continue
            new_text = _role_text(r.kind, r.body)
            if current is not None:
                cur_text = _role_text(r.kind, current)
                it.hash = _hash(cur_text)
                it.action = "same" if cur_text == new_text else "change"
                it.diff = "".join(difflib.unified_diff(cur_text.splitlines(True), new_text.splitlines(True),
                                                       f"vault: auth/{mount}/role/{r.name}", "new"))
                if it.action == "same" and it.status == "ready":
                    it.status = "noop"
        it.allowed = may(f"auth/{mount}/role/{r.name}", "create", "update")
        items.append(it)

    for n in body.delete_policies:
        try:
            current = await _read_policy(v, n)
        except Unreadable as e:
            items.append(Item(id=f"policy:{n}", kind="policy", name=n, action="delete", hash=None, status="denied", problems=[str(e)]))
            continue
        it = Item(id=f"policy:{n}", kind="policy", name=n, action="delete" if current is not None else "absent",
                  hash=_hash(current), allowed=may(f"sys/policies/acl/{n}", "delete"),
                  status="ready" if current is not None else "noop")
        if n in mine:
            it.warnings.append("Your own sign-in holds this policy: deleting it removes what it gave you.")
        items.append(it)
    for r in body.delete_roles:
        mount = r.mount.strip("/")
        try:
            current = await _read_role(v, mount, r.name)
        except Unreadable as e:
            items.append(Item(id=f"role:{mount}/{r.name}", kind="role", name=f"{mount}/{r.name}", action="delete",
                              hash=None, status="denied", problems=[str(e)]))
            continue
        kind = kinds.get(mount)
        items.append(Item(id=f"role:{mount}/{r.name}", kind="role", name=f"{mount}/{r.name}",
                          action="delete" if current is not None else "absent",
                          hash=_hash(_role_text(kind, current)) if current is not None and kind else None,
                          allowed=may(f"auth/{mount}/role/{r.name}", "delete"),
                          status="ready" if current is not None else "noop"))
    for it in items:
        if it.status == "ready" and it.allowed is False:
            it.status = "denied"
            it.problems.append("Your sign-in may not do this.")
    return items


def _guard(settings: Settings) -> None:
    require_writable(settings)
    if settings.policy_apply != "on":
        raise HTTPException(403, detail={"message": "Writing policies and roles from Lockstep is turned off on this "
                                                    "server (LOCKSTEP_POLICY_APPLY). Download them for an admin instead."})


@router.post("/preview", response_model=list[Item])
async def preview(body: AccessChanges, session: Sess, settings: Conf):
    conn = get_connection(session, body.conn_id)
    async with client_for(conn, settings) as v:
        try:
            return await plan(v, body)
        except VaultError as e:
            raise vault_http_error(e) from e


@router.post("/apply", response_model=list[Item])
async def apply(body: ApplyRequest, session: Sess, settings: Conf):
    _guard(settings)
    if not body.confirm:
        raise HTTPException(400, detail={"message": "Applying requires confirm=true"})
    conn = get_connection(session, body.conn_id)
    async with client_for(conn, settings) as v:
        return await run_apply(v, conn, body, body.expected)


async def run_apply(v: VaultClient, conn: Connection, body: Changes, expected: dict[str, str | None],
                    plan_id: str | None = None) -> list[Item]:
    """Write the changes, skipping (as conflicts) items whose hash isn't the expected one."""
    try:
        items = await plan(v, body)
    except VaultError as e:
        raise vault_http_error(e) from e
    policies = {f"policy:{p.name}": p for p in body.policies}
    roles = {f"role:{r.mount.strip('/')}/{r.name}": r for r in body.roles}
    order = sorted(items, key=lambda i: (i.action == "delete", i.kind == "role"))  # policies, roles, then deletes
    for it in order:
        if it.status != "ready":
            continue
        if it.id in expected and expected[it.id] != it.hash:
            it.status = "conflict"
            it.problems.append("Changed in Vault since the plan was made. Make a new plan." if plan_id
                               else "Changed in Vault since the preview. Preview again.")
            _audit(conn, it, plan_id)
            continue
        try:
            if it.action == "delete":
                if it.kind == "policy":
                    await v.request("DELETE", f"sys/policies/acl/{it.name}")
                else:
                    mount, name = it.name.rsplit("/", 1)
                    await v.request("DELETE", f"auth/{mount}/role/{name}")
            elif it.kind == "policy":
                await v.request("PUT", f"sys/policies/acl/{it.name}", json={"policy": policies[it.id].text})
            else:
                spec = roles[it.id]
                await v.request("POST", f"auth/{spec.mount.strip('/')}/role/{spec.name}", json=_full_role(spec))
            it.status = "applied"
        except VaultError as e:
            it.status = "denied" if e.denied else "error"
            it.problems.append(e.message)
        _audit(conn, it, plan_id)
    return items


def _audit(conn: Connection, it: Item, plan_id: str | None = None) -> None:
    audit.info(json.dumps({
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "event": f"{it.kind}.{'delete' if it.action == 'delete' else 'write'}",
        "outcome": it.status,
        "actor": {"identity": conn.display_name, "auth": conn.auth_method},
        "target": {"vault": conn.name, "url": conn.url, "name": it.name, "previous_hash": it.hash},
        "message": "; ".join(it.problems),
        **({"plan_id": plan_id} if plan_id else {}),
    }, sort_keys=True))


# --------------------------------------------------------------------------- saved access plans

PLAN_FORMAT = "lockstep.access-plan"
PLAN_VERSION = 1


class PlanItem(BaseModel):
    id: str
    action: str
    status: str


class AccessPlan(BaseModel):
    format: Literal["lockstep.access-plan"] = PLAN_FORMAT
    version: int = PLAN_VERSION
    id: str
    created: str
    created_by: str
    vault: str  # preset name, or the address of a custom connection
    preset: bool
    namespace: str | None = None
    changes: Changes
    expected: dict[str, str | None]  # item id -> hash of what was in Vault when the plan was made
    items: list[PlanItem]  # what the preview said then (informational)
    signature: str = ""


def _plan_key(settings: Settings) -> bytes:
    return hashlib.sha256(b"lockstep-access-plan-v1\0" + settings.session_key.encode()).digest()


def _canonical(data: dict) -> bytes:
    return json.dumps({k: x for k, x in data.items() if k != "signature"}, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode()


def _sign(p: AccessPlan, settings: Settings) -> AccessPlan:
    p.signature = hmac.new(_plan_key(settings), _canonical(p.model_dump(mode="json")), hashlib.sha256).hexdigest()
    return p


def load_access_plan(raw: dict[str, Any], settings: Settings) -> AccessPlan:
    if raw.get("format") != PLAN_FORMAT:
        raise HTTPException(400, detail={"message": "This isn't a Lockstep access plan file."})
    if raw.get("version") != PLAN_VERSION:
        raise HTTPException(400, detail={"message": f"Unsupported access plan version {raw.get('version')!r}."})
    try:
        p = AccessPlan.model_validate(raw)
    except ValidationError as e:
        raise HTTPException(400, detail={"message": f"The plan file is malformed: {e.errors()[0]['msg']}"}) from e
    # Re-serialise before checking, so the signature covers exactly what will be applied
    want = hmac.new(_plan_key(settings), _canonical(p.model_dump(mode="json")), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(want, str(raw.get("signature", ""))):
        raise HTTPException(400, detail={"message": (
            "This plan file was changed after it was created, or was made by a different Lockstep server. "
            "Nothing can be applied from it: make the plan again.")})
    return p


def _vault_of(conn: Connection, settings: Settings) -> tuple[str, bool]:
    if conn.preset_id is not None and conn.preset_id < len(settings.preset_connections):
        return settings.preset_connections[conn.preset_id].name, True
    return (conn.url or "").rstrip("/"), False


def _targets(session: SessionData, settings: Settings, p: AccessPlan, conn_ids: list[str]) -> list[Connection]:
    """The signed-in connections to the plan's Vault (and namespace)."""
    found = [c for c in (get_connection(session, cid) for cid in conn_ids)
             if _vault_of(c, settings) == (p.vault, p.preset) and (c.namespace or "").strip("/") == (p.namespace or "").strip("/")]
    if found:
        return found
    where = p.vault + (f" (namespace {p.namespace})" if p.namespace else "")
    raise HTTPException(409, detail={"message": f"This plan is for {where}: sign in to it on one side first."})


@router.post("/plans", response_model=AccessPlan)
async def create_plan(body: AccessChanges, session: Sess, settings: Conf):
    conn = get_connection(session, body.conn_id)
    async with client_for(conn, settings) as v:
        try:
            items = await plan(v, body)
        except VaultError as e:
            raise vault_http_error(e) from e
    if not any(i.status in ("ready", "denied") for i in items):
        raise HTTPException(400, detail={"message": "Nothing in these changes would be written, so there's no plan to save."})
    vault, preset = _vault_of(conn, settings)
    p = AccessPlan(id=uuid.uuid4().hex[:12], created=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                   created_by=conn.display_name or conn.auth_method, vault=vault, preset=preset,
                   namespace=conn.namespace or None, changes=Changes(**body.model_dump(exclude={"conn_id"})),
                   expected={i.id: i.hash for i in items}, items=[PlanItem(id=i.id, action=i.action, status=i.status) for i in items])
    audit.info(json.dumps({"ts": p.created, "event": "access.plan", "outcome": "created", "plan_id": p.id,
                           "actor": {"identity": conn.display_name, "auth": conn.auth_method},
                           "target": {"vault": conn.name, "url": conn.url}, "items": [i.id for i in p.items]}, sort_keys=True))
    return _sign(p, settings)


class PlanCheck(BaseModel):
    conn_ids: list[str] = Field(min_length=1, max_length=2)  # the sides signed in; the plan's Vault is picked
    # (apply: the conn_id the check returned, first)
    plan: dict[str, Any]


class PlanApply(PlanCheck):
    confirm: bool


@router.post("/plans/check")
async def check_plan(body: PlanCheck, session: Sess, settings: Conf):
    p = load_access_plan(body.plan, settings)
    # Both sides may be signed in to the plan's Vault: use the one that may make the changes
    best: tuple[Connection, list[Item]] | None = None
    for conn in _targets(session, settings, p, body.conn_ids):
        async with client_for(conn, settings) as v:
            try:
                items = await plan(v, p.changes)
            except VaultError as e:
                raise vault_http_error(e) from e
        if best is None or sum(i.status == "denied" for i in items) < sum(i.status == "denied" for i in best[1]):
            best = (conn, items)
    conn, items = best  # type: ignore[misc]
    for it in items:
        if it.status == "ready" and it.id in p.expected and p.expected[it.id] != it.hash:
            it.status = "conflict"
            it.problems.append("Changed in Vault since the plan was made. Make a new plan.")
    return {"plan": {k: x for k, x in p.model_dump(mode="json").items() if k not in ("signature", "changes", "expected")},
            "conn_id": conn.id, "items": [i.model_dump() for i in items]}


@router.post("/plans/apply", response_model=list[Item])
async def apply_plan(body: PlanApply, session: Sess, settings: Conf):
    _guard(settings)
    if not body.confirm:
        raise HTTPException(400, detail={"message": "Applying requires confirm=true"})
    p = load_access_plan(body.plan, settings)
    conn = _targets(session, settings, p, body.conn_ids)[0]  # the client passes the one the check chose
    async with client_for(conn, settings) as v:
        return await run_apply(v, conn, p.changes, p.expected, plan_id=p.id)
