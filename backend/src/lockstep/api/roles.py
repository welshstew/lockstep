"""Kubernetes, JWT/OIDC and AppRole auth roles: list, read, check, explain, compare across Vaults, and find
which roles grant a policy. Read-only: building roles happens in the browser, and writing them is
left to the admin bundle (or a later phase).

  GET  /api/roles/mounts?conn_id=          auth mounts of a supported type
  GET  /api/roles?conn_id=&mount=          every role on a mount, with its policies and findings
  GET  /api/roles/templates                starting points for new roles
  POST /api/roles/check                    normalise and check a role being built
  POST /api/roles/explain                  what a role's policies allow on a KV v2 mount
  POST /api/roles/compare                  the roles of two mounts (two Vaults), field by field
  GET  /api/roles/granting?conn_id=&policy= the roles (in supported mounts) that grant a policy
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from ..config import Settings, get_settings
from ..policy.compare import PolicyProfile
from ..policy.roles import LABELS, TEMPLATES, Kind, compare_roles, kind_of, lint, normalise, policies_of
from ..session import SessionData, load_session
from ..vault import VaultClient, VaultError
from .connections import client_for, get_connection, vault_http_error
from .guard import require_writable
from .. import writepolicy
from .policies import ExplainError, ExplainOut, run_explain

router = APIRouter(prefix="/api/roles", tags=["roles"])
audit = logging.getLogger("lockstep.audit")

Sess = Annotated[SessionData, Depends(load_session)]
Conf = Annotated[Settings, Depends(get_settings)]
MAX_ROLES = 500


async def auth_mounts(v: VaultClient) -> list[dict]:
    """Supported auth mounts: from sys/auth, or the UI listing when that's all the token may read."""
    try:
        data = (await v.request("GET", "sys/auth")).get("data") or {}
    except VaultError as e:
        if not e.denied:
            raise
        data = ((await v.request("GET", "sys/internal/ui/mounts")).get("data") or {}).get("auth") or {}
    out = []
    for path, m in sorted(data.items()):
        kind = kind_of(m.get("type", ""))
        if kind:
            out.append({"path": path.strip("/"), "type": m.get("type"), "kind": kind,
                        "description": m.get("description") or ""})
    return out


async def read_roles(v: VaultClient, mount: str) -> tuple[dict[str, dict], dict[str, str]]:
    """name -> raw role, and name -> error for roles that couldn't be read."""
    try:
        names = ((await v.request("LIST", f"auth/{mount}/role")).get("data") or {}).get("keys") or []
    except VaultError as e:
        if e.status == 404:
            return {}, {}
        raise
    sem = asyncio.Semaphore(16)
    roles: dict[str, dict] = {}
    errors: dict[str, str] = {}

    async def one(n: str):
        async with sem:
            try:
                roles[n] = (await v.request("GET", f"auth/{mount}/role/{n}"))["data"]
            except VaultError as e:
                errors[n] = e.message
    await asyncio.gather(*(one(n) for n in names[:MAX_ROLES]))
    return roles, errors


async def _existing_policies(v: VaultClient) -> set[str] | None:
    try:
        return set(await v.policy_names())
    except VaultError:
        return None


def _kind(mounts: list[dict], mount: str) -> Kind:
    m = next((x for x in mounts if x["path"] == mount.strip("/")), None)
    if m is None:
        raise HTTPException(404, detail={"message": f"auth/{mount} isn't a Kubernetes, JWT, OIDC or AppRole auth mount"})
    return m["kind"]


@router.get("/mounts")
async def mounts(session: Sess, settings: Conf, conn_id: str = Query()):
    conn = get_connection(session, conn_id)
    async with client_for(conn, settings) as v:
        try:
            return await auth_mounts(v)
        except VaultError as e:
            raise vault_http_error(e) from e


@router.get("/templates")
def templates():
    return [{"id": k, **t} for k, t in TEMPLATES.items()]


@router.get("")
async def list_roles(session: Sess, settings: Conf, conn_id: str = Query(), mount: str = Query(min_length=1)):
    conn = get_connection(session, conn_id)
    mount = mount.strip("/")
    async with client_for(conn, settings) as v:
        try:
            kind = _kind(await auth_mounts(v), mount)
            (roles, errors), existing = await asyncio.gather(read_roles(v, mount), _existing_policies(v))
        except VaultError as e:
            raise vault_http_error(e) from e
    out = []
    for name in sorted(set(roles) | set(errors)):
        if name in errors:
            out.append({"name": name, "error": errors[name]})
            continue
        role = normalise(kind, roles[name])
        out.append({"name": name, "role": role, "policies": policies_of(role),
                    "findings": [f.model_dump() for f in lint(kind, role, existing)]})
    return {"mount": mount, "kind": kind, "labels": LABELS, "roles": out,
            "policies_known": existing is not None}


class CheckRequest(BaseModel):
    kind: Kind
    body: dict[str, Any]
    conn_id: str | None = None  # check its policies exist on this Vault


@router.post("/check")
async def check(body: CheckRequest, session: Sess, settings: Conf):
    role = normalise(body.kind, body.body)
    existing = None
    if body.conn_id:
        async with client_for(get_connection(session, body.conn_id), settings) as v:
            existing = await _existing_policies(v)
    return {"role": role, "policies": policies_of(role),
            "findings": [f.model_dump() for f in lint(body.kind, role, existing)]}


class RoleExplainRequest(BaseModel):
    conn_id: str
    mount: str = Field(min_length=1)  # the auth mount
    role: str = Field(min_length=1)
    kv_mount: str = Field(min_length=1)
    prefix: str = ""


@router.post("/explain", response_model=ExplainOut)
async def explain_role(body: RoleExplainRequest, session: Sess, settings: Conf):
    """What a login with this role can do on a KV v2 mount: its policies, explained together."""
    conn = get_connection(session, body.conn_id)
    async with client_for(conn, settings) as v:
        try:
            raw = (await v.request("GET", f"auth/{body.mount.strip('/')}/role/{body.role}"))["data"]
            pols = [p for p in policies_of(raw) if p != "root"]
            out = await run_explain(v, body.kv_mount, body.prefix, names=pols, pasted=[], token=False,
                                    max_secrets=settings.max_tree_secrets)
        except ExplainError as e:
            raise HTTPException(e.status, detail={"message": e.message}) from e
        except VaultError as e:
            raise vault_http_error(e) from e
    return ExplainOut(**out)


class Side(BaseModel):
    conn_id: str
    mount: str = Field(min_length=1)


class CompareRequest(BaseModel):
    left: Side
    right: Side
    profile: PolicyProfile | None = None  # name mappings and rewrites, as for policies


@router.post("/compare")
async def compare(body: CompareRequest, session: Sess, settings: Conf):
    sides = {}
    for name, s in (("left", body.left), ("right", body.right)):
        conn = get_connection(session, s.conn_id)
        async with client_for(conn, settings) as v:
            try:
                kind = _kind(await auth_mounts(v), s.mount)
                roles, errors = await read_roles(v, s.mount.strip("/"))
            except VaultError as e:
                raise vault_http_error(e) from e
        sides[name] = (kind, {n: normalise(kind, r) for n, r in roles.items()}, errors)
    if sides["left"][0] != sides["right"][0]:
        raise HTTPException(400, detail={"message": "Compare roles of the same kind: Kubernetes with Kubernetes, JWT/OIDC with JWT/OIDC"})
    pairs = compare_roles(sides["left"][1], sides["right"][1], body.profile)
    summary = {s: sum(p["status"] == s for p in pairs) for s in ("equal", "different", "left_only", "right_only")}
    return {"kind": sides["left"][0], "pairs": pairs, "summary": summary,
            "errors": {"left": sides["left"][2], "right": sides["right"][2]}}


class SecretIdRequest(BaseModel):
    conn_id: str
    mount: str = Field(min_length=1)
    role: str = Field(min_length=1, max_length=128)
    ttl: Literal["5m", "15m", "1h", "24h"] = "15m"  # how long the wrapping token can be opened
    metadata: dict[str, str] = Field(default={}, max_length=20)


@router.post("/secret-id")
async def issue_secret_id(body: SecretIdRequest, session: Sess, settings: Conf):
    """Issue an AppRole secret ID, wrapped in a single-use token (never returned in plain text),
    with the role ID it goes with. Audit-logged without either secret."""
    require_writable(settings)
    conn = get_connection(session, body.conn_id)
    mount = body.mount.strip("/")
    writepolicy.check(settings, conn, f"auth/{mount}/role/{body.role}/secret-id", event="approle.secret_id")
    async with client_for(conn, settings) as v:
        try:
            if _kind(await auth_mounts(v), mount) != "approle":
                raise HTTPException(400, detail={"message": f"auth/{mount} isn't an AppRole mount"})
            role_id = (await v.request("GET", f"auth/{mount}/role/{body.role}/role-id"))["data"]["role_id"]
            res = await v.request("POST", f"auth/{mount}/role/{body.role}/secret-id",
                                  json={"metadata": json.dumps(body.metadata)} if body.metadata else {},
                                  headers={"X-Vault-Wrap-TTL": {"5m": "300", "15m": "900", "1h": "3600", "24h": "86400"}[body.ttl]})
        except VaultError as e:
            raise vault_http_error(e) from e
    wrap = res["wrap_info"]
    audit.info(json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "event": "approle.secret_id",
                           "outcome": "applied", "actor": {"identity": conn.display_name, "auth": conn.auth_method, "entity_id": conn.entity_id, "accessor": conn.accessor},
                           "target": {"vault": conn.name, "url": conn.url, "mount": mount, "role": body.role},
                           "wrapping_accessor": wrap.get("accessor"), "ttl": body.ttl}, sort_keys=True))
    return {"role_id": role_id, "wrapping_token": wrap["token"], "ttl": wrap["ttl"]}


@router.get("/granting")
async def granting(session: Sess, settings: Conf, conn_id: str = Query(), policy: str = Query(min_length=1)):
    """Which roles give this policy, in every supported auth mount the token may read."""
    conn = get_connection(session, conn_id)
    async with client_for(conn, settings) as v:
        try:
            ms = await auth_mounts(v)
        except VaultError as e:
            raise vault_http_error(e) from e
        found, unreadable = [], []
        for m in ms:
            try:
                roles, _ = await read_roles(v, m["path"])
            except VaultError:
                unreadable.append(m["path"])
                continue
            for n, r in sorted(roles.items()):
                if policy in policies_of(normalise(m["kind"], r)):
                    found.append({"mount": m["path"], "kind": m["kind"], "role": n})
        from .identity import read_groups
        try:
            groups, gmissing = await read_groups(v)
        except VaultError:
            groups, gmissing = {}, ["identity groups"]
    return {"policy": policy, "roles": found, "unreadable_mounts": unreadable,
            "groups": [n for n, g in sorted(groups.items()) if policy in (g.get("policies") or [])],
            "groups_missing": gmissing}
