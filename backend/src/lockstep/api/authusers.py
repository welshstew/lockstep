"""Users of userpass mounts and LDAP group mappings: read, compare, and (userpass, dev Vaults) write.

  GET  /api/authusers/mounts?conn_id=           userpass and LDAP auth mounts
  GET  /api/authusers?conn_id=&mount=           userpass: users and their token settings
                                                ldap: the connection settings (no bind password),
                                                group mappings and user mappings
  POST /api/authusers/compare                   the same on two Vaults, paired by name
  POST /api/authusers/userpass                  create a user, or reset a password (shown once
                                                when Lockstep generates it)

Passwords are never read (Vault doesn't return them) or compared. Writing users is for dev
Vaults: off unless LOCKSTEP_USER_WRITE=on, refused when LOCKSTEP_READ_ONLY is on, and
audit-logged without the password.
"""

from __future__ import annotations

import asyncio
import json
import logging
import secrets
import string
import time
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ..config import Settings, get_settings
from ..session import SessionData, load_session
from ..vault import VaultClient, VaultError, _q
from .connections import client_for, get_connection, vault_http_error
from .guard import require_writable
from .. import writepolicy

router = APIRouter(prefix="/api/authusers", tags=["auth users"])
audit = logging.getLogger("lockstep.audit")

Sess = Annotated[SessionData, Depends(load_session)]
Conf = Annotated[Settings, Depends(get_settings)]
MAX = 500
TYPES = ("userpass", "ldap")
TOKEN_FIELDS = ("token_policies", "token_ttl", "token_max_ttl", "token_bound_cidrs", "token_no_default_policy",
                "token_type", "token_period", "token_num_uses", "token_explicit_max_ttl")
LDAP_CONFIG_FIELDS = ("url", "userdn", "userattr", "upndomain", "groupdn", "groupfilter", "groupattr", "binddn",
                      "insecure_tls", "starttls", "case_sensitive_names", "username_as_alias", "deny_null_bind",
                      "discoverdn", "use_token_groups", "token_policies", "token_ttl", "token_max_ttl")


async def user_mounts(v: VaultClient) -> list[dict]:
    try:
        data = (await v.request("GET", "sys/auth")).get("data") or {}
    except VaultError as e:
        if not e.denied:
            raise
        data = ((await v.request("GET", "sys/internal/ui/mounts")).get("data") or {}).get("auth") or {}
    return [{"path": p.strip("/"), "type": m.get("type"), "description": m.get("description") or ""}
            for p, m in sorted(data.items()) if m.get("type") in TYPES]


def _clean(d: dict, fields: tuple[str, ...]) -> dict:
    """The fields that say something: zero, empty and false values are Vault's defaults."""
    return {k: d[k] for k in fields if d.get(k) not in (None, "", [], 0, False, "default")}


async def read_mount(v: VaultClient, mount: str) -> dict:
    mount = mount.strip("/")
    kinds = {m["path"]: m["type"] for m in await user_mounts(v)}
    kind = kinds.get(mount)
    if kind is None:
        raise HTTPException(400, detail={"message": f"auth/{mount} isn't a userpass or LDAP auth mount here"})
    missing: list[str] = []
    sem = asyncio.Semaphore(16)

    async def names(path: str) -> list[str]:
        try:
            return ((await v.request("LIST", f"auth/{mount}/{path}")).get("data") or {}).get("keys") or []
        except VaultError as e:
            if e.status == 404:
                return []
            if e.denied:
                missing.append(f"list on auth/{mount}/{path}")
                return []
            raise

    async def read(path: str, name: str) -> dict:
        async with sem:
            try:
                return (await v.request("GET", f"auth/{mount}/{path}/{_q(name)}")).get("data") or {}
            except VaultError as e:
                if e.denied:
                    missing.append(f"read on auth/{mount}/{path}/{name}")
                return {"error": e.message}

    def entry(name: str, d: dict, extra: tuple[str, ...] = ()) -> dict:
        if "error" in d:
            return {"name": name, "error": d["error"]}
        out = {"name": name, **_clean(d, extra + TOKEN_FIELDS)}
        if isinstance(out.get("groups"), str):  # LDAP returns a comma separated string
            out["groups"] = [g for g in out["groups"].split(",") if g]
        return out

    out: dict = {"mount": mount, "type": kind}
    if kind == "userpass":
        users = (await names("users"))[:MAX]
        out["users"] = [entry(n, d) for n, d in zip(users, await asyncio.gather(*(read("users", n) for n in users)))]
    else:
        try:
            cfg = (await v.request("GET", f"auth/{mount}/config")).get("data") or {}
            out["config"] = _clean(cfg, LDAP_CONFIG_FIELDS)
        except VaultError as e:
            if not e.denied:
                raise
            missing.append(f"read on auth/{mount}/config")
            out["config"] = None
        groups, users = (await names("groups"))[:MAX], (await names("users"))[:MAX]
        g, u = await asyncio.gather(asyncio.gather(*(read("groups", n) for n in groups)),
                                    asyncio.gather(*(read("users", n) for n in users)))
        out["groups"] = [entry(n, d, ("policies",)) for n, d in zip(groups, g)]
        out["users"] = [entry(n, d, ("policies", "groups")) for n, d in zip(users, u)]
    out["missing"] = list(dict.fromkeys(missing))
    return out


@router.get("/mounts")
async def mounts(session: Sess, settings: Conf, conn_id: str):
    async with client_for(get_connection(session, conn_id), settings) as v:
        try:
            return await user_mounts(v)
        except VaultError as e:
            raise vault_http_error(e) from e


@router.get("")
async def list_mount(session: Sess, settings: Conf, conn_id: str, mount: str):
    async with client_for(get_connection(session, conn_id), settings) as v:
        try:
            return await read_mount(v, mount)
        except VaultError as e:
            raise vault_http_error(e) from e


class Side(BaseModel):
    conn_id: str
    mount: str = Field(min_length=1)


class CompareRequest(BaseModel):
    left: Side
    right: Side


def _pairs(left: list[dict], right: list[dict]) -> list[dict]:
    lm, rm = {x["name"]: x for x in left}, {x["name"]: x for x in right}
    out = []
    for n in sorted(set(lm) | set(rm)):
        a, b = lm.get(n), rm.get(n)
        if a is None or b is None:
            out.append({"name": n, "status": "right_only" if a is None else "left_only", "fields": []})
            continue
        norm = lambda x: sorted(x) if isinstance(x, list) else x  # noqa: E731
        fields = [{"field": k, "left": a.get(k), "right": b.get(k)} for k in sorted((set(a) | set(b)) - {"name"})
                  if norm(a.get(k)) != norm(b.get(k))]
        out.append({"name": n, "status": "different" if fields else "equal", "fields": fields})
    return out


@router.post("/compare")
async def compare(body: CompareRequest, session: Sess, settings: Conf):
    sides = {}
    for side, ref in (("left", body.left), ("right", body.right)):
        async with client_for(get_connection(session, ref.conn_id), settings) as v:
            try:
                sides[side] = await read_mount(v, ref.mount)
            except VaultError as e:
                raise vault_http_error(e) from e
    left, right = sides["left"], sides["right"]
    if left["type"] != right["type"]:
        raise HTTPException(400, detail={"message": f"Can't compare a {left['type']} mount with a {right['type']} mount"})
    out = {"type": left["type"], "users": _pairs(left["users"], right["users"]),
           "missing": {"left": left["missing"], "right": right["missing"]}}
    if left["type"] == "ldap":
        out["groups"] = _pairs(left["groups"], right["groups"])
        lc, rc = left.get("config") or {}, right.get("config") or {}
        out["config"] = [{"field": k, "left": lc.get(k), "right": rc.get(k)} for k in sorted(set(lc) | set(rc))
                         if lc.get(k) != rc.get(k)]
    every = out["users"] + out.get("groups", [])
    out["summary"] = {s: sum(p["status"] == s for p in every) for s in ("equal", "different", "left_only", "right_only")}
    return out


class UserWrite(BaseModel):
    conn_id: str
    mount: str = Field(min_length=1)
    username: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$")
    action: Literal["create", "reset"]
    password: str | None = Field(default=None, min_length=8, max_length=256)  # None: Lockstep generates one
    policies: list[str] = Field(default=[], max_length=50)  # create only
    token_ttl: str | None = Field(default=None, max_length=32)


def generate_password(n: int = 24) -> str:
    alphabet = string.ascii_letters + string.digits + "-_.~"
    return "".join(secrets.choice(alphabet) for _ in range(n))


@router.post("/userpass")
async def write_user(body: UserWrite, session: Sess, settings: Conf):
    require_writable(settings)
    if settings.user_write != "on":
        raise HTTPException(403, detail={"message": "Creating users and resetting passwords is turned off on this server "
                                                    "(LOCKSTEP_USER_WRITE). It's meant for development Vaults."})
    conn = get_connection(session, body.conn_id)
    mount = body.mount.strip("/")
    writepolicy.check(settings, conn, f"auth/{mount}/users/{body.username}", event="userpass.write")
    password = body.password or generate_password()
    async with client_for(conn, settings) as v:
        try:
            kinds = {m["path"]: m["type"] for m in await user_mounts(v)}
            if kinds.get(mount) != "userpass":
                raise HTTPException(400, detail={"message": f"auth/{mount} isn't a userpass auth mount here"})
            path = f"auth/{mount}/users/{_q(body.username)}"
            try:
                await v.request("GET", path)
                exists = True
            except VaultError as e:
                if e.status != 404:
                    raise
                exists = False
            if body.action == "create" and exists:
                raise HTTPException(409, detail={"message": f"{body.username} already exists on auth/{mount}: reset their password instead"})
            if body.action == "reset" and not exists:
                raise HTTPException(404, detail={"message": f"No user {body.username} on auth/{mount}"})
            if body.action == "create":
                payload: dict = {"password": password, "token_policies": body.policies}
                if body.token_ttl:
                    payload["token_ttl"] = body.token_ttl
                await v.request("POST", path, json=payload)
            else:
                await v.request("POST", f"{path}/password", json={"password": password})
        except VaultError as e:
            raise vault_http_error(e) from e
    audit.info(json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "event": f"userpass.{body.action}",
                           "outcome": "applied", "actor": {"identity": conn.display_name, "auth": conn.auth_method, "entity_id": conn.entity_id, "accessor": conn.accessor},
                           "target": {"vault": conn.name, "url": conn.url, "mount": mount, "user": body.username},
                           "generated": body.password is None}, sort_keys=True))
    return {"username": body.username, "mount": mount, "action": body.action,
            **({"password": password} if body.password is None else {})}
