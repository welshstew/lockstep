"""Database secrets engine, for developers: see connections and roles, and generate credentials.

  GET  /api/database/mounts?conn_id=           database secrets engines
  GET  /api/database/overview?conn_id=&mount=  connections (no passwords), dynamic and static roles
  POST /api/database/creds                     generate credentials for a dynamic role (shown once)

Configuring connections and roles, and rotating root, stay in the Vault UI or Terraform.
Generating is refused when LOCKSTEP_READ_ONLY is on; it's audit-logged with the lease ID,
never the password.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from ..config import Settings, get_settings
from ..session import SessionData, load_session
from ..vault import VaultClient, VaultError, _q
from .connections import client_for, get_connection, vault_http_error
from .guard import require_writable
from .. import writepolicy

router = APIRouter(prefix="/api/database", tags=["database"])
audit = logging.getLogger("lockstep.audit")

Sess = Annotated[SessionData, Depends(load_session)]
Conf = Annotated[Settings, Depends(get_settings)]
MAX = 200
CONNECTION_FIELDS = ("plugin_name", "allowed_roles", "password_policy", "verify_connection")
ROLE_FIELDS = ("db_name", "default_ttl", "max_ttl", "creation_statements", "revocation_statements",
               "renew_statements", "rollback_statements", "credential_type")
STATIC_FIELDS = ("db_name", "username", "rotation_period", "rotation_schedule", "last_vault_rotation", "ttl")
_INLINE_PASSWORD = re.compile(r"(://[^:/@]+:)([^@]+)(@)")


def redact_url(url: str) -> str:
    """A connection URL without an inline password ({{password}} templates are kept)."""
    return _INLINE_PASSWORD.sub(lambda m: m.group(0) if m.group(2) == "{{password}}" else f"{m.group(1)}…{m.group(3)}", url)


async def database_mounts(v: VaultClient) -> list[dict]:
    try:
        data = (await v.request("GET", "sys/mounts")).get("data") or {}
    except VaultError as e:
        if not e.denied:
            raise
        data = ((await v.request("GET", "sys/internal/ui/mounts")).get("data") or {}).get("secret") or {}
    return [{"path": p.strip("/"), "description": m.get("description") or ""} for p, m in sorted(data.items())
            if m.get("type") == "database"]


@router.get("/mounts")
async def mounts(session: Sess, settings: Conf, conn_id: str):
    async with client_for(get_connection(session, conn_id), settings) as v:
        try:
            return await database_mounts(v)
        except VaultError as e:
            raise vault_http_error(e) from e


@router.get("/overview")
async def overview(session: Sess, settings: Conf, conn_id: str, mount: str):
    mount = mount.strip("/")
    missing: list[str] = []
    async with client_for(get_connection(session, conn_id), settings) as v:
        sem = asyncio.Semaphore(16)

        async def lst(path: str) -> list[str]:
            try:
                return ((await v.request("LIST", f"{mount}/{path}")).get("data") or {}).get("keys") or []
            except VaultError as e:
                if e.denied:
                    missing.append(f"list on {mount}/{path}")
                elif e.status != 404:
                    raise
                return []

        async def read(path: str, name: str, fields: tuple[str, ...]) -> dict:
            async with sem:
                try:
                    d = (await v.request("GET", f"{mount}/{path}/{_q(name)}"))["data"]
                except VaultError as e:
                    return {"name": name, "error": e.message}
            out = {"name": name, **{k: d.get(k) for k in fields if d.get(k) not in (None, "", [])}}
            details = d.get("connection_details") or {}
            if path == "config":
                out["connection_url"] = redact_url(details.get("connection_url") or "")
                out["username"] = details.get("username")
            return out

        try:
            conns, roles, statics = await asyncio.gather(lst("config"), lst("roles"), lst("static-roles"))
            c, r, s = await asyncio.gather(
                asyncio.gather(*(read("config", n, CONNECTION_FIELDS) for n in conns[:MAX])),
                asyncio.gather(*(read("roles", n, ROLE_FIELDS) for n in roles[:MAX])),
                asyncio.gather(*(read("static-roles", n, STATIC_FIELDS) for n in statics[:MAX])))
        except VaultError as e:
            raise vault_http_error(e) from e
    return {"mount": mount, "connections": list(c), "roles": list(r), "static_roles": list(s), "missing": missing}


class CredsRequest(BaseModel):
    conn_id: str
    mount: str = Field(min_length=1)
    role: str = Field(min_length=1, max_length=256)


@router.post("/creds")
async def creds(body: CredsRequest, session: Sess, settings: Conf):
    require_writable(settings)
    conn = get_connection(session, body.conn_id)
    mount = body.mount.strip("/")
    writepolicy.check(settings, conn, f"{mount}/creds/{body.role}", event="database.creds")
    async with client_for(conn, settings) as v:
        try:
            res = await v.request("GET", f"{mount}/creds/{_q(body.role)}")
        except VaultError as e:
            raise vault_http_error(e) from e
    audit.info(json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "event": "database.creds",
                           "outcome": "applied", "actor": {"identity": conn.display_name, "auth": conn.auth_method, "entity_id": conn.entity_id, "accessor": conn.accessor},
                           "target": {"vault": conn.name, "url": conn.url, "mount": mount, "role": body.role},
                           "lease_id": res.get("lease_id"), "ttl": res.get("lease_duration")}, sort_keys=True))
    return {"data": res.get("data") or {}, "lease_id": res.get("lease_id"), "ttl": res.get("lease_duration"),
            "renewable": res.get("renewable")}
