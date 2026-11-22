"""PKI for developers: issue a certificate from a role, and see a PKI engine's issuers and roles.

  GET  /api/pki/mounts?conn_id=          PKI secrets engines
  GET  /api/pki/overview?conn_id=&mount= issuers (with their certificate details) and roles
  POST /api/pki/issue                    issue a certificate from a role; optionally store it in KV

Configuring PKI (CAs, roles, tidy) stays in the Vault UI or Terraform. Issuing is refused when
LOCKSTEP_READ_ONLY is on; it's audit-logged with the serial number, never the private key.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import timezone
from typing import Annotated

from cryptography import x509
from cryptography.x509.oid import NameOID
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ..config import Settings, get_settings
from ..session import SessionData, load_session
from ..vault import VaultClient, VaultError, _q
from .connections import client_for, get_connection, vault_http_error
from .guard import require_writable

router = APIRouter(prefix="/api/pki", tags=["pki"])
audit = logging.getLogger("lockstep.audit")

Sess = Annotated[SessionData, Depends(load_session)]
Conf = Annotated[Settings, Depends(get_settings)]
ROLE_FIELDS = ("allowed_domains", "allow_subdomains", "allow_glob_domains", "allow_any_name", "allow_localhost",
               "allow_ip_sans", "max_ttl", "ttl", "key_type", "key_bits", "server_flag", "client_flag", "issuer_ref")


def describe(pem: str) -> dict:
    """The parts of a certificate a person checks: names, issuer, validity, serial, key."""
    c = x509.load_pem_x509_certificate(pem.encode())
    cn = lambda name: ", ".join(a.value for a in name.get_attributes_for_oid(NameOID.COMMON_NAME)) or name.rfc4514_string()  # noqa: E731
    try:
        sans = [str(n.value) for n in c.extensions.get_extension_for_class(x509.SubjectAlternativeName).value]
    except x509.ExtensionNotFound:
        sans = []
    key = c.public_key()
    return {"subject": cn(c.subject), "issuer": cn(c.issuer), "sans": sans,
            "not_before": c.not_valid_before_utc.astimezone(timezone.utc).isoformat(),
            "not_after": c.not_valid_after_utc.astimezone(timezone.utc).isoformat(),
            "serial": format(c.serial_number, "x"), "key": f"{type(key).__name__.replace('PublicKey', '').replace('_', '')} "
            f"{getattr(key, 'key_size', '') or getattr(getattr(key, 'curve', None), 'name', '')}".strip()}


async def pki_mounts(v: VaultClient) -> list[dict]:
    try:
        data = (await v.request("GET", "sys/mounts")).get("data") or {}
    except VaultError as e:
        if not e.denied:
            raise
        data = ((await v.request("GET", "sys/internal/ui/mounts")).get("data") or {}).get("secret") or {}
    return [{"path": p.strip("/"), "description": m.get("description") or ""} for p, m in sorted(data.items())
            if m.get("type") == "pki"]


@router.get("/mounts")
async def mounts(session: Sess, settings: Conf, conn_id: str):
    async with client_for(get_connection(session, conn_id), settings) as v:
        try:
            return await pki_mounts(v)
        except VaultError as e:
            raise vault_http_error(e) from e


@router.get("/overview")
async def overview(session: Sess, settings: Conf, conn_id: str, mount: str):
    mount = mount.strip("/")
    missing: list[str] = []

    async def lst(path: str) -> list[str]:
        try:
            return ((await v.request("LIST", path)).get("data") or {}).get("keys") or []
        except VaultError as e:
            if e.denied:
                missing.append(f"list on {path}")
            elif e.status != 404:
                raise
            return []

    async with client_for(get_connection(session, conn_id), settings) as v:
        try:
            issuer_ids, role_names = await asyncio.gather(lst(f"{mount}/issuers"), lst(f"{mount}/roles"))

            async def issuer(i: str) -> dict:
                try:
                    d = (await v.request("GET", f"{mount}/issuer/{i}"))["data"]
                    return {"id": i, "name": d.get("issuer_name") or "", **describe(d["certificate"])}
                except VaultError as e:
                    return {"id": i, "error": e.message}

            async def role(n: str) -> dict:
                try:
                    d = (await v.request("GET", f"{mount}/roles/{n}"))["data"]
                    return {"name": n, **{k: d.get(k) for k in ROLE_FIELDS}}
                except VaultError as e:
                    return {"name": n, "error": e.message}

            issuers, roles = await asyncio.gather(asyncio.gather(*(issuer(i) for i in issuer_ids[:50])),
                                                  asyncio.gather(*(role(n) for n in role_names[:200])))
        except VaultError as e:
            raise vault_http_error(e) from e
    return {"mount": mount, "issuers": list(issuers), "roles": list(roles), "missing": missing}


class Store(BaseModel):
    mount: str = Field(min_length=1)  # a KV v2 mount on the same connection
    path: str = Field(min_length=1, max_length=1024)


class IssueRequest(BaseModel):
    conn_id: str
    mount: str = Field(min_length=1)
    role: str = Field(min_length=1, max_length=128)
    common_name: str = Field(min_length=1, max_length=255)
    alt_names: list[str] = Field(default=[], max_length=50)
    ttl: str = Field(default="24h", pattern=r"^\d+[smhd]$")
    store: Store | None = None  # write certificate, private_key and ca_chain to this KV secret (it must not exist)


@router.post("/issue")
async def issue(body: IssueRequest, session: Sess, settings: Conf):
    require_writable(settings)
    conn = get_connection(session, body.conn_id)
    mount = body.mount.strip("/")
    async with client_for(conn, settings) as v:
        try:
            d = (await v.request("POST", f"{mount}/issue/{_q(body.role)}", json={
                "common_name": body.common_name, "ttl": body.ttl,
                **({"alt_names": ",".join(body.alt_names)} if body.alt_names else {})}))["data"]
        except VaultError as e:
            raise vault_http_error(e) from e
        chain = d.get("ca_chain") or ([d["issuing_ca"]] if d.get("issuing_ca") else [])
        stored = None
        if body.store:
            kv, path = body.store.mount.strip("/"), body.store.path.strip("/")
            try:
                version = await v.kv_write(kv, path, {"certificate": d["certificate"], "private_key": d["private_key"],
                                                      "ca_chain": "\n".join(chain)}, cas=0)
                stored = {"mount": kv, "path": path, "version": version}
            except VaultError as e:
                if e.status == 400 and "check-and-set" in e.message:
                    raise HTTPException(409, detail={"message": f"{kv}/{path} exists already: choose a new path"}) from e
                raise vault_http_error(e) from e
    info = describe(d["certificate"])
    audit.info(json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "event": "pki.issue",
                           "outcome": "applied", "actor": {"identity": conn.display_name, "auth": conn.auth_method},
                           "target": {"vault": conn.name, "url": conn.url, "mount": mount, "role": body.role},
                           "serial": d.get("serial_number"), "subject": info["subject"],
                           "stored": stored}, sort_keys=True))
    return {"certificate": d["certificate"], "private_key": d["private_key"], "ca_chain": chain,
            "serial": d.get("serial_number"), "info": info, "stored": stored}
