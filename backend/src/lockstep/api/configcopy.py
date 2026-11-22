"""Copying configuration to the other Vault: a mount's tuning, or a secrets engine's role.

  POST /api/config/copy   read the source (a mount's or auth method's tuning, or an engine role)
                          and return it as access changes for the other side, to preview, apply
                          or save as a plan through /api/access (nothing is written here)

What can be copied is deliberately narrow:
  - tuning: TTLs, description, listing visibility, audit and header settings (never the plugin
    version or KV options);
  - roles of PKI, database (dynamic roles), SSH, Kubernetes, AWS, Azure and the LDAP secrets
    engine (dynamic roles), written whole;
  - Transit keys' deletion_allowed and auto_rotate_period, for a key that exists on both sides.
Not copied: database connections and static roles (they hold or rotate credentials), GCP
rolesets and accounts (writing them creates cloud service accounts), LDAP static roles and
library sets (they rotate directory passwords), and anything secret.
"""

from __future__ import annotations

import json
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, model_validator

from ..config import Settings, get_settings
from ..session import SessionData, load_session
from ..vault import VaultClient, VaultError, _q
from .connections import client_for, get_connection, vault_http_error
from .vaultconfig import SENSITIVE

router = APIRouter(prefix="/api/config", tags=["config"])

Sess = Annotated[SessionData, Depends(load_session)]
Conf = Annotated[Settings, Depends(get_settings)]

TUNE_FIELDS = ("default_lease_ttl", "max_lease_ttl", "description", "listing_visibility", "force_no_cache",
               "audit_non_hmac_request_keys", "audit_non_hmac_response_keys", "passthrough_request_headers",
               "allowed_response_headers", "token_type")
# engine type -> object kinds that may be copied; "keys" (Transit) copies only TRANSIT_FIELDS
COPYABLE: dict[str, set[str]] = {
    "pki": {"roles"}, "database": {"roles"}, "ssh": {"roles"}, "kubernetes": {"roles"}, "aws": {"roles"},
    "azure": {"roles"}, "ldap": {"role"}, "openldap": {"role"}, "transit": {"keys"},
}
TRANSIT_FIELDS = ("deletion_allowed", "auto_rotate_period")
# Fields a role read returns that a write doesn't take (or that belong to one cluster)
READ_ONLY = {"issuer_id", "last_vault_rotation", "keys", "latest_version", "min_available_version", "type",
             "name", "imported_key", "kms_key", "supports_encryption", "supports_decryption", "supports_derivation",
             "supports_signing", "exportable", "allow_plaintext_backup", "derived", "convergent_encryption",
             "min_decryption_version", "min_encryption_version", "backup_info", "restore_info", "certificate_chain"}


class TuneChange(BaseModel):
    kind: Literal["secret", "auth"]
    path: str = Field(min_length=1, max_length=256)
    config: dict[str, Any] = Field(max_length=len(TUNE_FIELDS))

    @model_validator(mode="after")
    def _check(self):
        self.path = self.path.strip("/")
        bad = set(self.config) - set(TUNE_FIELDS)
        if bad:
            raise ValueError(f"these tuning fields can't be copied: {', '.join(sorted(bad))}")
        return self


class EngineObjectChange(BaseModel):
    mount: str = Field(min_length=1, max_length=256)
    kind: str = Field(min_length=1, max_length=64)
    name: str = Field(min_length=1, max_length=256)
    body: dict[str, Any] = Field(max_length=200)

    @model_validator(mode="after")
    def _check(self):
        self.mount = self.mount.strip("/")
        if any(SENSITIVE.search(k) for k in self.body):
            raise ValueError("secret fields can't be copied")
        if self.kind == "keys" and set(self.body) - set(TRANSIT_FIELDS):
            raise ValueError(f"only {', '.join(TRANSIT_FIELDS)} can be copied for a Transit key")
        return self


def tune_path(kind: str, path: str) -> str:
    return f"{'sys/auth' if kind == 'auth' else 'sys/mounts'}/{path.strip('/')}/tune"


async def read_tune(v: VaultClient, kind: str, path: str) -> dict:
    """A mount's tuning as it's set: the tune endpoint reports effective TTLs, so a TTL the mount
    inherits reads as "system" (from the mount's own config), which is also what a write takes."""
    tune = dict((await v.request("GET", tune_path(kind, path))).get("data") or {})
    try:
        raw = ((await v.request("GET", f"{'sys/auth' if kind == 'auth' else 'sys/mounts'}/{path.strip('/')}")).get("data") or {}).get("config") or {}
    except VaultError:
        raw = None
    if raw is not None:
        for k in ("default_lease_ttl", "max_lease_ttl"):
            tune[k] = raw.get(k) or "system"
    return tune


def engine_path(obj: EngineObjectChange) -> str:
    base = f"{obj.mount}/{obj.kind}/{_q(obj.name)}"
    return f"{base}/config" if obj.kind == "keys" else base


def normalise(d: dict | None, keys: list[str] | tuple[str, ...] | None = None) -> str | None:
    """A stable text form of the fields being written, for diffs and hashes."""
    if d is None:
        return None
    pick = {k: d.get(k) for k in (keys if keys is not None else sorted(d))}
    pick = {k: (sorted(v) if isinstance(v, list) and all(isinstance(x, str) for x in v) else v) for k, v in pick.items()}
    return json.dumps(pick, sort_keys=True, indent=2, default=str) + "\n"


async def mount_types(v: VaultClient) -> dict[str, str]:
    try:
        data = (await v.request("GET", "sys/mounts")).get("data") or {}
    except VaultError as e:
        if not e.denied:
            raise
        data = ((await v.request("GET", "sys/internal/ui/mounts")).get("data") or {}).get("secret") or {}
    return {p.strip("/"): m.get("type", "") for p, m in data.items()}


def _clean_role(d: dict) -> dict:
    return {k: x for k, x in d.items() if k not in READ_ONLY and not SENSITIVE.search(k) and x is not None}


class CopyRequest(BaseModel):
    conn_id: str  # the source side
    source: Literal["mount", "auth", "engine"]
    path: str = Field(min_length=1, max_length=512)  # "kv-dev/" or "pki/roles/web"
    to_path: str | None = Field(default=None, max_length=512)  # where on the other side (default: the same)


@router.post("/copy")
async def copy(body: CopyRequest, session: Sess, settings: Conf):
    """The access changes that would make the other side match the source (not written)."""
    conn = get_connection(session, body.conn_id)
    src = body.path.strip("/")
    dst = (body.to_path or body.path).strip("/")
    async with client_for(conn, settings) as v:
        try:
            if body.source in ("mount", "auth"):
                kind = "auth" if body.source == "auth" else "secret"
                tune = await read_tune(v, kind, src)
                config = {k: tune[k] for k in TUNE_FIELDS if k in tune and not (kind == "secret" and k == "token_type")}
                return {"tunes": [{"kind": kind, "path": dst, "config": config}], "notes": []}
            mount, _, rest = src.partition("/")
            kind, _, name = rest.partition("/")
            types = await mount_types(v)
            etype = types.get(mount)
            if not name or kind not in COPYABLE.get(etype or "", set()):
                raise HTTPException(400, detail={"message": f"{src} can't be copied: Lockstep copies tuning, and roles of "
                                                            "PKI, database (dynamic), SSH, Kubernetes, AWS, Azure and LDAP "
                                                            "(dynamic), and Transit key settings"})
            d = (await v.request("GET", f"{mount}/{kind}/{_q(name)}")).get("data") or {}
        except VaultError as e:
            raise vault_http_error(e) from e
    dmount, _, drest = dst.partition("/")
    dname = drest.partition("/")[2] or name
    notes = []
    if kind == "keys":
        obj = {k: d[k] for k in TRANSIT_FIELDS if k in d}
        notes.append("Only deletion_allowed and auto_rotate_period are copied; the key itself must exist on the other side.")
    else:
        obj = _clean_role(d)
        if etype == "database":
            notes.append(f"The role uses the connection {d.get('db_name')!r}: it has to exist on the other side too.")
        if etype == "pki" and d.get("issuer_ref") not in (None, "default"):
            notes.append(f"The role names the issuer {d.get('issuer_ref')!r}, which may not exist on the other side.")
    return {"engine_objects": [{"mount": dmount, "kind": kind, "name": dname, "body": obj}], "notes": notes}
