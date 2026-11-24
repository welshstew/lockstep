"""Vault configuration, side by side: an overview of each Vault, and every secrets engine and auth
method (with their tuning, and auth methods' configuration) compared across two Vaults.
Read-only. Sensitive configuration fields are left out even when Vault returns them.

  GET  /api/config/overview?conn_id=   version, seal, HA and replication status
  POST /api/config/compare             mounts and auth methods of two Vaults, field by field
  GET  /api/config/profiles            shared configuration profiles (LOCKSTEP_CONFIG_PROFILES)

A configuration profile pairs mounts whose paths differ between the Vaults (kv-dev ↔ kv-prod,
kubernetes-* ↔ k8s-*), rewrites the left side's values before comparing (dev → prod in a
description or a role's allowed domains), and leaves out paths that don't matter.
"""

from __future__ import annotations

import asyncio
import re
from typing import Annotated, Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from ..config import Settings, get_settings
from ..policy.compare import ConfigProfile, _regex
from ..policy.roles import map_name, rewrite
from ..session import SessionData, load_session
from ..vault import VaultClient, VaultError
from .connections import client_for, get_connection, vault_http_error

router = APIRouter(prefix="/api/config", tags=["config"])

Sess = Annotated[SessionData, Depends(load_session)]
Conf = Annotated[Settings, Depends(get_settings)]

SYSTEM_MOUNTS = {"sys", "identity", "cubbyhole", "token"}
# Fields that differ on every cluster or say nothing about configuration
VOLATILE = {"accessor", "uuid", "running_sha256", "deprecation_status"}
SENSITIVE = re.compile(r"secret|password|passwd|bindpass|token_reviewer_jwt|private|client_key|credential", re.I)


def _clean(v: Any) -> Any:
    """Defaults out, lists sorted, sensitive fields dropped, so equal setups compare equal."""
    if isinstance(v, dict):
        out = {}
        for k, x in sorted(v.items()):
            if SENSITIVE.search(k):
                continue
            x = _clean(x)
            if x in (None, "", [], {}, False, 0):
                continue
            out[k] = x
        return out
    if isinstance(v, list):
        items = [_clean(x) for x in v]
        return sorted(items, key=str) if all(not isinstance(x, (dict, list)) for x in items) else items
    return v


def normalise_mount(m: dict) -> dict:
    out = {k: x for k, x in m.items() if k not in VOLATILE}
    # The plugin version actually running says more than the (usually empty) pinned one
    if not out.get("plugin_version") and out.get("running_plugin_version"):
        out["plugin_version"] = out["running_plugin_version"]
    out.pop("running_plugin_version", None)
    # A built-in plugin's version is the server's (v1.21.4+builtin.vault, v2.7.3+builtin.bao): the
    # overview shows that once, so mounts don't all differ between versions, or Vault and OpenBao
    if "+builtin" in str(out.get("plugin_version") or ""):
        out["plugin_version"] = "builtin"
    return _clean(out)


def diff(a: dict | None, b: dict | None, prefix: str = "") -> list[dict]:
    """Fields that differ, flattened to dotted names (config.max_lease_ttl)."""
    a, b = a or {}, b or {}
    out = []
    for k in sorted(set(a) | set(b)):
        x, y = a.get(k), b.get(k)
        name = f"{prefix}{k}"
        if isinstance(x, dict) and isinstance(y, dict):
            out += diff(x, y, name + ".")
        elif x != y:
            out.append({"field": name, "left": x, "right": y})
    return out


def map_path(path: str, profile: ConfigProfile | None) -> str | None:
    """The right side's path for a left path under the profile's mappings, or None. Mappings name
    mounts ("kv-dev" → "kv-prod", "kubernetes-*" → "k8s-*"); a mapped mount carries its roles and
    keys with it (kv-dev/roles/web → kv-prod/roles/web)."""
    if not profile or not profile.mappings:
        return None
    trail = "/" if path.endswith("/") else ""

    def one(name: str) -> str | None:
        for candidate in (name, name + "/"):
            hit = map_name(candidate, profile)
            if hit is not None:
                return hit.strip("/")
        return None

    bare = path.rstrip("/")
    if (hit := one(bare)) is not None:
        return hit + trail
    mount, sep, rest = bare.partition("/")
    if sep and (hit := one(mount)) is not None:
        return f"{hit}/{rest}{trail}"
    return None


def ignored(path: str, profile: ConfigProfile | None) -> bool:
    return bool(profile) and any(_regex(p.rstrip("/")).match(path.rstrip("/")) or _regex(p.rstrip("/")).match(path.split("/")[0])
                                 for p in profile.ignore)


# Fields one product reports as a resolved default and the other as 0, "automatic"
# (PKI signature_bits: Vault 256, OpenBao 0). Not compared when one side leaves it automatic.
AUTOMATIC = {"signature_bits"}


def set_aside(fields: list[dict], a: dict, b: dict) -> tuple[list[dict], list[dict]]:
    """Split differences into real ones and fields only one server knows about. Engine objects
    carry `_returned` (the field names the server sent): Vault and OpenBao, or two versions of
    either, return fields the other doesn't have, which say nothing about drift."""
    la, lb = set(a.get("_returned") or ()), set(b.get("_returned") or ())
    if not (la and lb):
        return fields, []
    keep, aside = [], []
    for f in fields:
        top = f["field"].split(".")[0]
        if (top in la) != (top in lb):
            aside.append({**f, "reason": f"only {'the left' if top in la else 'the right'} server has this field"})
        elif top in AUTOMATIC and (f["left"] is None or f["right"] is None):
            aside.append({**f, "reason": "automatic on one side"})
        else:
            keep.append(f)
    return keep, aside


def _public(d: dict | None) -> dict | None:
    return None if d is None else {k: x for k, x in d.items() if k != "_returned"}


def pair(left: dict[str, dict], right: dict[str, dict], profile: ConfigProfile | None = None) -> list[dict]:
    """Pair by path (or the profile's mappings) and diff. `right_path` is set where they differ."""
    left = {p: x for p, x in left.items() if not ignored(p, profile)}
    right = {p: x for p, x in right.items() if not ignored(p, profile)}
    out, taken = [], set()
    for path in sorted(left):
        target = map_path(path, profile)
        rpath = target if target in right else (path if target is None and path in right else None)
        if rpath:
            taken.add(rpath)
        a, b = left[path], right.get(rpath) if rpath else None
        fields = diff(rewrite(_public(a), profile), _public(b)) if b is not None else []
        fields, aside = set_aside(fields, a, b) if b is not None else (fields, [])
        out.append({"path": path, "right_path": rpath if rpath and rpath != path else None, "type": (a or b or {}).get("type"),
                    "system": path.strip("/").split("/")[0] in SYSTEM_MOUNTS,
                    "status": "left_only" if b is None else "different" if fields else "equal",
                    "fields": fields, **({"set_aside": aside} if aside else {}), "left": _public(a), "right": _public(b),
                    **({"mapped_to": target} if target and target not in right else {})})
    for path in sorted(set(right) - taken):
        b = right[path]
        out.append({"path": path, "right_path": None, "type": b.get("type"),
                    "system": path.strip("/").split("/")[0] in SYSTEM_MOUNTS,
                    "status": "right_only", "fields": [], "left": None, "right": _public(b)})
    return out


def product(seal: dict, ui_mounts: dict) -> str:
    """Vault or OpenBao: OpenBao's built-in plugins report versions ending in .bao (readable with
    any token through sys/internal/ui/mounts); Vault Enterprise has +ent in its version."""
    mounts = (ui_mounts.get("data") or {}).get("secret") or {}
    if any(str(m.get("running_plugin_version") or "").endswith(".bao") for m in mounts.values()):
        return "OpenBao"
    return "Vault Enterprise" if "+ent" in str(seal.get("version") or "") else "Vault"


async def overview(v: VaultClient) -> dict:
    async def get(path: str):
        try:
            return await v.request("GET", path)
        except VaultError as e:
            return {"_error": e.message, "_status": e.status}

    seal, leader, repl, ui = await asyncio.gather(get("sys/seal-status"), get("sys/leader"), get("sys/replication/status"),
                                                  get("sys/internal/ui/mounts"))
    out: dict[str, Any] = {
        "product": product(seal, ui), "version": seal.get("version"), "cluster_name": seal.get("cluster_name"), "sealed": seal.get("sealed"),
        "seal_type": seal.get("type"), "storage_type": seal.get("storage_type"),
        "ha_enabled": leader.get("ha_enabled"), "performance_standby": leader.get("performance_standby"),
    }
    data = repl.get("data") or {}
    if "_error" in repl:
        out["replication"] = None
    else:
        out["replication"] = {k: (data.get(k) or {}).get("mode") for k in ("dr", "performance") if data.get(k)}
    return out


async def read_config(v: VaultClient) -> dict:
    """Mounts, auth methods and auth configuration, with what couldn't be read."""
    missing: list[str] = []

    async def get(path: str) -> dict | None:
        try:
            return (await v.request("GET", path)).get("data")
        except VaultError as e:
            if e.denied:
                missing.append(f"read on {path}")
                return None
            if e.status in (404, 405):
                return None
            raise

    mounts_raw, auth_raw = await asyncio.gather(get("sys/mounts"), get("sys/auth"))
    if mounts_raw is None:  # fall back to what the UI listing shows
        ui = await get("sys/internal/ui/mounts") or {}
        mounts_raw, auth_raw = ui.get("secret") or {}, auth_raw or ui.get("auth") or {}
    mounts = {p: normalise_mount(m) for p, m in (mounts_raw or {}).items()}
    auth = {p: normalise_mount(m) for p, m in (auth_raw or {}).items()}
    sem = asyncio.Semaphore(8)

    async def conf(path: str):
        if auth[path].get("type") in ("token",):
            return
        async with sem:
            c = await get(f"auth/{path.rstrip('/')}/config")
        if c:
            auth[path]["configuration"] = _clean(c)
    await asyncio.gather(*(conf(p) for p in auth))
    return {"mounts": mounts, "auth": auth, "missing": missing}


# Per engine type: the objects worth comparing (path under the mount), and fields that change on their own
ENGINE_OBJECTS: dict[str, list[str]] = {
    "pki": ["roles"],
    "database": ["config", "roles", "static-roles"],
    "transit": ["keys"],
    "ssh": ["roles"],
    "kubernetes": ["roles"],
    "aws": ["roles"],
    "azure": ["roles"],
    "gcp": ["roleset", "static-account", "impersonated-account"],
    "ldap": ["role", "static-role", "library"],  # the LDAP secrets engine (not the auth method)
    "openldap": ["role", "static-role", "library"],
}
ENGINE_VOLATILE = {"keys", "latest_version", "min_available_version", "last_vault_rotation", "ttl",
                   "last_rotated", "issuer_id", "imported_key", "kms_key", "password", "last_password"}
MAX_OBJECTS = 200
_URL_PASSWORD = re.compile(r"(://[^:/@]+:)(?!\{\{password\}\})[^@]+(@)")


def _engine_clean(kind: str, d: dict) -> dict:
    d = {k: x for k, x in d.items() if k not in ENGINE_VOLATILE}
    if kind == "config":  # database connections: the URL without an inline password
        details = dict(d.pop("connection_details", None) or {})
        if details.get("connection_url"):
            details["connection_url"] = _URL_PASSWORD.sub(r"\1…\2", details["connection_url"])
        d["connection_details"] = details
    return _clean(d)


async def read_engine_objects(v: VaultClient, mounts: dict[str, dict]) -> tuple[dict[str, dict], list[str]]:
    """'<mount>/<kind>/<name>' -> the object's settings, for the engines in ENGINE_OBJECTS."""
    out: dict[str, dict] = {}
    missing: list[str] = []
    sem = asyncio.Semaphore(16)

    async def one(mount: str, etype: str, kind: str):
        try:
            names = ((await v.request("LIST", f"{mount}{kind}")).get("data") or {}).get("keys") or []
        except VaultError as e:
            if e.denied:
                missing.append(f"list on {mount}{kind}")
            return

        async def read(n: str):
            async with sem:
                try:
                    d = (await v.request("GET", f"{mount}{kind}/{n}")).get("data") or {}
                except VaultError as e:
                    if e.denied:
                        missing.append(f"read on {mount}{kind}/*")
                    return
            out[f"{mount}{kind}/{n}"] = {**_engine_clean(kind, d), "engine": etype, "kind": kind, "_returned": sorted(d)}
        await asyncio.gather(*(read(n) for n in names[:MAX_OBJECTS] if not n.endswith("/")))

    await asyncio.gather(*(one(p, m["type"], k) for p, m in mounts.items() for k in ENGINE_OBJECTS.get(m.get("type", ""), [])))
    return out, sorted(set(missing))


class Side(BaseModel):
    conn_id: str


class CompareRequest(BaseModel):
    left: str
    right: str
    profile: ConfigProfile | None = None


async def run_compare(lv: VaultClient, rv: VaultClient, profile: ConfigProfile | None = None) -> dict:
    (lo, lc), (ro, rc) = await asyncio.gather(asyncio.gather(overview(lv), read_config(lv)),
                                             asyncio.gather(overview(rv), read_config(rv)))
    mounts, auth = pair(lc["mounts"], rc["mounts"], profile), pair(lc["auth"], rc["auth"], profile)
    # Engine roles and keys, for mounts paired with one of the same type on the other side
    both = {p["path"]: p["right_path"] or p["path"] for p in mounts
            if p["left"] and p["right"] and p["left"].get("type") == p["right"].get("type")}
    (le, lmiss), (re_, rmiss) = await asyncio.gather(read_engine_objects(lv, {p: lc["mounts"][p] for p in both}),
                                                    read_engine_objects(rv, {r: rc["mounts"][r] for r in both.values()}))
    engines = pair(le, re_, profile)
    for p in engines:  # the engine's type, not the object's own "type" (a Transit key's type, say)
        p["type"] = (p["left"] or p["right"])["engine"]
    lc["missing"] += lmiss
    rc["missing"] += rmiss
    summary = {s: sum(p["status"] == s for p in mounts + auth + engines if not p["system"])
               for s in ("equal", "different", "left_only", "right_only")}
    return {"overview": {"left": lo, "right": ro}, "mounts": mounts, "auth": auth, "engines": engines, "summary": summary,
            "profile": profile.name if profile else None,
            "missing": {"left": lc["missing"], "right": rc["missing"]}}


@router.get("/overview")
async def get_overview(session: Sess, settings: Conf, conn_id: str):
    async with client_for(get_connection(session, conn_id), settings) as v:
        return await overview(v)


@router.post("/compare")
async def compare(body: CompareRequest, session: Sess, settings: Conf):
    lconn, rconn = get_connection(session, body.left), get_connection(session, body.right)
    async with client_for(lconn, settings) as lv, client_for(rconn, settings) as rv:
        try:
            return await run_compare(lv, rv, body.profile)
        except VaultError as e:
            raise vault_http_error(e) from e


@router.get("/profiles", response_model=list[ConfigProfile])
def shared_profiles(settings: Conf):
    return settings.config_profiles
