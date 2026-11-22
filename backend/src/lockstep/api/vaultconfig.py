"""Vault configuration, side by side: an overview of each Vault, and every secrets engine and auth
method (with their tuning, and auth methods' configuration) compared across two Vaults.
Read-only. Sensitive configuration fields are left out even when Vault returns them.

  GET  /api/config/overview?conn_id=   version, seal, HA and replication status
  POST /api/config/compare             mounts and auth methods of two Vaults, field by field
"""

from __future__ import annotations

import asyncio
import re
from typing import Annotated, Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from ..config import Settings, get_settings
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


def pair(left: dict[str, dict], right: dict[str, dict]) -> list[dict]:
    out = []
    for path in sorted(set(left) | set(right)):
        a, b = left.get(path), right.get(path)
        fields = diff(a, b) if a is not None and b is not None else []
        out.append({"path": path, "type": (a or b or {}).get("type"),
                    "system": path.strip("/").split("/")[0] in SYSTEM_MOUNTS,
                    "status": "left_only" if b is None else "right_only" if a is None else "different" if fields else "equal",
                    "fields": fields, "left": a, "right": b})
    return out


async def overview(v: VaultClient) -> dict:
    async def get(path: str):
        try:
            return await v.request("GET", path)
        except VaultError as e:
            return {"_error": e.message, "_status": e.status}

    seal, leader, repl = await asyncio.gather(get("sys/seal-status"), get("sys/leader"), get("sys/replication/status"))
    out: dict[str, Any] = {
        "version": seal.get("version"), "cluster_name": seal.get("cluster_name"), "sealed": seal.get("sealed"),
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
}
ENGINE_VOLATILE = {"keys", "latest_version", "min_available_version", "last_vault_rotation", "ttl",
                   "last_rotated", "issuer_id", "imported_key", "kms_key"}
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
            out[f"{mount}{kind}/{n}"] = {**_engine_clean(kind, d), "engine": etype, "kind": kind}
        await asyncio.gather(*(read(n) for n in names[:MAX_OBJECTS] if not n.endswith("/")))

    await asyncio.gather(*(one(p, m["type"], k) for p, m in mounts.items() for k in ENGINE_OBJECTS.get(m.get("type", ""), [])))
    return out, sorted(set(missing))


class Side(BaseModel):
    conn_id: str


class CompareRequest(BaseModel):
    left: str
    right: str


async def run_compare(lv: VaultClient, rv: VaultClient) -> dict:
    (lo, lc), (ro, rc) = await asyncio.gather(asyncio.gather(overview(lv), read_config(lv)),
                                             asyncio.gather(overview(rv), read_config(rv)))
    mounts, auth = pair(lc["mounts"], rc["mounts"]), pair(lc["auth"], rc["auth"])
    # Engine roles and keys, for mounts of the same type on both sides
    both = {p: m for p, m in lc["mounts"].items() if (rc["mounts"].get(p) or {}).get("type") == m.get("type")}
    (le, lmiss), (re_, rmiss) = await asyncio.gather(read_engine_objects(lv, both),
                                                    read_engine_objects(rv, {p: rc["mounts"][p] for p in both}))
    engines = pair(le, re_)
    for p in engines:  # the engine's type, not the object's own "type" (a Transit key's type, say)
        p["type"] = (p["left"] or p["right"])["engine"]
    lc["missing"] += lmiss
    rc["missing"] += rmiss
    summary = {s: sum(p["status"] == s for p in mounts + auth + engines if not p["system"])
               for s in ("equal", "different", "left_only", "right_only")}
    return {"overview": {"left": lo, "right": ro}, "mounts": mounts, "auth": auth, "engines": engines, "summary": summary,
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
            return await run_compare(lv, rv)
        except VaultError as e:
            raise vault_http_error(e) from e
