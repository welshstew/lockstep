"""Vault configuration, side by side: an overview of each Vault, and every secrets engine and auth
method (with their tuning, and auth methods' configuration), the engines' roles and keys, and the
system settings (audit devices, password policies, token roles, quotas, MFA, plugins, identity
entities) compared across two Vaults.
Read-only. Sensitive fields (passwords, keys, client secrets) are never compared or shown, even
when Vault returns them: each is reported as "not compared" with its name only.

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
from ..vault import VaultClient, VaultError, product_of
from .connections import client_for, get_connection, vault_http_error

router = APIRouter(prefix="/api/config", tags=["config"])

Sess = Annotated[SessionData, Depends(load_session)]
Conf = Annotated[Settings, Depends(get_settings)]

SYSTEM_MOUNTS = {"sys", "identity", "cubbyhole", "token"}
# Fields that differ on every cluster or say nothing about configuration
VOLATILE = {"accessor", "uuid", "running_sha256", "deprecation_status"}
# Fields that hold secrets in the engines and auth methods Lockstep reads (database connections,
# LDAP, Kubernetes, JWT/OIDC, AWS, Azure, GCP, RADIUS, Kerberos, Okta, Consul, Nomad…)
SENSITIVE_FIELDS = frozenset({
    "password", "passwd", "bindpass", "secret", "secret_key", "client_secret", "oidc_client_secret",
    "private_key", "client_key", "tls_client_key", "client_tls_key", "credentials", "service_account_json",
    "token_reviewer_jwt", "service_account_jwt", "keytab", "token", "session_token", "last_password",
    "integration_key", "settings_file_base64", "api_token",  # MFA methods (Duo, PingID, Okta)
})
# Settings whose names look secret but aren't: compared like any other field
NOT_SENSITIVE = frozenset({
    "password_policy", "password_authentication", "credential_type", "credential_config", "secret_type",
    "secret_id_bound_cidrs", "secret_id_num_uses", "secret_id_ttl", "bind_secret_id", "local_secret_ids",
    "private_key_format", "allow_private_key_export", "username_template", "key_type", "credential_ttl",
    "disable_local_ca_jwt",
})
# The safety net for fields in neither list (a plugin, a new Vault version): hidden, to be safe
LOOKS_SENSITIVE = re.compile(r"secret|password|passwd|bindpass|_jwt$|private|client_key|credential|keytab|_token$", re.I)
HIDDEN = "(sensitive: not compared)"  # stands in for a sensitive value, which never leaves the server


def sensitive(name: str) -> str | None:
    """Why a field's value is never compared or copied ("sensitive", or "name looks sensitive" for
    an unknown field the safety net caught), or None."""
    if name in SENSITIVE_FIELDS:
        return "sensitive"
    if name in NOT_SENSITIVE:
        return None
    return "name looks sensitive" if LOOKS_SENSITIVE.search(name) else None


# Values that mean "not set" for mount and auth tuning fields: dropped, so a server that leaves
# them out and one that reports the default compare equal. Any other false or 0 is a real setting.
MOUNT_DEFAULTS: dict[str, Any] = {
    "local": False, "seal_wrap": False, "external_entropy_access": False, "plugin_version": "",
    "config.default_lease_ttl": 0, "config.max_lease_ttl": 0, "config.force_no_cache": False,
    "config.listing_visibility": "", "config.token_type": "default-service",
}


def _clean(v: Any, path: str = "", defaults: dict[str, Any] | None = None) -> Any:
    """Empty values and known defaults out, lists sorted, sensitive values replaced by HIDDEN, so
    equal setups compare equal. A real false or 0 stays."""
    if isinstance(v, dict):
        out = {}
        for k, x in sorted(v.items()):
            name = f"{path}{k}"
            if sensitive(k) and x not in (None, "", [], {}):
                out[k] = HIDDEN
                continue
            x = _clean(x, name + ".", defaults)
            if x in (None, "", [], {}) or (defaults and name in defaults and x == defaults[name]):
                continue
            out[k] = x
        return out
    if isinstance(v, list):
        items = [_clean(x) for x in v]
        return sorted(items, key=str) if all(not isinstance(x, (dict, list)) for x in items) else items
    return v


def normalise_mount(m: dict) -> dict:
    """A mount's or auth method's settings, cleaned. No `_returned` field list here: Vault leaves
    unset tuning fields out of sys/mounts, so a missing field doesn't mean the server lacks it.
    MOUNT_DEFAULTS make "unset" and "set to the default" compare equal instead."""
    out = {k: x for k, x in m.items() if k not in VOLATILE}
    # The plugin version actually running says more than the (usually empty) pinned one
    if not out.get("plugin_version") and out.get("running_plugin_version"):
        out["plugin_version"] = out["running_plugin_version"]
    out.pop("running_plugin_version", None)
    # A built-in plugin's version is the server's (v1.21.4+builtin.vault, v2.7.3+builtin.bao): the
    # overview shows that once, so mounts don't all differ between versions, or Vault and OpenBao
    if "+builtin" in str(out.get("plugin_version") or ""):
        out["plugin_version"] = "builtin"
    cleaned = _clean(out, defaults=MOUNT_DEFAULTS)
    if isinstance(out.get("config"), dict):  # all defaults: kept empty, so a tuned side diffs field by field
        cleaned.setdefault("config", {})
    return cleaned


def diff(a: dict | None, b: dict | None, prefix: str = "") -> list[dict]:
    """Fields that differ, flattened to dotted names (config.max_lease_ttl). Sensitive fields
    aren't compared (see not_compared)."""
    a, b = a or {}, b or {}
    out = []
    for k in sorted(set(a) | set(b)):
        x, y = a.get(k), b.get(k)
        name = f"{prefix}{k}"
        if HIDDEN in (x, y):
            continue
        if isinstance(x, dict) and isinstance(y, dict):
            out += diff(x, y, name + ".")
        elif x != y:
            out.append({"field": name, "left": x, "right": y})
    return out


def not_compared(*sides: dict | None, prefix: str = "") -> list[dict]:
    """The sensitive fields on either side, by name, with why they weren't compared."""
    names: dict[str, str] = {}
    for d in sides:
        for k, x in (d or {}).items():
            if x == HIDDEN:
                names[f"{prefix}{k}"] = sensitive(k) or "sensitive"
            elif isinstance(x, dict):
                names.update({f["field"]: f["reason"] for f in not_compared(x, prefix=f"{prefix}{k}.")})
    return [{"field": f, "reason": r} for f, r in sorted(names.items())]


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
# (PKI signature_bits: Vault 256, OpenBao 0). Not compared when one side leaves it automatic (0 or unset).
AUTOMATIC = {"signature_bits"}


def set_aside(fields: list[dict], a: dict, b: dict) -> tuple[list[dict], list[dict]]:
    """Split differences into real ones and fields only one server knows about. Engine objects
    carry `_returned` (the field names the server sent): Vault and OpenBao, or two versions of
    either, return fields the other doesn't have, which say nothing about drift. Auth methods
    carry dotted names for their configuration (`configuration.status`)."""
    la, lb = set(a.get("_returned") or ()), set(b.get("_returned") or ())
    if not (la and lb):
        return fields, []
    nested = {r.split(".")[0] for r in la | lb if "." in r}
    keep, aside = [], []
    for f in fields:
        parts = f["field"].split(".")
        top = ".".join(parts[:2]) if parts[0] in nested and len(parts) > 1 else parts[0]
        if parts[0] in nested and len(parts) == 1:  # the whole configuration on one side only
            keep.append(f)
            continue
        if (top in la) != (top in lb):
            aside.append({**f, "reason": f"only {'the left' if top in la else 'the right'} server has this field"})
        elif top in AUTOMATIC and (f["left"] in (None, 0) or f["right"] in (None, 0)):
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
        hidden = not_compared(a, b)
        out.append({"path": path, "right_path": rpath if rpath and rpath != path else None, "type": (a or b or {}).get("type"),
                    "system": path.strip("/").split("/")[0] in SYSTEM_MOUNTS,
                    "status": "left_only" if b is None else "different" if fields else "equal",
                    "fields": fields, **({"set_aside": aside} if aside else {}), **({"not_compared": hidden} if hidden else {}),
                    "left": _public(a), "right": _public(b),
                    **({"mapped_to": target} if target and target not in right else {})})
    for path in sorted(set(right) - taken):
        b = right[path]
        out.append({"path": path, "right_path": None, "type": b.get("type"),
                    "system": path.strip("/").split("/")[0] in SYSTEM_MOUNTS,
                    "status": "right_only", "fields": [], "left": None, "right": _public(b)})
    return out


product = product_of  # Vault or OpenBao (shared with the policy explainer)


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
            auth[path]["_returned"] = sorted({*auth[path].get("_returned", ()), *(f"configuration.{k}" for k in c)})
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
    # Engines compared generically: their objects listed and their fields compared, secrets left out
    "totp": ["keys"],
    "consul": ["roles"],
    "nomad": ["role"],
    "rabbitmq": ["roles"],
    "transform": ["role", "transformations", "template", "alphabet"],
    "terraform": ["role"],
    "kmip": ["scope"],
    "mongodbatlas": ["roles"],
    "alicloud": ["role"],
    "ad": ["roles"],
}
# Not configuration objects (KV holds data, the rest are built in)
NO_OBJECTS = {"kv", "generic", "cubbyhole", "system", "identity", "ns_system", "ns_identity", "ns_cubbyhole", "token"}
# For an engine Lockstep doesn't know: the usual places plugins keep their objects
PROBE = ["roles", "role", "keys"]
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


def _kinds(etype: str) -> tuple[list[str], bool]:
    """Where an engine type keeps its objects, and whether that's a guess (an unknown plugin)."""
    if etype in ENGINE_OBJECTS:
        return ENGINE_OBJECTS[etype], False
    if not etype or etype in NO_OBJECTS:
        return [], False
    return PROBE, True


async def read_engine_objects(v: VaultClient, mounts: dict[str, dict],
                              truncated: list[str] | None = None) -> tuple[dict[str, dict], list[str]]:
    """'<mount>/<kind>/<name>' -> the object's settings: for the engines in ENGINE_OBJECTS, and for
    other engines whatever is listed under roles/, role/ or keys/. A list longer than MAX_OBJECTS is
    cut off there, and `truncated` says so."""
    out: dict[str, dict] = {}
    missing: list[str] = []
    sem = asyncio.Semaphore(16)

    async def one(mount: str, etype: str, kind: str, guess: bool):
        try:
            names = ((await v.request("LIST", f"{mount}{kind}")).get("data") or {}).get("keys") or []
        except VaultError as e:
            if e.denied and not guess:  # a guessed path the plugin doesn't have can answer 403 too
                missing.append(f"list on {mount}{kind}")
            return
        if len(names) > MAX_OBJECTS and truncated is not None:
            truncated.append(f"{mount}{kind}: {len(names)} objects, the first {MAX_OBJECTS} compared")

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

    await asyncio.gather(*(one(p, m["type"], k, guess) for p, m in mounts.items()
                           for kinds, guess in [_kinds(m.get("type", ""))] for k in kinds))
    return out, sorted(set(missing))


# --------------------------------------------------------------------------- system settings

MAX_SYSTEM = 500
AUTO_ENTITY = re.compile(r"entity_[0-9a-f]{8}")  # the name Vault gives an entity it creates at login
_TIMES = {"id", "namespace_id", "namespace_path", "creation_time", "update_time", "last_update_time", "name",
          "method_name", "mount_accessor", "canonical_id"}
SYSTEM_LABEL = {"audit": "audit device", "password-policy": "password policy", "token-role": "token role",
                "quota": "quota", "quota-config": "quota settings", "mfa-method": "MFA method",
                "mfa-enforcement": "MFA enforcement", "plugin": "plugin", "entity": "identity entity"}


async def read_system(v: VaultClient) -> dict:
    """Settings that live outside mounts, keyed by what they're called rather than cluster IDs:
    audit devices, password policies, token roles, quotas, MFA methods and login enforcements,
    registered (not built-in) plugins, and identity entities with their aliases. Returns
    {"objects", "missing", "truncated", "warnings"}."""
    missing: list[str] = []
    truncated: list[str] = []
    warnings: list[str] = []
    objs: dict[str, dict] = {}
    sem = asyncio.Semaphore(16)

    async def get(path: str) -> dict | None:
        async with sem:
            try:
                r = await v.request("GET", path)
            except VaultError as e:
                if e.denied:
                    missing.append(f"read on {path}")
                elif e.status not in (400, 404, 405):  # 400/405: an Enterprise feature, or not in this version
                    raise
                return None
        return r.get("data") if isinstance(r.get("data"), dict) else r

    async def names(path: str, what: str) -> list[str]:
        async with sem:
            try:
                keys = ((await v.request("LIST", path)).get("data") or {}).get("keys") or []
            except VaultError as e:
                if e.denied:
                    missing.append(f"list on {path}")
                elif e.status not in (400, 404, 405):
                    raise
                return []
        if len(keys) > MAX_SYSTEM:
            truncated.append(f"{what}: {len(keys)}, the first {MAX_SYSTEM} compared")
        return [k for k in keys[:MAX_SYSTEM] if not k.endswith("/")]

    def put(key: str, d: dict | None) -> None:
        if d is not None:
            objs[key] = {**_clean({k: x for k, x in d.items() if k not in _TIMES}), "_returned": sorted(d)}

    auth = await get("sys/auth") or {}
    accessor_path = {m.get("accessor"): p for p, m in auth.items() if isinstance(m, dict) and m.get("accessor")}

    async def audit():
        d = await get("sys/audit")
        if d is None:
            return
        devices = {p: m for p, m in d.items() if isinstance(m, dict) and "type" in m}
        if not devices:
            warnings.append("No audit device: requests to this Vault aren't logged.")
        for p, m in devices.items():
            put(f"audit/{p}", {k: m.get(k) for k in ("type", "description", "options", "local")})

    async def password_policies():
        async def one(n):
            d = await get(f"sys/policies/password/{n}")
            if d is not None:
                text = "\n".join(ln.strip() for ln in str(d.get("policy") or "").splitlines() if ln.strip())
                objs[f"password-policy/{n}"] = {"policy": text, "_returned": ["policy"]}
        await asyncio.gather(*(one(n) for n in await names("sys/policies/password", "password policies")))

    async def token_roles():
        async def one(n):
            put(f"token-role/{n}", await get(f"auth/token/roles/{n}"))
        await asyncio.gather(*(one(n) for n in await names("auth/token/roles", "token roles")))

    async def quotas():
        put("quota-config/", await get("sys/quotas/config"))

        async def kind(k):
            async def one(n):
                put(f"quota/{k}/{n}", await get(f"sys/quotas/{k}/{n}"))
            await asyncio.gather(*(one(n) for n in await names(f"sys/quotas/{k}", f"{k} quotas")))
        await asyncio.gather(kind("rate-limit"), kind("lease-count"))

    group_names: dict[str, str] = {}
    entity_names: dict[str, str] = {}

    async def name_of(kind: str, i: str, cache: dict[str, str]) -> str:
        if i not in cache:
            d = await get(f"identity/{kind}/id/{i}")
            cache[i] = (d or {}).get("name") or i
        return cache[i]

    async def mfa():
        async with sem:
            try:
                listing = (await v.request("LIST", "identity/mfa/method")).get("data") or {}
            except VaultError as e:
                if e.denied:
                    missing.append("list on identity/mfa/method")
                elif e.status not in (400, 404, 405):
                    raise
                listing = {}
        info = listing.get("key_info") or {}
        method_names: dict[str, str] = {}

        async def method(i: str):
            t = (info.get(i) or {}).get("type")
            d = await get(f"identity/mfa/method/{t}/{i}") if t else None
            if d is None:
                return
            name = d.get("method_name") or d.get("name") or i
            method_names[i] = f"{t}/{name}"
            put(f"mfa-method/{t}/{name}", d)
        await asyncio.gather(*(method(i) for i in (listing.get("keys") or [])[:MAX_SYSTEM]))

        async def enforcement(n: str):
            d = await get(f"identity/mfa/login-enforcement/{n}")
            if d is None:
                return
            d = dict(d)
            d["mfa_methods"] = sorted(method_names.get(i, i) for i in d.pop("mfa_method_ids", None) or [])
            d["auth_methods"] = sorted(accessor_path.get(a, a) for a in d.pop("auth_method_accessors", None) or [])
            d["identity_groups"] = sorted([await name_of("group", i, group_names) for i in d.pop("identity_group_ids", None) or []])
            d["identity_entities"] = sorted([await name_of("entity", i, entity_names) for i in d.pop("identity_entity_ids", None) or []])
            put(f"mfa-enforcement/{n}", d)
        await asyncio.gather(*(enforcement(n) for n in await names("identity/mfa/login-enforcement", "MFA enforcements")))

    async def plugins():
        d = await get("sys/plugins/catalog")
        found: dict[str, dict] = {}
        for p in (d or {}).get("detailed") or []:
            if p.get("builtin"):
                continue  # built-in plugins come with the server's version: the overview shows that
            key = f"plugin/{p.get('type')}/{p.get('name')}"
            found.setdefault(key, {"versions": {}})["versions"][p.get("version") or "(no version)"] = p.get("sha256") or ""
            if p.get("oci_image"):
                found[key]["oci_image"] = p["oci_image"]
        for key, x in found.items():
            objs[key] = {**x, "_returned": sorted(x)}

    async def entities():
        async def one(n):
            d = await get(f"identity/entity/name/{n}")
            if d is None:
                return
            aliases = sorted(f"{accessor_path.get(a.get('mount_accessor'), a.get('mount_accessor'))}{a.get('name')}"
                             for a in d.get("aliases") or [])
            key = n
            if AUTO_ENTITY.fullmatch(n):  # named by Vault at login: differs on every cluster, so pair by alias
                if not aliases or not (d.get("policies") or d.get("metadata")):
                    return  # just someone who signed in: not configuration
                key = " + ".join(aliases)
            put(f"entity/{key}", {"policies": sorted(d.get("policies") or []), "metadata": d.get("metadata"),
                                  "disabled": d.get("disabled") or None, "aliases": aliases})
        await asyncio.gather(*(one(n) for n in await names("identity/entity/name", "identity entities")))

    await asyncio.gather(audit(), password_policies(), token_roles(), quotas(), mfa(), plugins(), entities())
    return {"objects": objs, "missing": sorted(set(missing)), "truncated": truncated, "warnings": warnings}


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
    ltrunc: list[str] = []
    rtrunc: list[str] = []
    (le, lmiss), (re_, rmiss), ls, rs = await asyncio.gather(
        read_engine_objects(lv, {p: lc["mounts"][p] for p in both}, ltrunc),
        read_engine_objects(rv, {r: rc["mounts"][r] for r in both.values()}, rtrunc),
        read_system(lv), read_system(rv))
    from .configcopy import COPYABLE
    engines = pair(le, re_, profile)
    for p in engines:  # the engine's type, not the object's own "type" (a Transit key's type, say)
        obj = p["left"] or p["right"]
        p["type"] = obj["engine"]
        p["copyable"] = obj["kind"] in COPYABLE.get(obj["engine"], set())
    system = pair(ls["objects"], rs["objects"], profile)
    for p in system:
        p["type"] = SYSTEM_LABEL.get(p["path"].split("/")[0], p["path"].split("/")[0])
        p["system"] = False
    lc["missing"] += lmiss + ls["missing"]
    rc["missing"] += rmiss + rs["missing"]
    summary = {s: sum(p["status"] == s for p in mounts + auth + engines + system if not p["system"])
               for s in ("equal", "different", "left_only", "right_only")}
    return {"overview": {"left": lo, "right": ro}, "mounts": mounts, "auth": auth, "engines": engines, "system": system,
            "summary": summary, "profile": profile.name if profile else None,
            "missing": {"left": lc["missing"], "right": rc["missing"]},
            "truncated": {"left": ltrunc + ls["truncated"], "right": rtrunc + rs["truncated"]},
            "warnings": {"left": ls["warnings"], "right": rs["warnings"]}}


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
