"""Browsing one KV v2 mount, and editing it safely.

  GET  /api/browse/list      one folder: its entries and what the token may do with each
  GET  /api/browse/secret    a secret's metadata, versions and key names (no values)
  GET  /api/browse/values    a secret's values (current or a given version): only when the user shows them
  POST /api/browse/find      secrets whose path contains some text
  POST /api/browse/diff      two versions of a secret, key by key
  POST /api/browse/preview   what edits would do
  POST /api/browse/apply     do them (refused when LOCKSTEP_READ_ONLY)
  POST /api/browse/metadata  change a secret's metadata (version settings, custom metadata)
  POST /api/browse/share     wrap chosen values in a one-time token (response wrapping)
  POST /api/browse/unwrap    look up or open a wrapping token

Edits follow the same rules as copies: every write is checked against the version the user saw
(KV v2 check-and-set), removing every key soft-deletes the latest version instead of writing an
empty one, destroying follows LOCKSTEP_ALLOW_DESTROY, and every attempt is audit-logged without
values.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, model_validator

from ..config import Settings, get_settings
from ..session import Connection, SessionData, load_session
from ..reveal import Shown, reveal
from ..vault import VaultClient, VaultError
from .connections import client_for, get_connection, vault_http_error
from .guard import require_writable
from .. import writepolicy
from .sync import MAX_SET_BYTES, MAX_SET_KEYS
from ..vault import _q

router = APIRouter(prefix="/api/browse", tags=["browse"])
audit = logging.getLogger("lockstep.audit")

Sess = Annotated[SessionData, Depends(load_session)]
Conf = Annotated[Settings, Depends(get_settings)]

PAGE = 200
MAX_EDITS = 100


def _clean(p: str) -> str:
    return p.strip().strip("/")


async def _caps(v: VaultClient, paths: list[str]) -> dict[str, list[str]] | None:
    try:
        out: dict[str, list[str]] = {}
        for i in range(0, len(paths), 400):
            out |= await v.capabilities(paths[i:i + 400])
        return out
    except VaultError:
        return None  # can't tell: the UI leaves controls on and the write itself decides


def _has(caps: list[str] | None, *want: str) -> bool | None:
    if caps is None:
        return None
    return "root" in caps or any(c in caps for c in want)


# --------------------------------------------------------------------------- reading


@router.get("/list")
async def list_folder(session: Sess, settings: Conf, conn_id: str = Query(), mount: str = Query(min_length=1),
                      folder: str = "", offset: int = Query(0, ge=0), limit: int = Query(PAGE, ge=1, le=1000)):
    conn = get_connection(session, conn_id)
    mount, folder = _clean(mount), _clean(folder)
    base = f"{folder}/" if folder else ""
    async with client_for(conn, settings) as v:
        try:
            keys = await v.kv_list(mount, base)
        except VaultError as e:
            if e.denied:
                return {"mount": mount, "folder": folder, "total": 0, "offset": offset, "entries": [], "denied": True}
            raise vault_http_error(e) from e
        keys = sorted(keys, key=lambda k: (not k.endswith("/"), k.lower()))
        page = keys[offset:offset + limit]
        paths = []
        for k in page:
            p = base + k
            paths += [f"{mount}/metadata/{p}"] if k.endswith("/") else [f"{mount}/data/{p}", f"{mount}/metadata/{p}"]
        caps = await _caps(v, paths)
    entries = []
    for k in page:
        p = base + k.rstrip("/")
        if k.endswith("/"):
            c = caps.get(f"{mount}/metadata/{p}/") if caps else None
            entries.append({"name": k.rstrip("/"), "path": p, "folder": True, "caps": {"list": _has(c, "list")}})
        else:
            d = caps.get(f"{mount}/data/{p}") if caps else None
            m = caps.get(f"{mount}/metadata/{p}") if caps else None
            entries.append({"name": k, "path": p, "folder": False,
                            "caps": {"read": _has(d, "read"), "write": _has(d, "create", "update"),
                                     "history": _has(m, "read")}})
    return {"mount": mount, "folder": folder, "total": len(keys), "offset": offset, "entries": entries, "denied": False}


@router.get("/secret")
async def secret_info(session: Sess, settings: Conf, conn_id: str = Query(), mount: str = Query(min_length=1),
                      path: str = Query(min_length=1), version: int | None = Query(None, ge=1)):
    """Metadata, versions and key names of a secret (or one version of it). Never values."""
    conn = get_connection(session, conn_id)
    mount, path = _clean(mount), _clean(path)
    async with client_for(conn, settings) as v:
        meta_res, data_res, caps = await asyncio.gather(
            _try(v.kv_metadata(mount, path)), _try(v.kv_read(mount, path, version=version)),
            _caps(v, [f"{mount}/{p}/{path}" for p in ("data", "metadata", "delete", "undelete", "destroy")]))
    meta, meta_err = meta_res
    data, data_err = data_res
    subkeys = None
    if data_err is not None and data_err.denied:
        # No read on the values: the key names may still be visible through subkeys/
        try:
            async with client_for(conn, settings) as v2:
                sk = (await v2.request("GET", f"{mount}/subkeys/{_q(path)}", params={"depth": 1})).get("data") or {}
            subkeys = sorted((sk.get("subkeys") or {}).keys())
        except VaultError:
            subkeys = None
    if meta_err and meta_err.status == 404 and (data is None or data.state == "absent"):
        raise HTTPException(404, detail={"message": f"No secret at {mount}/{path}"})
    versions = []
    for n, info in sorted(((meta or {}).get("versions") or {}).items(), key=lambda x: -int(x[0])):
        versions.append({"version": int(n), "created": info.get("created_time"),
                         "deleted": bool(info.get("deletion_time")), "destroyed": bool(info.get("destroyed")),
                         # Who wrote it and who deleted it (Vault 1.21+ records these)
                         "by": (info.get("created_by") or {}).get("actor"),
                         "deleted_by": (info.get("deleted_by") or {}).get("actor")})
    current = (meta or {}).get("current_version") or (data.version if data and version is None else None)
    c = lambda kind: caps.get(f"{mount}/{kind}/{path}") if caps else None  # noqa: E731
    state = "absent"
    if data is not None:
        state = data.state
        if version and any(x["version"] == version and x["destroyed"] for x in versions):
            state = "destroyed"
    return {
        "path": path, "mount": mount, "state": state, "version": data.version if data else version,
        "current_version": current, "updated": data.updated if data else None,
        "keys": sorted((data.data or {}).keys()) if data and data.state == "present" else subkeys,
        "keys_only": subkeys is not None,  # names from subkeys/: the values can't be read
        "read_error": data_err.message if data_err else None,
        "metadata": None if meta is None else {
            k: meta.get(k) for k in ("max_versions", "cas_required", "delete_version_after", "custom_metadata",
                                     "created_time", "updated_time", "oldest_version")}
            | {"updated_by": (meta.get("last_updated_by") or {}).get("actor"), "hash": _meta_hash(meta)},
        "metadata_error": meta_err.message if meta_err and meta_err.status != 404 else None,
        "versions": versions,
        "caps": {"read": _has(c("data"), "read"), "write": _has(c("data"), "create", "update"),
                 "patch": _has(c("data"), "patch"),
                 "delete": _has(c("data"), "delete"), "delete_versions": _has(c("delete"), "update"),
                 "undelete": _has(c("undelete"), "update"), "destroy_versions": _has(c("destroy"), "update"),
                 "destroy": _has(c("metadata"), "delete"), "history": _has(c("metadata"), "read")},
    }


async def _try(coro):
    try:
        return await coro, None
    except VaultError as e:
        return None, e


@router.get("/values")
async def secret_values(session: Sess, settings: Conf, conn_id: str = Query(), mount: str = Query(min_length=1),
                        path: str = Query(min_length=1), version: int | None = Query(None, ge=1)):
    """The values of a secret, or of one version. The UI asks only when the user shows them."""
    conn = get_connection(session, conn_id)
    async with client_for(conn, settings) as v:
        try:
            s = await v.kv_read(_clean(mount), _clean(path), version=version)
        except VaultError as e:
            raise vault_http_error(e) from e
    if s.state != "present":
        raise HTTPException(404, detail={"message": "That version has no data (deleted, destroyed or missing)"})
    reveal(settings, "browse.show", [Shown(conn, _clean(mount), _clean(path), list(s.data or {}), s.version)])
    return {"path": _clean(path), "version": s.version, "data": s.data}


class FindRequest(BaseModel):
    conn_id: str
    mount: str = Field(min_length=1)
    folder: str = ""
    query: str = Field(min_length=1, max_length=256)
    limit: int = Field(200, ge=1, le=1000)


@router.post("/find")
async def find(body: FindRequest, session: Sess, settings: Conf):
    conn = get_connection(session, body.conn_id)
    async with client_for(conn, settings) as v:
        try:
            tree = await v.kv_tree(_clean(body.mount), _clean(body.folder), max_secrets=settings.max_tree_secrets)
        except VaultError as e:
            raise vault_http_error(e) from e
    q = body.query.lower()
    hits = [p for p in tree.secrets if q in p.lower()]
    return {"matches": hits[:body.limit], "more": len(hits) > body.limit, "denied": tree.denied,
            "truncated": tree.truncated}


class DiffRequest(BaseModel):
    conn_id: str
    mount: str = Field(min_length=1)
    path: str = Field(min_length=1)
    a: int = Field(ge=1)  # usually the older version
    b: int = Field(ge=1)
    reveal: bool = False


@router.post("/diff")
async def diff_versions(body: DiffRequest, session: Sess, settings: Conf):
    conn = get_connection(session, body.conn_id)
    mount, path = _clean(body.mount), _clean(body.path)
    async with client_for(conn, settings) as v:
        try:
            a, b = await asyncio.gather(v.kv_read(mount, path, version=body.a), v.kv_read(mount, path, version=body.b))
        except VaultError as e:
            raise vault_http_error(e) from e
    for n, s in ((body.a, a), (body.b, b)):
        if s.state != "present":
            raise HTTPException(400, detail={"message": f"Version {n} has no data (deleted or destroyed)"})
    da, db = a.data or {}, b.data or {}
    keys = []
    for k in sorted(set(da) | set(db)):
        change = ("added" if k not in da else "removed" if k not in db
                  else "same" if _canon(da[k]) == _canon(db[k]) else "changed")
        keys.append({"key": k, "change": change,
                     **({"a": da.get(k), "b": db.get(k)} if body.reveal else {})})
    if body.reveal:
        reveal(settings, "browse.diff", [Shown(conn, mount, path, list(da), body.a), Shown(conn, mount, path, list(db), body.b)])
    return {"a": body.a, "b": body.b, "keys": keys}


def _canon(x: Any) -> str:
    return json.dumps(x, sort_keys=True)


# --------------------------------------------------------------------------- editing


class Edit(BaseModel):
    path: str = Field(min_length=1, max_length=4096)
    action: Literal["write", "delete", "undelete", "destroy", "rollback"]
    expected_version: int | None = None  # the current version the user saw (None: the secret is new)
    set: dict[str, Any] | None = Field(default=None, max_length=MAX_SET_KEYS)  # write: typed values
    remove: list[str] | None = Field(default=None, max_length=MAX_SET_KEYS)  # write: keys to drop
    versions: list[int] | None = Field(default=None, max_length=100)  # delete/undelete/destroy (default: current)
    rollback_to: int | None = Field(default=None, ge=1)

    @model_validator(mode="after")
    def _check(self):
        self.path = _clean(self.path)
        if not self.path or "//" in self.path:
            raise ValueError("a secret path can't be empty or contain //")
        if self.action == "write":
            if not self.set and not self.remove:
                raise ValueError(f"{self.path}: nothing to write")
            both = set(self.set or {}) & set(self.remove or [])
            if both:
                raise ValueError(f"{', '.join(sorted(both))}: both set and removed")
            if any(not k or len(k) > 512 for k in self.set or {}):
                raise ValueError("key names must be 1-512 characters")
            if len(json.dumps(self.set or {})) > MAX_SET_BYTES:
                raise ValueError(f"values for {self.path} are too large")
        if self.action == "rollback" and not self.rollback_to:
            raise ValueError("rollback needs rollback_to")
        if self.action in ("undelete", "destroy") and not self.versions:
            raise ValueError(f"{self.action} needs versions")
        return self


class EditRequest(BaseModel):
    conn_id: str
    mount: str = Field(min_length=1)
    edits: list[Edit] = Field(min_length=1, max_length=MAX_EDITS)
    reveal: bool = False  # preview: include old and new values


class ApplyRequest(EditRequest):
    confirm: bool


class KeyChange(BaseModel):
    key: str
    action: Literal["add", "update", "remove", "unchanged"]
    old: Any = None  # only with reveal
    new: Any = None


class EditResult(BaseModel):
    path: str
    action: str  # what will happen / happened: write | delete | undelete | destroy | rollback
    status: Literal["ready", "noop", "conflict", "invalid", "error", "applied", "denied"]
    old_version: int | None = None
    new_version: int | None = None
    versions: list[int] = []
    keys: list[KeyChange] = []
    message: str = ""
    patch: bool = False  # sent as a PATCH: the sign-in may change keys but not read the values


async def _plan(v: VaultClient, mount: str, e: Edit, reveal: bool, settings: Settings) -> tuple[EditResult, dict | None]:
    """Check one edit against Vault now. Returns the result (status ready/noop/...) and the data to write."""
    res = EditResult(path=e.path, action=e.action, status="ready")
    try:
        cur = await v.kv_read(mount, e.path)
    except VaultError as err:
        if err.denied and e.action == "write":
            return await _plan_patch(v, mount, e, res)
        res.status, res.message = ("denied" if err.denied else "error"), err.message
        return res, None
    actual = cur.version if cur.state in ("present", "deleted") and cur.version else 0
    res.old_version = actual or None
    if e.action in ("write", "rollback") or e.expected_version is not None:
        if actual != (e.expected_version or 0):
            res.status = "conflict"
            res.message = (f"Changed since you loaded it (expected v{e.expected_version or '—'}, now v{actual or '—'}). "
                           "Reload it and try again.")
            return res, None

    if e.action in ("delete", "undelete", "destroy"):
        if e.action == "destroy" and not settings.allow_destroy:
            res.status, res.message = "invalid", "Destroying is turned off on this server (LOCKSTEP_ALLOW_DESTROY)."
            return res, None
        if not actual:
            res.status, res.message = "noop", "No such secret."
            return res, None
        res.versions = sorted(e.versions or [actual])
        if e.action == "delete" and cur.state == "deleted" and res.versions == [actual]:
            res.status, res.message = "noop", "The latest version is already deleted."
        return res, None

    if e.action == "rollback":
        try:
            old = await v.kv_read(mount, e.path, version=e.rollback_to)
        except VaultError as err:
            res.status, res.message = ("denied" if err.denied else "error"), err.message
            return res, None
        if old.state != "present":
            res.status, res.message = "invalid", f"Version {e.rollback_to} has no data (deleted or destroyed)."
            return res, None
        new = dict(old.data or {})
    else:
        base = dict(cur.data or {}) if cur.state == "present" else {}
        new = {k: x for k, x in base.items() if k not in set(e.remove or [])} | (e.set or {})
    base = dict(cur.data or {}) if cur.state == "present" else {}
    for k in sorted(set(base) | set(new)):
        if k not in new:
            act = "remove"
        elif k not in base:
            act = "add"
        else:
            act = "unchanged" if _canon(base[k]) == _canon(new[k]) else "update"
        res.keys.append(KeyChange(key=k, action=act, old=base.get(k) if reveal else None,
                                  new=new.get(k) if reveal else None))
    if all(k.action == "unchanged" for k in res.keys) and cur.state == "present":
        res.status, res.message = "noop", "Nothing changes."
        return res, None
    if not new:
        if cur.state != "present":
            res.status, res.message = "noop", "Nothing to write."
            return res, None
        res.action, res.versions = "delete", [actual]
        res.message = "Every key is removed, so the latest version is deleted instead (vault kv undelete brings it back)."
        return res, None
    res.new_version = actual + 1
    return res, new


async def _plan_patch(v: VaultClient, mount: str, e: Edit, res: EditResult) -> tuple[EditResult, dict | None]:
    """A write by a sign-in that can't read the values: plan it from the metadata and subkeys/,
    and send only the changed keys (PATCH) with check-and-set."""
    try:
        meta = await v.kv_metadata(mount, e.path)
        sub = (await v.request("GET", f"{mount}/subkeys/{_q(e.path)}", params={"depth": 1})).get("data") or {}
    except VaultError as err:
        res.status = "denied" if err.denied else "error"
        res.message = "Your sign-in may neither read this secret nor see its structure (subkeys)."
        return res, None
    actual = meta.get("current_version") or 0
    res.old_version = actual or None
    if actual != (e.expected_version or 0):
        res.status = "conflict"
        res.message = f"Changed since you loaded it (expected v{e.expected_version or '—'}, now v{actual or '—'})."
        return res, None
    if not actual:
        res.status, res.message = "denied", "A new secret needs a full write, which this sign-in may not do."
        return res, None
    names = set((sub.get("subkeys") or {}).keys())
    res.keys = [KeyChange(key=k, action="update" if k in names else "add") for k in sorted(e.set or {})]
    res.keys += [KeyChange(key=k, action="remove") for k in sorted(e.remove or []) if k in names]
    res.patch, res.new_version = True, actual + 1
    res.message = "Sent as a patch: your sign-in can change keys but not read the values."
    return res, {}


async def _run(body: EditRequest, session: SessionData, settings: Settings, write: bool) -> list[EditResult]:
    conn = get_connection(session, body.conn_id)
    mount = _clean(body.mount)
    out: list[EditResult] = []
    async with client_for(conn, settings) as v:
        for e in body.edits:  # one at a time: predictable order and audit trail
            res, data = await _plan(v, mount, e, body.reveal and not write, settings)
            action = "destroy" if e.action == "destroy" else "write"
            if res.status == "ready" and (why := writepolicy.refusal(settings, conn, f"{mount}/{e.path}", action)
                                          or writepolicy.needs_plan(settings, conn)):
                res.status, res.message = "invalid", why
                if write:
                    writepolicy.log_refusal(conn, f"{mount}/{e.path}", action, f"browse.{e.action}", why)
            if write and res.status == "ready":
                try:
                    if res.action == "delete":
                        if res.versions == [res.old_version]:
                            await v.kv_delete(mount, e.path)
                        else:
                            await v.kv_delete_versions(mount, e.path, res.versions)
                    elif res.action == "undelete":
                        await v.kv_undelete(mount, e.path, res.versions)
                    elif res.action == "destroy":
                        await v.kv_destroy_versions(mount, e.path, res.versions)
                    elif res.patch:
                        res.new_version = await v.kv_patch(
                            mount, e.path, {**(e.set or {}), **{k: None for k in e.remove or []}}, cas=res.old_version)
                    else:
                        try:
                            res.new_version = await v.kv_write(mount, e.path, data or {}, cas=res.old_version or 0)
                        except VaultError as err:
                            if not (err.denied and e.action == "write" and res.old_version):
                                raise
                            # No update right: a token with only `patch` can still change keys
                            res.new_version = await v.kv_patch(
                                mount, e.path, {**(e.set or {}), **{k: None for k in e.remove or []}}, cas=res.old_version)
                    res.status = "applied"
                except VaultError as err:
                    if err.status == 400 and "check-and-set" in err.message:
                        res.status, res.message = "conflict", "Changed while saving; nothing written. Reload it."
                    else:
                        res.status, res.message = ("denied" if err.denied else "error"), err.message
                _audit(conn, mount, res)
            out.append(res)
    return out


def _audit(conn: Connection, mount: str, res: EditResult) -> None:
    audit.info(json.dumps({
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "event": f"browse.{res.action}",
        "outcome": res.status,
        "actor": {"identity": conn.display_name, "auth": conn.auth_method, "entity_id": conn.entity_id, "accessor": conn.accessor},
        "target": {"vault": conn.name, "url": conn.url, "mount": mount, "path": res.path,
                   "old_version": res.old_version, "new_version": res.new_version},
        "keys": [k.key for k in res.keys if k.action != "unchanged"],  # names only, never values
        "versions": res.versions,
        "message": res.message,
    }, sort_keys=True))


@router.post("/preview", response_model=list[EditResult])
async def preview(body: EditRequest, session: Sess, settings: Conf):
    out = await _run(body, session, settings, write=False)
    if body.reveal:  # the current values being replaced (new ones were typed by the user)
        conn = get_connection(session, body.conn_id)
        reveal(settings, "browse.preview", [Shown(conn, _clean(body.mount), r.path,
                                                  [k.key for k in r.keys if k.old is not None], r.old_version) for r in out])
    return out


@router.post("/apply", response_model=list[EditResult])
async def apply(body: ApplyRequest, session: Sess, settings: Conf):
    require_writable(settings)
    if not body.confirm:
        raise HTTPException(400, detail={"message": "Saving requires confirm=true"})
    return await _run(body, session, settings, write=True)


# --------------------------------------------------------------------------- metadata


META_FIELDS = ("max_versions", "cas_required", "delete_version_after", "custom_metadata")


def _meta_hash(meta: dict) -> str:
    """A fingerprint of the editable metadata. Vault keeps no version of metadata (and a metadata
    write doesn't change updated_time), so edits are checked against this instead."""
    import hashlib
    return hashlib.sha256(_canon({k: meta.get(k) for k in META_FIELDS}).encode()).hexdigest()[:16]


DURATION = r"^(0|\d+(\.\d+)?(ns|us|µs|ms|s|m|h))+$"


class MetadataRequest(BaseModel):
    conn_id: str
    mount: str = Field(min_length=1)
    path: str = Field(min_length=1)
    expected_hash: str | None = None  # the metadata's hash when loaded (from /secret): refuse if it changed
    max_versions: int | None = Field(default=None, ge=0, le=10000)
    cas_required: bool | None = None
    delete_version_after: str | None = Field(default=None, pattern=DURATION)
    custom_metadata: dict[str, str] | None = Field(default=None, max_length=64)  # replaces the whole set

    @model_validator(mode="after")
    def _check(self):
        for k, v in (self.custom_metadata or {}).items():
            if not k or len(k) > 128 or len(v) > 512:
                raise ValueError("custom metadata keys are 1-128 characters and values at most 512")
        return self


@router.post("/metadata")
async def write_metadata(body: MetadataRequest, session: Sess, settings: Conf):
    require_writable(settings)
    conn = get_connection(session, body.conn_id)
    mount, path = _clean(body.mount), _clean(body.path)
    writepolicy.check(settings, conn, f"{mount}/{path}", event="browse.metadata")
    if why := writepolicy.needs_plan(settings, conn):
        writepolicy.log_refusal(conn, f"{mount}/{path}", "write", "browse.metadata", why)
        raise HTTPException(403, detail={"message": why, "write_policy": True})
    fields = {k: getattr(body, k) for k in META_FIELDS if getattr(body, k) is not None}
    if not fields:
        raise HTTPException(400, detail={"message": "Nothing to change"})
    res = EditResult(path=path, action="metadata", status="error", keys=[KeyChange(key=k, action="update") for k in fields])
    async with client_for(conn, settings) as v:
        try:
            meta = await v.kv_metadata(mount, path)
            if body.expected_hash and _meta_hash(meta) != body.expected_hash:
                res.status, res.message = "conflict", "The metadata changed since you loaded it. Reload it and try again."
            else:
                await v.kv_metadata_write(mount, path, fields)
                res.status = "applied"
        except VaultError as e:
            res.status, res.message = ("denied" if e.denied else "error"), e.message
        _audit(conn, mount, res)
    return res


# --------------------------------------------------------------------------- share once


TTLS = {"5m": 300, "15m": 900, "1h": 3600, "24h": 86400}


class ShareRequest(BaseModel):
    conn_id: str
    mount: str = Field(min_length=1)
    path: str = Field(min_length=1)
    keys: list[str] | None = Field(default=None, max_length=MAX_SET_KEYS)  # None: every key
    version: int | None = Field(default=None, ge=1)
    ttl: Literal["5m", "15m", "1h", "24h"] = "15m"


@router.post("/share")
async def share(body: ShareRequest, session: Sess, settings: Conf):
    """Wrap chosen values in a single-use wrapping token (sys/wrapping/wrap). The values go from
    Vault to Vault: Lockstep reads them and hands them straight to the wrap call."""
    conn = get_connection(session, body.conn_id)
    mount, path = _clean(body.mount), _clean(body.path)
    async with client_for(conn, settings) as v:
        try:
            s = await v.kv_read(mount, path, version=body.version)
            if s.state != "present":
                raise HTTPException(404, detail={"message": "That secret (or version) has no data"})
            data = s.data or {}
            if body.keys is not None:
                missing = [k for k in body.keys if k not in data]
                if missing:
                    raise HTTPException(400, detail={"message": f"Not in the secret: {', '.join(missing)}"})
                data = {k: data[k] for k in body.keys}
            wrapped = await v.wrap(data, TTLS[body.ttl])
        except VaultError as e:
            raise vault_http_error(e) from e
    audit.info(json.dumps({
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "event": "browse.share", "outcome": "applied",
        "actor": {"identity": conn.display_name, "auth": conn.auth_method, "entity_id": conn.entity_id, "accessor": conn.accessor},
        "target": {"vault": conn.name, "url": conn.url, "mount": mount, "path": path, "version": s.version},
        "keys": sorted(data), "ttl": body.ttl, "wrapping_accessor": wrapped.get("accessor"),
    }, sort_keys=True))
    return {"token": wrapped["token"], "ttl": wrapped["ttl"], "created": wrapped.get("creation_time"),
            "keys": sorted(data), "accessor": wrapped.get("accessor")}


class UnwrapRequest(BaseModel):
    conn_id: str  # which Vault the token belongs to
    token: str = Field(min_length=10, max_length=512)
    open: bool = False  # False: only look it up (doesn't use it up)


@router.post("/unwrap")
async def unwrap(body: UnwrapRequest, session: Sess, settings: Conf):
    conn = get_connection(session, body.conn_id)
    async with client_for(conn, settings) as v:
        try:
            info = await v.wrap_lookup(body.token.strip())
            if not body.open:
                return {"info": info}
            data = await v.unwrap(body.token.strip())
        except VaultError as e:
            if e.status in (400, 403):
                raise HTTPException(400, detail={"message": "That token isn't valid: it was used already, expired, "
                                                            "or belongs to another Vault."}) from e
            raise vault_http_error(e) from e
    reveal(settings, "unwrap", [Shown(conn, "", f"(wrapped by {info.get('creation_path') or 'unknown'})",
                                      list(data or {}) if isinstance(data, dict) else ["(response)"])])
    return {"info": info, "data": data}
