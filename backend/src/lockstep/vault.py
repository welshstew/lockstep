"""Minimal async Vault HTTP client: only the endpoints this tool needs."""

from __future__ import annotations

import asyncio
import logging
import ssl
import time
from urllib.parse import quote
from dataclasses import dataclass, field
from typing import Any

import httpcore
import httpx

from . import metrics

from .config import Settings

log = logging.getLogger("lockstep.vault")


class VaultError(Exception):
    """A Vault request failed. `status` is Vault's HTTP status, or 0 if Vault was unreachable."""

    def __init__(self, status: int, message: str, path: str = "", body: dict | None = None):
        super().__init__(f"{status} {path}: {message}")
        self.status = status
        self.message = message
        self.path = path
        self.body = body or {}

    @property
    def denied(self) -> bool:
        return self.status == 403


def _ssl_context(settings: Settings) -> ssl.SSLContext | bool:
    if not settings.vault_tls_verify:
        return False
    if settings.vault_ca_bundle:
        return ssl.create_default_context(cafile=settings.vault_ca_bundle)
    return True


@dataclass
class KvMount:
    path: str  # without trailing slash
    description: str = ""
    version: str = "2"


@dataclass
class KvSecret:
    state: str  # present | absent | deleted
    data: dict | None = None
    version: int | None = None
    updated: str | None = None


@dataclass
class TreeResult:
    secrets: list[str] = field(default_factory=list)  # paths relative to the mount, e.g. "payments/db"
    denied: list[str] = field(default_factory=list)  # folders we could not list, e.g. "restricted/"
    truncated: bool = False


def _origin(url: httpx.URL | str) -> str:
    u = httpx.URL(url)
    return f"{u.scheme}://{u.host}:{u.port or (443 if u.scheme == 'https' else 80)}".lower()


IDEMPOTENT = {"GET", "LIST", "HEAD"}
RETRY_STATUS = {429, 502, 503, 504}
RETRIES = 2  # extra attempts for reads; writes are never retried (check-and-set makes a repeat safe by hand)
BACKOFF = (0.25, 1.0)  # seconds before the first and second retry
MAX_REDIRECTS = 2


class _Pinned(httpcore.AsyncNetworkBackend):
    """Connects only to addresses that were checked: host -> the IP it was checked as."""

    def __init__(self, inner: httpcore.AsyncNetworkBackend, pins: dict[str, str]):
        self.inner, self.pins = inner, pins

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        ip = self.pins.get(str(host).lower().strip("[]"))
        if ip is None:  # fail closed: only checked hosts
            raise httpcore.ConnectError(f"{host} wasn't checked")
        return await self.inner.connect_tcp(ip, port, timeout=timeout, local_address=local_address,
                                            socket_options=socket_options)

    async def sleep(self, seconds: float) -> None:
        await self.inner.sleep(seconds)


class VaultClient:
    def __init__(self, url: str, settings: Settings, token: str | None = None,
                 namespace: str | None = None, timeout: float | None = None, custom: bool = False):
        """`custom`: a user-typed address (not a preset): checked by lockstep.addresses before the
        first request, and only the checked address is connected to."""
        headers = {"X-Vault-Request": "true"}
        if token:
            headers["X-Vault-Token"] = token
        if namespace:
            headers["X-Vault-Namespace"] = namespace
        base = url.rstrip("/")
        preset = next((p for p in settings.preset_connections if p.url.rstrip("/") == base), None)
        if timeout is None:
            timeout = (preset.timeout_seconds if preset else None) or settings.vault_timeout_seconds
        self._custom = custom
        self._pins: dict[str, str] = {}
        transport = None
        if custom:
            # httpx has no resolver hook: wrap the pool's network backend. (An explicit transport
            # also ignores HTTPS_PROXY, which a pinned address couldn't go through anyway.)
            transport = httpx.AsyncHTTPTransport(verify=_ssl_context(settings))
            pool = transport._pool
            pool._network_backend = _Pinned(pool._network_backend, self._pins)
        self._http = httpx.AsyncClient(base_url=base + "/v1/", headers=headers, transport=transport,
                                       verify=_ssl_context(settings), timeout=timeout)
        self.settings = settings
        self._host = httpx.URL(url).netloc.decode() or url
        # Redirects (an HA standby pointing at the active node) are followed only to this Vault or
        # another preset Vault: the token goes with the request, so never to an address nobody chose.
        self._redirect_ok = {_origin(base)} | {_origin(p.url) for p in settings.preset_connections}
        self._list_via_get = False  # a proxy refused the LIST verb: send GET ?list=true instead
        self._kv_versions: dict[str, asyncio.Future] = {}  # mount -> "1" or "2"

    async def __aenter__(self) -> "VaultClient":
        return self

    async def __aexit__(self, *exc) -> None:
        await self._http.aclose()

    async def request(self, method: str, path: str, json: Any = None,
                      params: dict | None = None, headers: dict | None = None, token: str | None = None) -> dict:
        """`token`: send this token instead of the connection's ("" sends none)."""
        path = path.lstrip("/")
        hdrs = dict(headers or {})
        if token is not None:
            hdrs["X-Vault-Token"] = token
        if method == "LIST" and self._list_via_get:
            method, params = "GET", {**(params or {}), "list": "true"}
        r = await self._send(method, path, json, params, hdrs)
        if method == "LIST" and _list_refused(r):
            # Some proxies and WAFs don't pass the LIST verb: Vault takes GET ?list=true as the same
            r2 = await self._send("GET", path, json, {**(params or {}), "list": "true"}, hdrs)
            if not _list_refused(r2):
                if r2.status_code < 400:
                    log.info("%s refused LIST %s (%d): using GET ?list=true from now on", self._host, path, r.status_code)
                    self._list_via_get = True
                r = r2
        if 300 <= r.status_code < 400:
            raise VaultError(r.status_code, f"Vault answered {r.status_code} without following up", path)
        if r.status_code >= 400:
            try:
                body = r.json()
            except ValueError:
                body = {}
            errors = body.get("errors") or []
            msg = "; ".join(str(e) for e in errors) or r.reason_phrase
            raise VaultError(r.status_code, msg, path, body)
        return r.json() if r.content else {}

    async def _send(self, method: str, path: str, json: Any, params: dict | None, hdrs: dict) -> httpx.Response:
        """One logical request: retries reads on connection errors and 429/502/503/504, and follows
        307/308 redirects to allowed addresses. Raises VaultError if Vault can't be reached."""
        url: str | httpx.URL = path
        hops = 0
        attempt = 0
        if self._custom and not self._pins:
            await self._pin(self._http.base_url, path)
        while True:
            start = time.perf_counter()
            try:
                r = await self._http.request(method, url, json=json, params=params, headers=hdrs or None)
            except httpx.HTTPError as e:
                ms = (time.perf_counter() - start) * 1000
                # A connection that never opened is safe to retry; a read that timed out already waited long
                if method in IDEMPOTENT and attempt < RETRIES and isinstance(e, (httpx.ConnectError, httpx.RemoteProtocolError)):
                    log.info("%s %s %s: %s after %dms, retrying", self._host, method, path, e.__class__.__name__, ms)
                    await asyncio.sleep(BACKOFF[attempt])
                    attempt += 1
                    continue
                log.warning("%s %s %s: cannot reach Vault after %dms: %s: %s", self._host, method, path,
                            ms, e.__class__.__name__, e)
                metrics.vault_call(self._host, 0, ms / 1000)
                raise VaultError(0, f"cannot reach Vault: {e.__class__.__name__}: {e}", path) from e
            ms = (time.perf_counter() - start) * 1000
            metrics.vault_call(self._host, r.status_code, ms / 1000)
            if r.status_code >= 500:
                log.warning("%s %s %s -> %d in %dms", self._host, method, path, r.status_code, ms)
            elif log.isEnabledFor(logging.DEBUG):
                log.debug("%s %s %s -> %d in %dms", self._host, method, path, r.status_code, ms)
            wait = _retry_after(r)
            if r.status_code in RETRY_STATUS and method in IDEMPOTENT and attempt < RETRIES and wait != -1:
                await asyncio.sleep(wait or BACKOFF[attempt])
                attempt += 1
                continue
            if r.status_code in (307, 308) and r.headers.get("location"):
                target = r.url.join(r.headers["location"])
                if _origin(target) not in self._redirect_ok and not await self._custom_redirect_ok(target, path):
                    raise VaultError(r.status_code, f"Vault redirected to {target.host}: point Lockstep at the "
                                     "active node or the load balancer", path)
                if hops >= MAX_REDIRECTS:
                    raise VaultError(r.status_code, "Vault redirected too many times", path)
                log.info("%s %s %s redirected to %s", self._host, method, path, target.host)
                url, params, hops = target, None, hops + 1  # the Location carries the query string
                continue
            return r

    async def _pin(self, url: httpx.URL, path: str) -> None:
        from .addresses import AddressError, resolve
        try:
            self._pins[url.host.lower()] = await resolve(url.host, url.port or (443 if url.scheme == "https" else 80), self.settings)
        except AddressError as e:
            raise VaultError(0, str(e), path) from e

    async def _custom_redirect_ok(self, target: httpx.URL, path: str) -> bool:
        """A custom connection's redirect: allowed if the target passes the same checks as a
        typed address (patterns, then its resolved addresses)."""
        from .addresses import AddressError, check_origin
        if not self._custom:
            return False
        try:
            check_origin(str(target.copy_with(path="/", query=None, fragment=None)), self.settings)
        except AddressError:
            return False
        await self._pin(target, path)
        return True

    # ------------------------------------------------------------------ auth

    async def lookup_self(self) -> dict:
        return (await self.request("GET", "auth/token/lookup-self"))["data"]

    async def revoke_self(self) -> None:
        await self.request("POST", "auth/token/revoke-self")

    async def login_userpass(self, username: str, password: str, mount: str = "userpass") -> dict:
        res = await self.request("POST", f"auth/{mount.strip('/')}/login/{username}",
                                 json={"password": password})
        return res["auth"]

    async def login_ldap(self, username: str, password: str, mount: str = "ldap") -> dict:
        res = await self.request("POST", f"auth/{mount.strip('/')}/login/{username}",
                                 json={"password": password})
        return res["auth"]

    async def oidc_auth_url(self, mount: str, role: str | None, redirect_uri: str, client_nonce: str) -> str:
        body = {"redirect_uri": redirect_uri, "client_nonce": client_nonce}
        if role:
            body["role"] = role
        res = await self.request("POST", f"auth/{mount.strip('/')}/oidc/auth_url", json=body)
        url = (res.get("data") or {}).get("auth_url")
        if not url:  # Vault answers 200 with an empty URL when the redirect_uri isn't allowed
            raise VaultError(400, "Vault returned no login URL. Is this tool's callback URL in the "
                                  "role's allowed_redirect_uris?", f"auth/{mount}/oidc/auth_url")
        return url

    async def oidc_callback(self, mount: str, state: str, code: str, client_nonce: str) -> dict:
        res = await self.request("GET", f"auth/{mount.strip('/')}/oidc/callback",
                                 params={"state": state, "code": code, "client_nonce": client_nonce})
        return res["auth"]

    async def login_methods(self) -> list[dict]:
        """Auth methods this Vault advertises to unauthenticated users (listing_visibility=unauth)."""
        data = (await self.request("GET", "sys/internal/ui/mounts")).get("data") or {}
        return [{"path": p.rstrip("/"), "type": m.get("type"), "description": m.get("description") or ""}
                for p, m in sorted((data.get("auth") or {}).items())]

    async def login_kubernetes(self, role: str, jwt: str, mount: str = "kubernetes") -> dict:
        res = await self.request("POST", f"auth/{mount.strip('/')}/login", json={"role": role, "jwt": jwt})
        return res["auth"]

    async def login_jwt(self, jwt: str, role: str | None = None, mount: str = "jwt") -> dict:
        """Vault's JWT auth method: exchange a JWT (e.g. an ID token or a CI job's OIDC token)
        for a Vault token. Without a role, Vault uses the mount's default_role."""
        body = {"jwt": jwt} | ({"role": role} if role else {})
        res = await self.request("POST", f"auth/{mount.strip('/')}/login", json=body)
        return res["auth"]

    # ------------------------------------------------------------------ mounts

    async def list_kv2_mounts(self, include_v1: bool = False) -> tuple[list[KvMount], str]:
        """Return the KV v2 mounts (and KV v1, with `include_v1`) plus where the list came from.

        `sys/mounts` needs explicit permission. If that is denied, fall back to
        `sys/internal/ui/mounts`, which the default policy allows; it returns only the
        mounts this token can access.
        """
        try:
            data = (await self.request("GET", "sys/mounts"))["data"]
            source = "sys/mounts"
        except VaultError as e:
            if not e.denied:
                raise
            data = (await self.request("GET", "sys/internal/ui/mounts"))["data"]["secret"]
            source = "sys/internal/ui/mounts"
        mounts = [
            KvMount(path=p.rstrip("/"), description=m.get("description") or "", version=_kv_version(m) or "")
            for p, m in data.items()
            if _kv_version(m) == "2" or (include_v1 and _kv_version(m) == "1")
        ]
        return sorted(mounts, key=lambda m: m.path), source

    async def describe_mount(self, path: str, include_v1: bool = False) -> KvMount | None:
        """Look up a single mount by path (for manual entry). Returns None if it isn't KV v2
        (or KV v1, with `include_v1`)."""
        m = (await self.request("GET", f"sys/internal/ui/mounts/{path.strip('/')}"))["data"]
        version = _kv_version(m)
        if not (version == "2" or (include_v1 and version == "1")):
            return None
        return KvMount(path=(m.get("path") or path).strip("/"), description=m.get("description") or "",
                       version=version)

    async def kv_version(self, mount: str) -> str:
        """"1" or "2", looked up once per mount (sys/internal/ui/mounts, which any token may read
        for a mount it can use). When it can't be told, "2": what Lockstep always assumed."""
        mount = mount.strip("/")
        fut = self._kv_versions.get(mount)
        if fut is None:
            fut = self._kv_versions[mount] = asyncio.ensure_future(self._lookup_kv_version(mount))
        return await asyncio.shield(fut)

    async def _lookup_kv_version(self, mount: str) -> str:
        try:
            m = (await self.request("GET", f"sys/internal/ui/mounts/{mount}")).get("data") or {}
        except VaultError:
            return "2"
        return _kv_version(m) or "2"

    async def _v1(self, mount: str) -> bool:
        return await self.kv_version(mount) == "1"

    async def _writable(self, mount: str, path: str) -> None:
        if await self._v1(mount):
            raise VaultError(400, f"{mount}/ is a KV v1 mount: Lockstep only reads KV v1. Copy into a KV v2 "
                                  f"mount instead.", path)

    # ------------------------------------------------------------------ KV v2

    async def kv_list(self, mount: str, prefix: str = "") -> list[str]:
        where = f"{mount}/{_q(prefix)}" if await self._v1(mount) else f"{mount}/metadata/{_q(prefix)}"
        try:
            res = await self.request("LIST", where)
        except VaultError as e:
            if e.status == 404:  # empty folder or empty mount
                return []
            raise
        return res["data"]["keys"]

    async def kv_tree(self, mount: str, prefix: str = "", max_secrets: int = 5000,
                      concurrency: int = 16) -> TreeResult:
        """List every secret under `prefix`, walking folders in parallel.

        Folders the token can't list go into `denied` and are skipped. Any other
        error is raised.
        """
        prefix = prefix.strip("/")
        prefix = f"{prefix}/" if prefix else ""
        result = TreeResult()
        sem = asyncio.Semaphore(concurrency)

        async def walk(folder: str) -> None:
            if result.truncated:
                return
            try:
                async with sem:
                    keys = await self.kv_list(mount, folder)
            except VaultError as e:
                if e.denied:
                    result.denied.append(folder)
                    return
                raise
            children = []
            for k in keys:
                if k.endswith("/"):
                    children.append(folder + k)
                elif len(result.secrets) >= max_secrets:
                    result.truncated = True
                    return
                else:
                    result.secrets.append(folder + k)
            await asyncio.gather(*(walk(c) for c in children))

        await walk(prefix)
        result.secrets.sort()
        result.denied.sort()
        return result

    async def kv_read(self, mount: str, path: str, version: int | None = None) -> KvSecret:
        """Read the current version (or a specific one). A deleted or destroyed version is
        returned with state "deleted" (Vault answers 404 but still includes the metadata).
        KV v1 keeps one value per path, with no versions or metadata."""
        if await self._v1(mount):
            if version:
                raise VaultError(400, "KV v1 keeps no versions", path)
            try:
                res = await self.request("GET", f"{mount}/{_q(path)}")
            except VaultError as e:
                if e.status == 404:
                    return KvSecret(state="absent")
                raise
            return KvSecret(state="present", data=res.get("data") or {})
        try:
            res = await self.request("GET", f"{mount}/data/{_q(path)}",
                                     params={"version": version} if version else None)
        except VaultError as e:
            meta = ((e.body.get("data") or {}).get("metadata")) if e.status == 404 else None
            if meta:
                return KvSecret(state="deleted", data=None, version=meta.get("version"),
                                updated=meta.get("created_time"))
            if e.status == 404:
                return KvSecret(state="absent")
            raise
        d = res["data"]
        meta = d.get("metadata") or {}
        return KvSecret(state="present", data=d.get("data") or {}, version=meta.get("version"),
                        updated=meta.get("created_time"))

    async def kv_metadata(self, mount: str, path: str) -> dict:
        if await self._v1(mount):
            return {}  # KV v1 has no metadata
        return (await self.request("GET", f"{mount}/metadata/{_q(path)}"))["data"]

    async def kv_metadata_write(self, mount: str, path: str, fields: dict) -> None:
        """Change a secret's metadata settings or custom metadata."""
        await self._writable(mount, path)
        await self.request("POST", f"{mount}/metadata/{_q(path)}", json=fields)

    async def kv_write(self, mount: str, path: str, data: dict, cas: int | None) -> int:
        """Write a new version. `cas` is the version we expect to replace (0 = must not
        exist yet). Vault rejects the write with 400 if the secret changed meanwhile.
        Returns the new version number."""
        await self._writable(mount, path)
        body: dict = {"data": data}
        if cas is not None:
            body["options"] = {"cas": cas}
        res = await self.request("POST", f"{mount}/data/{_q(path)}", json=body)
        return res["data"]["version"]

    async def kv_patch(self, mount: str, path: str, changes: dict, cas: int | None) -> int:
        """Change some keys (JSON merge patch: a null removes a key). Needs the `patch` capability."""
        await self._writable(mount, path)
        body: dict = {"data": changes}
        if cas is not None:
            body["options"] = {"cas": cas}
        res = await self.request("PATCH", f"{mount}/data/{_q(path)}", json=body,
                                 headers={"Content-Type": "application/merge-patch+json"})
        return res["data"]["version"]

    async def kv_delete(self, mount: str, path: str) -> None:
        """Soft-delete the latest version: the data stays in Vault's history and
        `vault kv undelete` restores it. KV v2 has no check-and-set for deletes, so callers
        check the version just before."""
        await self._writable(mount, path)
        await self.request("DELETE", f"{mount}/data/{_q(path)}")

    async def kv_delete_versions(self, mount: str, path: str, versions: list[int]) -> None:
        """Soft-delete specific versions (`vault kv delete -versions=`)."""
        await self._writable(mount, path)
        await self.request("POST", f"{mount}/delete/{_q(path)}", json={"versions": versions})

    async def kv_undelete(self, mount: str, path: str, versions: list[int]) -> None:
        """Restore soft-deleted versions (`vault kv undelete`)."""
        await self._writable(mount, path)
        await self.request("POST", f"{mount}/undelete/{_q(path)}", json={"versions": versions})

    async def kv_destroy_versions(self, mount: str, path: str, versions: list[int]) -> None:
        """Permanently delete the data of specific versions (`vault kv destroy`). Can't be undone."""
        await self._writable(mount, path)
        await self.request("PUT", f"{mount}/destroy/{_q(path)}", json={"versions": versions})

    async def kv_destroy_all(self, mount: str, path: str) -> None:
        """Permanently delete every version and the metadata (`vault kv metadata delete`).
        Can't be undone."""
        await self._writable(mount, path)
        await self.request("DELETE", f"{mount}/metadata/{_q(path)}")

    async def wrap(self, data: dict, ttl_seconds: int) -> dict:
        """Wrap data in a single-use token (sys/wrapping/wrap). Returns Vault's wrap_info."""
        res = await self.request("POST", "sys/wrapping/wrap", json=data, headers={"X-Vault-Wrap-TTL": str(ttl_seconds)})
        return res["wrap_info"]

    async def wrap_lookup(self, token: str) -> dict:
        """Look up a wrapping token without using it up."""
        return (await self.request("POST", "sys/wrapping/lookup", json={"token": token}))["data"]

    async def unwrap(self, token: str) -> dict:
        """Open a wrapping token (single use)."""
        return (await self.request("POST", "sys/wrapping/unwrap", token=token)).get("data") or {}

    async def server_version(self) -> str | None:
        """The Vault version, from sys/seal-status (no token needed). None if it can't be read."""
        try:
            return (await self.request("GET", "sys/seal-status")).get("version")
        except VaultError:
            return None

    async def server_info(self) -> tuple[str, str | None]:
        """(product, version): "Vault", "Vault Enterprise" or "OpenBao", and the version (None if
        sys/seal-status can't be read)."""
        async def get(path: str) -> dict:
            try:
                return await self.request("GET", path)
            except VaultError:
                return {}
        seal = await get("sys/seal-status")
        ui = {} if "commit_date" in seal else await get("sys/internal/ui/mounts")
        return product_of(seal, ui), seal.get("version")

    async def policy_names(self) -> list[str]:
        """ACL policy names (LIST sys/policies/acl)."""
        res = await self.request("LIST", "sys/policies/acl")
        return sorted((res.get("data") or {}).get("keys") or [])

    async def policy_text(self, name: str) -> str:
        res = await self.request("GET", f"sys/policies/acl/{_q(name)}")
        return (res.get("data") or {}).get("policy") or ""

    async def capabilities(self, paths: list[str], token: str | None = None) -> dict[str, list[str]]:
        """This token's (or `token`'s) capabilities on each path (sys/capabilities-self)."""
        if not paths:
            return {}
        res = await self.request("POST", "sys/capabilities-self", json={"paths": paths}, token=token)
        data = res.get("data") or res
        return {p: data.get(p) or [] for p in paths}


def _list_refused(r: httpx.Response) -> bool:
    """Whether a LIST was refused by something in front of Vault: 405, or a 403 without Vault's
    JSON error body (Vault's own "permission denied" has one)."""
    if r.status_code == 405:
        return True
    if r.status_code != 403:
        return False
    try:
        return "errors" not in r.json()
    except ValueError:
        return True


def _retry_after(r: httpx.Response) -> float | None:
    """Seconds to wait from Retry-After: None if absent, -1 if longer than 2 seconds (not worth
    waiting for in a request: give up instead)."""
    try:
        s = float(r.headers.get("retry-after", ""))
    except ValueError:
        return None
    return s if 0 <= s <= 2 else -1


def product_of(seal: dict, ui_mounts: dict) -> str:
    """Vault or OpenBao, from sys/seal-status and sys/internal/ui/mounts (both readable with any
    token). Newer OpenBao releases report `commit_date` in seal-status, and every OpenBao's built-in plugins
    report versions ending in .bao. Vault Enterprise has +ent in its version."""
    mounts = (ui_mounts.get("data") or {}).get("secret") or {}
    if "commit_date" in seal or any(str(m.get("running_plugin_version") or "").endswith(".bao")
                                    for m in mounts.values()):
        return "OpenBao"
    return "Vault Enterprise" if "+ent" in str(seal.get("version") or "") else "Vault"


def _q(path: str) -> str:
    """URL-quote a secret path. Secret names may contain spaces, '#', '?' and so on."""
    return quote(path, safe="/")


def _kv_version(mount: dict) -> str | None:
    """"2" for KV v2, "1" for KV v1 (a kv mount without version 2, or the old "generic"), else None."""
    if mount.get("type") not in ("kv", "generic"):
        return None
    return "2" if str((mount.get("options") or {}).get("version")) == "2" else "1"


def _is_kv2(mount: dict) -> bool:
    return _kv_version(mount) == "2"
