"""Minimal async Vault HTTP client: only the endpoints this tool needs."""

from __future__ import annotations

import asyncio
import ssl
from urllib.parse import quote
from dataclasses import dataclass, field
from typing import Any

import httpx

from .config import Settings


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


class VaultClient:
    def __init__(self, url: str, settings: Settings, token: str | None = None,
                 namespace: str | None = None, timeout: float = 15.0):
        headers = {"X-Vault-Request": "true"}
        if token:
            headers["X-Vault-Token"] = token
        if namespace:
            headers["X-Vault-Namespace"] = namespace
        self._http = httpx.AsyncClient(base_url=url.rstrip("/") + "/v1/", headers=headers,
                                       verify=_ssl_context(settings), timeout=timeout)
        self.settings = settings

    async def __aenter__(self) -> "VaultClient":
        return self

    async def __aexit__(self, *exc) -> None:
        await self._http.aclose()

    async def request(self, method: str, path: str, json: Any = None,
                      params: dict | None = None) -> dict:
        path = path.lstrip("/")
        try:
            r = await self._http.request(method, path, json=json, params=params)
        except httpx.HTTPError as e:
            raise VaultError(0, f"cannot reach Vault: {e.__class__.__name__}: {e}", path) from e
        if r.status_code >= 400:
            try:
                body = r.json()
            except ValueError:
                body = {}
            errors = body.get("errors") or []
            msg = "; ".join(str(e) for e in errors) or r.reason_phrase
            raise VaultError(r.status_code, msg, path, body)
        return r.json() if r.content else {}

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

    async def list_kv2_mounts(self) -> tuple[list[KvMount], str]:
        """Return the KV v2 mounts plus where the list came from.

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
            KvMount(path=p.rstrip("/"), description=m.get("description") or "")
            for p, m in data.items()
            if _is_kv2(m)
        ]
        return sorted(mounts, key=lambda m: m.path), source

    async def describe_mount(self, path: str) -> KvMount | None:
        """Look up a single mount by path (for manual entry). Returns None if it isn't KV v2."""
        m = (await self.request("GET", f"sys/internal/ui/mounts/{path.strip('/')}"))["data"]
        if not _is_kv2(m):
            return None
        return KvMount(path=(m.get("path") or path).strip("/"), description=m.get("description") or "")

    # ------------------------------------------------------------------ KV v2

    async def kv_list(self, mount: str, prefix: str = "") -> list[str]:
        try:
            res = await self.request("LIST", f"{mount}/metadata/{_q(prefix)}")
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
        returned with state "deleted" (Vault answers 404 but still includes the metadata)."""
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
        return (await self.request("GET", f"{mount}/metadata/{_q(path)}"))["data"]

    async def kv_write(self, mount: str, path: str, data: dict, cas: int | None) -> int:
        """Write a new version. `cas` is the version we expect to replace (0 = must not
        exist yet). Vault rejects the write with 400 if the secret changed meanwhile.
        Returns the new version number."""
        body: dict = {"data": data}
        if cas is not None:
            body["options"] = {"cas": cas}
        res = await self.request("POST", f"{mount}/data/{_q(path)}", json=body)
        return res["data"]["version"]

    async def capabilities(self, paths: list[str]) -> dict[str, list[str]]:
        """This token's capabilities on each path (sys/capabilities-self)."""
        if not paths:
            return {}
        res = await self.request("POST", "sys/capabilities-self", json={"paths": paths})
        data = res.get("data") or res
        return {p: data.get(p) or [] for p in paths}


def _q(path: str) -> str:
    """URL-quote a secret path. Secret names may contain spaces, '#', '?' and so on."""
    return quote(path, safe="/")


def _is_kv2(mount: dict) -> bool:
    return mount.get("type") == "kv" and str((mount.get("options") or {}).get("version")) == "2"
