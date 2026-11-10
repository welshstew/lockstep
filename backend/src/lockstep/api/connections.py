"""Connections: logging in to a Vault, finding KV v2 mounts, listing secret trees."""

from __future__ import annotations

import asyncio
import base64
import json
import re
import time
from typing import Annotated, Literal
from pathlib import Path
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, Field

from ..config import Settings, get_settings
from ..session import Connection, SessionData, load_session, save_session
from ..vault import VaultClient, VaultError

router = APIRouter(prefix="/api/connections", tags=["connections"])

MAX_CONNECTIONS = 6

Sess = Annotated[SessionData, Depends(load_session)]
Conf = Annotated[Settings, Depends(get_settings)]


# --------------------------------------------------------------------------- models


class TokenAuth(BaseModel):
    method: Literal["token"]
    token: str = Field(min_length=1)


class PasswordAuth(BaseModel):
    method: Literal["userpass", "ldap"]
    username: str = Field(min_length=1)
    password: str = Field(min_length=1)
    mount: str | None = None


class KubernetesAuth(BaseModel):
    method: Literal["kubernetes"]
    role: str = Field(min_length=1, max_length=128)
    mount: str | None = None


JWT_MAX = 64 * 1024


class JwtAuth(BaseModel):
    method: Literal["jwt"]
    jwt: str = Field(min_length=1, max_length=JWT_MAX)
    role: str | None = Field(default=None, max_length=128)  # default: the mount's default_role
    mount: str | None = None


class ConnectionCreate(BaseModel):
    preset_id: int | None = None
    url: str | None = None
    namespace: str | None = None
    name: str | None = None
    auth: TokenAuth | PasswordAuth | KubernetesAuth | JwtAuth = Field(discriminator="method")


class ConnectionOut(BaseModel):
    id: str
    name: str
    url: str | None  # hidden for presets, which may use internal addresses
    namespace: str | None
    preset_id: int | None
    auth_method: str
    display_name: str
    policies: list[str]
    expires_at: float | None
    status: Literal["ok", "expired", "unreachable", "unknown"] = "unknown"


class MountOut(BaseModel):
    path: str
    description: str


class MountsOut(BaseModel):
    mounts: list[MountOut]
    source: str
    complete: bool  # False when the list came from the fallback and may leave mounts out


class TreeOut(BaseModel):
    mount: str
    prefix: str
    secrets: list[str]
    denied: list[str]
    truncated: bool


# --------------------------------------------------------------------------- helpers


def vault_http_error(e: VaultError, *, login: bool = False) -> HTTPException:
    if e.status == 0:
        return HTTPException(502, detail={"message": e.message, "vault_status": 0})
    if login and e.status in (400, 401, 403):
        return HTTPException(401, detail={"message": "Vault rejected the credentials: " + e.message,
                                          "vault_status": e.status})
    status = e.status if e.status in (400, 403, 404) else 502
    return HTTPException(status, detail={"message": e.message, "vault_status": e.status})


def client_for(conn: Connection, settings: Settings) -> VaultClient:
    return VaultClient(conn.url, settings, token=conn.token, namespace=conn.namespace)


def get_connection(session: SessionData, conn_id: str) -> Connection:
    conn = session.get(conn_id)
    if conn is None:
        raise HTTPException(404, detail={"message": "Unknown or expired connection", "reconnect": True})
    return conn


def to_out(c: Connection, status: str = "unknown") -> ConnectionOut:
    return ConnectionOut(
        id=c.id, name=c.name, url=None if c.preset_id is not None else c.url,
        namespace=c.namespace, preset_id=c.preset_id, auth_method=c.auth_method,
        display_name=c.display_name, policies=c.policies, expires_at=c.expires_at, status=status)


def resolve_target(body: ConnectionCreate, settings: Settings) -> tuple[str, str | None, str, int | None]:
    """Return (url, namespace, name, preset_id) for a create request, enforcing policy."""
    if body.preset_id is not None:
        if not 0 <= body.preset_id < len(settings.preset_connections):
            raise HTTPException(400, detail={"message": "Unknown preset connection"})
        p = settings.preset_connections[body.preset_id]
        return p.url, p.namespace or body.namespace, body.name or p.name, body.preset_id
    if not body.url:
        raise HTTPException(400, detail={"message": "Either preset_id or url is required"})
    if not settings.allow_custom_connections:
        raise HTTPException(403, detail={"message": "Custom Vault URLs are disabled; pick a preset"})
    u = urlparse(body.url)
    if u.scheme not in ("http", "https") or not u.hostname:
        raise HTTPException(400, detail={"message": "Vault URL must be http(s)://host[:port]"})
    if settings.custom_url_patterns and not any(re.fullmatch(p, body.url) for p in settings.custom_url_patterns):
        raise HTTPException(403, detail={"message": "This Vault URL is not on the allowed list"})
    return body.url.rstrip("/"), body.namespace, body.name or u.netloc, None


def connection_from_token(*, token: str, info: dict, url: str, namespace: str | None, name: str,
                          preset_id: int | None, method: str, minted: bool) -> Connection:
    ttl = info.get("ttl") or 0
    return Connection(
        name=name, url=url, namespace=namespace, preset_id=preset_id, token=token,
        auth_method=method, minted=minted,
        display_name=info.get("display_name") or "",
        policies=sorted(set(info.get("policies") or []) | set(info.get("identity_policies") or [])),
        expires_at=time.time() + ttl if ttl else None,
    )


K8S_TOKEN_MAX = 64 * 1024


def k8s_available(settings: Settings) -> bool:
    return settings.k8s_auth_enabled and Path(settings.k8s_token_path).is_file()


def k8s_service_account(settings: Settings) -> str | None:
    """'namespace/name' of the pod's service account, from the token's (unverified) claims.
    Display only; Vault does the real validation through the TokenReview API."""
    try:
        payload = Path(settings.k8s_token_path).read_text().strip().split(".")[1]
        sub = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))["sub"]
        _, _, ns, name = sub.split(":", 3)
        return f"{ns}/{name}"
    except Exception:  # noqa: BLE001
        return None


def read_k8s_token(auth: KubernetesAuth, settings: Settings) -> str:
    if not settings.k8s_auth_enabled:
        raise HTTPException(403, detail={"message": "Kubernetes auth is disabled on this server"})
    if settings.k8s_auth_roles and auth.role not in settings.k8s_auth_roles:
        raise HTTPException(403, detail={"message": f"Role '{auth.role}' isn't allowed here. "
                                                    f"Allowed: {', '.join(settings.k8s_auth_roles)}"})
    p = Path(settings.k8s_token_path)
    if not p.is_file():
        raise HTTPException(400, detail={"message": "No service account token found. Is this running in Kubernetes "
                                                    "with automountServiceAccountToken enabled?"})
    token = p.read_text()[:K8S_TOKEN_MAX].strip()  # read fresh each time: projected tokens rotate
    if not token:
        raise HTTPException(400, detail={"message": "The service account token file is empty"})
    return token


def add_connection(session: SessionData, conn: Connection) -> None:
    if len(session.connections) >= MAX_CONNECTIONS:
        raise HTTPException(400, detail={"message": f"At most {MAX_CONNECTIONS} connections per session"})
    session.connections.append(conn)


# --------------------------------------------------------------------------- routes


@router.get("", response_model=list[ConnectionOut])
async def list_connections(session: Sess, settings: Conf):
    async def probe(c: Connection) -> ConnectionOut:
        try:
            async with client_for(c, settings) as v:
                await v.lookup_self()
            return to_out(c, "ok")
        except VaultError as e:
            return to_out(c, "unreachable" if e.status == 0 else "expired")

    return await asyncio.gather(*(probe(c) for c in session.connections))


@router.post("", response_model=ConnectionOut, status_code=201)
async def create_connection(body: ConnectionCreate, response: Response, session: Sess, settings: Conf):
    url, namespace, name, preset_id = resolve_target(body, settings)
    auth = body.auth
    async with VaultClient(url, settings, namespace=namespace) as anon:
        try:
            if isinstance(auth, TokenAuth):
                token, minted = auth.token.strip(), False
            elif isinstance(auth, KubernetesAuth):
                jwt = read_k8s_token(auth, settings)
                res = await anon.login_kubernetes(auth.role, jwt, auth.mount or settings.k8s_auth_mount)
                token, minted = res["client_token"], True
            elif isinstance(auth, JwtAuth):
                res = await anon.login_jwt(auth.jwt.strip(), auth.role or None, auth.mount or "jwt")
                token, minted = res["client_token"], True
            else:
                login = anon.login_userpass if auth.method == "userpass" else anon.login_ldap
                res = await login(auth.username, auth.password, auth.mount or auth.method)
                token, minted = res["client_token"], True
        except VaultError as e:
            raise vault_http_error(e, login=True) from e

    async with VaultClient(url, settings, token=token, namespace=namespace) as v:
        try:
            info = await v.lookup_self()
        except VaultError as e:
            raise vault_http_error(e, login=True) from e

    conn = connection_from_token(token=token, info=info, url=url, namespace=namespace, name=name,
                                 preset_id=preset_id, method=auth.method, minted=minted)
    add_connection(session, conn)
    save_session(response, session, settings)
    return to_out(conn, "ok")


@router.delete("/{conn_id}", status_code=204)
async def delete_connection(conn_id: str, response: Response, session: Sess, settings: Conf):
    conn = get_connection(session, conn_id)
    if conn.minted:  # revoke tokens we created; leave pasted tokens alone
        try:
            async with client_for(conn, settings) as v:
                await v.revoke_self()
        except VaultError:
            pass
    session.connections = [c for c in session.connections if c.id != conn_id]
    save_session(response, session, settings)


@router.get("/{conn_id}/mounts", response_model=MountsOut)
async def list_mounts(conn_id: str, session: Sess, settings: Conf):
    conn = get_connection(session, conn_id)
    async with client_for(conn, settings) as v:
        try:
            mounts, source = await v.list_kv2_mounts()
        except VaultError as e:
            raise vault_http_error(e) from e
    return MountsOut(mounts=[MountOut(path=m.path, description=m.description) for m in mounts],
                     source=source, complete=source == "sys/mounts")


@router.get("/{conn_id}/mounts/{path:path}", response_model=MountOut)
async def describe_mount(conn_id: str, path: str, session: Sess, settings: Conf):
    """For a manually typed mount path: check it exists, is KV v2 and is accessible."""
    conn = get_connection(session, conn_id)
    async with client_for(conn, settings) as v:
        try:
            m = await v.describe_mount(path)
        except VaultError as e:
            if e.status in (400, 403, 404):
                raise HTTPException(404, detail={"message": f"No accessible mount at '{path}'",
                                                 "vault_status": e.status}) from e
            raise vault_http_error(e) from e
    if m is None:
        raise HTTPException(400, detail={"message": f"'{path}' is not a KV v2 mount"})
    return MountOut(path=m.path, description=m.description)


@router.get("/{conn_id}/tree", response_model=TreeOut)
async def secret_tree(conn_id: str, session: Sess, settings: Conf,
                      mount: str = Query(min_length=1), prefix: str = ""):
    conn = get_connection(session, conn_id)
    mount = mount.strip("/")
    async with client_for(conn, settings) as v:
        try:
            tree = await v.kv_tree(mount, prefix, max_secrets=settings.max_tree_secrets)
        except VaultError as e:
            raise vault_http_error(e) from e
    return TreeOut(mount=mount, prefix=prefix.strip("/"), secrets=tree.secrets, denied=tree.denied,
                   truncated=tree.truncated)
