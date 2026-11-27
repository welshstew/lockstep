"""Connections: logging in to a Vault, finding KV v2 mounts, listing secret trees."""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import re
import secrets
import time
from typing import Annotated, Literal
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from ..config import Settings, get_settings
from ..session import Connection, PendingMfa, SessionData, load_session, save_session
from ..addresses import AddressError, check_origin
from .. import metrics, writepolicy
from ..ratelimit import retry_after, signin_throttle
from ..vault import VaultClient, VaultError

router = APIRouter(prefix="/api/connections", tags=["connections"])
log = logging.getLogger("lockstep.auth")

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
    renewable: bool = False
    status: Literal["ok", "expired", "unreachable", "unknown"] = "unknown"
    parent: str | None = None  # opened in a child namespace of this connection
    writes: Literal["all", "some", "none"] = "all"  # the preset's write policy (some: only certain paths)
    destroy: bool = True  # destroying secrets is allowed here
    export: Literal["any", "encrypted", "off"] = "encrypted"  # which exports are allowed from here
    # How an encrypted export from here may be protected: key, passphrase, age, teams (age to the configured teams only)
    export_protection: list[str] = ["key", "passphrase", "age", "teams"]


class MountOut(BaseModel):
    path: str
    description: str
    version: str = "2"  # KV version: "1" mounts are listed only with ?kv1=true, and only read


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


def _throttle(settings: Settings):
    return signin_throttle(settings.signin_max_failures, settings.signin_window_seconds)


def signin_keys(request: Request, url: str | None = None, mount: str | None = None,
                username: str | None = None) -> list[str]:
    """Throttle keys: the client's address, and the user on that Vault (case-insensitive)."""
    keys = [f"client {request.client.host if request.client else 'unknown'}"]
    if username and url:
        keys.append(f"user {username.strip().lower()} at {url} ({(mount or '').strip('/')})")
    return keys


def check_signin_throttle(settings: Settings, keys: list[str]) -> None:
    """429 if too many sign-ins failed recently for any of the keys."""
    wait = _throttle(settings).wait(*keys)
    if wait:
        secs = retry_after(wait)
        metrics.rate_limited("signin")
        log.warning("sign-in refused for %ds: %d failed sign-ins within %ds (%s)", secs,
                    settings.signin_max_failures, settings.signin_window_seconds, "; ".join(keys))
        raise HTTPException(429, headers={"Retry-After": str(secs)}, detail={
            "message": f"Too many failed sign-ins. Try again in {secs} second{'s' if secs != 1 else ''}."})


def client_for(conn: Connection, settings: Settings) -> VaultClient:
    return VaultClient(conn.url, settings, token=conn.token, namespace=conn.namespace,
                       custom=conn.preset_id is None and conn.custom)


def get_connection(session: SessionData, conn_id: str) -> Connection:
    conn = session.get(conn_id)
    if conn is None:
        raise HTTPException(404, detail={"message": "Unknown or expired connection", "reconnect": True})
    return conn


def to_out(c: Connection, status: str = "unknown") -> ConnectionOut:
    return ConnectionOut(
        id=c.id, name=c.name, url=None if c.preset_id is not None else c.url,
        namespace=c.namespace, preset_id=c.preset_id, auth_method=c.auth_method,
        display_name=c.display_name, policies=c.policies, expires_at=c.expires_at, renewable=c.renewable,
        status=status, parent=c.parent, **dict(zip(("writes", "destroy"), writepolicy.summary(get_settings(), c))),
        export=writepolicy.export_mode(get_settings(), c)[0],
        export_protection=writepolicy.export_protection(get_settings(), c))


def resolve_target(body: ConnectionCreate, settings: Settings) -> tuple[str, str | None, str, int | None]:
    """Return (url, namespace, name, preset_id) for a create request, enforcing policy."""
    if body.preset_id is not None:
        if not 0 <= body.preset_id < len(settings.preset_connections):
            raise HTTPException(400, detail={"message": "Unknown preset connection"})
        p = settings.preset_connections[body.preset_id]
        return p.url, p.namespace or body.namespace, body.name or p.name, body.preset_id
    if not body.url:
        raise HTTPException(400, detail={"message": "Either preset_id or url is required"})
    try:
        origin = check_origin(body.url, settings)
    except AddressError as e:
        status = 403 if not settings.allow_custom_connections or "allowed list" in str(e) else 400
        raise HTTPException(status, detail={"message": str(e)}) from e
    return origin, body.namespace, body.name or origin.split("://", 1)[1], None


def connection_from_token(*, token: str, info: dict, url: str, namespace: str | None, name: str,
                          preset_id: int | None, method: str, minted: bool, custom: bool = True) -> Connection:
    ttl = info.get("ttl") or 0
    return Connection(
        name=name, url=url, namespace=namespace, preset_id=preset_id, token=token,
        auth_method=method, minted=minted, custom=custom,
        display_name=info.get("display_name") or "",
        entity_id=info.get("entity_id") or "", accessor=info.get("accessor") or "",
        policies=sorted(set(info.get("policies") or []) | set(info.get("identity_policies") or [])),
        expires_at=time.time() + ttl if ttl else None,
        renewable=bool(ttl and info.get("renewable")),
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


def mfa_constraints(auth: dict) -> list[dict] | None:
    """The second factors a login asks for (Vault login MFA), or None if it doesn't."""
    req = auth.get("mfa_requirement")
    if not req or auth.get("client_token"):
        return None
    out = []
    for name, c in (req.get("mfa_constraints") or {}).items():
        out.append({"name": name, "methods": [
            {"id": m.get("id"), "type": m.get("type"), "uses_passcode": bool(m.get("uses_passcode")),
             "name": m.get("name") or m.get("type")} for m in (c or {}).get("any") or []]})
    return out


def mfa_response(session: SessionData, settings: Settings, pending: PendingMfa) -> JSONResponse:
    """Keep the half-done login in the session and tell the browser which factors to ask for."""
    session.pending_mfa = pending
    r = JSONResponse({"mfa_required": True, "constraints": pending.constraints}, status_code=202)
    save_session(r, session, settings)
    return r


@router.post("", response_model=ConnectionOut, status_code=201,
             responses={202: {"description": "Vault wants a second factor: answer with POST /api/connections/mfa"}})
async def create_connection(body: ConnectionCreate, request: Request, response: Response, session: Sess, settings: Conf):
    url, namespace, name, preset_id = resolve_target(body, settings)
    auth = body.auth
    username = getattr(auth, "username", None)
    keys = signin_keys(request, url, getattr(auth, "mount", None) or auth.method, username)
    check_signin_throttle(settings, keys)
    try:
        out = await _sign_in(body, url, namespace, name, preset_id, response, session, settings)
    except HTTPException as e:
        if e.status_code == 401:  # Vault rejected the credentials
            _throttle(settings).failed(*keys)
            metrics.signin(auth.method, False)
        raise
    if username and isinstance(out, ConnectionOut):
        _throttle(settings).succeeded(keys[-1])
    return out


async def _sign_in(body: ConnectionCreate, url: str, namespace: str | None, name: str, preset_id: int | None,
                   response: Response, session: SessionData, settings: Settings):
    auth = body.auth
    async with VaultClient(url, settings, namespace=namespace, custom=preset_id is None) as anon:
        try:
            if isinstance(auth, TokenAuth):
                token, minted, res = auth.token.strip(), False, {}
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
            who = f" as {auth.username}" if hasattr(auth, "username") else ""
            log.info("sign-in to %s%s (%s) failed: Vault said %d: %s", name, who, auth.method, e.status, e.message)
            raise vault_http_error(e, login=True) from e
    constraints = mfa_constraints(res)
    if constraints is not None:
        return mfa_response(session, settings, PendingMfa(
            request_id=res["mfa_requirement"]["mfa_request_id"], constraints=constraints, url=url, namespace=namespace,
            name=name, preset_id=preset_id, method=auth.method))
    return await finish_login(token, minted, url, namespace, name, preset_id, auth.method, response, session, settings)


async def finish_login(token: str, minted: bool, url: str, namespace: str | None, name: str, preset_id: int | None,
                       method: str, response: Response, session: SessionData, settings: Settings) -> ConnectionOut:
    async with VaultClient(url, settings, token=token, namespace=namespace, custom=preset_id is None) as v:
        try:
            info = await v.lookup_self()
        except VaultError as e:
            raise vault_http_error(e, login=True) from e

    conn = connection_from_token(token=token, info=info, url=url, namespace=namespace, name=name,
                                 preset_id=preset_id, method=method, minted=minted)
    add_connection(session, conn)
    save_session(response, session, settings)
    metrics.signin(method, True)
    log.info("signed in to %s as %s (%s), connection %s, policies %s", name, conn.display_name, method, conn.id,
             ",".join(conn.policies) or "none")
    return to_out(conn, "ok")


class MfaAnswer(BaseModel):
    # method id -> passcode ("" for push methods such as Duo, Okta or PingID: approve on your device)
    payload: dict[str, str] = Field(max_length=10)


@router.get("/mfa")
def pending_mfa(session: Sess):
    p = session.pending_mfa
    if p is None or p.expired():
        raise HTTPException(404, detail={"message": "No sign-in is waiting for a second factor"})
    return {"constraints": p.constraints, "name": p.name, "side": p.side}


@router.post("/mfa", response_model=ConnectionOut, status_code=201)
async def answer_mfa(body: MfaAnswer, request: Request, response: Response, session: Sess, settings: Conf):
    """Send the second factor to Vault (sys/mfa/validate) and finish the sign-in."""
    keys = signin_keys(request)
    check_signin_throttle(settings, keys)
    p = session.pending_mfa
    if p is None or p.expired():
        session.pending_mfa = None
        save_session(response, session, settings)
        raise HTTPException(410, detail={"message": "The sign-in waited too long for the second factor. Sign in again."})
    known = {m["id"] for c in p.constraints for m in c["methods"]}
    if not body.payload or not set(body.payload) <= known:
        raise HTTPException(400, detail={"message": "Answer the methods this sign-in asked for"})
    async with VaultClient(p.url, settings, namespace=p.namespace, custom=p.preset_id is None) as anon:
        try:
            res = await anon.request("POST", "sys/mfa/validate", token="", json={
                "mfa_request_id": p.request_id,
                "mfa_payload": {mid: ([code.strip()] if code.strip() else []) for mid, code in body.payload.items()}})
        except VaultError as e:
            # A wrong passcode can be tried again until the request expires, or the throttle stops it
            _throttle(settings).failed(*keys)
            metrics.signin(p.method, False)
            raise HTTPException(401, detail={"message": f"Vault didn't accept the second factor: {e.message}"}) from e
    session.pending_mfa = None
    return await finish_login(res["auth"]["client_token"], True, p.url, p.namespace, p.name, p.preset_id, p.method,
                              response, session, settings)


@router.delete("/{conn_id}", status_code=204)
async def delete_connection(conn_id: str, response: Response, session: Sess, settings: Conf):
    conn = get_connection(session, conn_id)
    if conn.minted:  # revoke tokens we created; leave pasted tokens alone
        try:
            async with client_for(conn, settings) as v:
                await v.revoke_self()
        except VaultError as e:
            log.info("signing out of %s: couldn't revoke the token (Vault said %d: %s)", conn.name, e.status, e.message)
    # Connections opened in its namespaces use the same token: they go with it
    session.connections = [c for c in session.connections if c.id != conn_id and c.parent != conn_id]
    log.info("signed out of %s (%s), connection %s", conn.name, conn.display_name, conn_id)
    save_session(response, session, settings)


class NamespaceOut(BaseModel):
    name: str  # the child's own name, e.g. team-a
    path: str  # its full path, e.g. eng/team-a


class NamespacesOut(BaseModel):
    supported: bool  # False: this Vault has no namespaces (Vault Community)
    namespace: str | None  # the connection's own namespace
    namespaces: list[NamespaceOut] = []
    error: str | None = None


NAMESPACE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


def _join_ns(parent: str | None, child: str) -> str:
    return "/".join(x for x in ((parent or "").strip("/"), child.strip("/")) if x)


@router.get("/{conn_id}/namespaces", response_model=NamespacesOut)
async def list_namespaces(conn_id: str, session: Sess, settings: Conf):
    """The child namespaces of the connection's namespace (LIST sys/namespaces): Vault
    Enterprise and OpenBao 2.3+."""
    conn = get_connection(session, conn_id)
    async with client_for(conn, settings) as v:
        try:
            res = await v.request("LIST", "sys/namespaces")
        except VaultError as e:
            text = e.message.lower()
            if "enterprise" in text or "unsupported" in text or e.status == 405:
                return NamespacesOut(supported=False, namespace=conn.namespace)
            if e.status == 404:  # no child namespaces
                return NamespacesOut(supported=True, namespace=conn.namespace)
            return NamespacesOut(supported=True, namespace=conn.namespace,
                                 error="can't list namespaces (needs list on sys/namespaces)" if e.denied else e.message)
    keys = (res.get("data") or {}).get("keys") or []
    return NamespacesOut(supported=True, namespace=conn.namespace, namespaces=[
        NamespaceOut(name=k.strip("/"), path=_join_ns(conn.namespace, k)) for k in sorted(keys)])


class NamespaceOpen(BaseModel):
    namespace: str = Field(min_length=1, max_length=128)  # a child of the connection's namespace


@router.post("/{conn_id}/namespaces", response_model=ConnectionOut, status_code=201)
async def open_namespace(conn_id: str, body: NamespaceOpen, response: Response, session: Sess, settings: Conf):
    """A connection to a child namespace with the same token, so it can be a side like any other."""
    conn = get_connection(session, conn_id)
    child = body.namespace.strip("/")
    if not all(NAMESPACE_NAME.match(p) for p in child.split("/")):
        raise HTTPException(400, detail={"message": "A namespace name is letters, digits, '.', '_' and '-'"})
    root = session.get(conn.parent) if conn.parent else conn
    root = root or conn
    full = _join_ns(conn.namespace, child)
    for c in session.connections:  # already open
        if (c.parent == root.id or c.id == root.id) and (c.namespace or "") == full:
            return to_out(c, "ok")
    async with VaultClient(conn.url, settings, token=conn.token, namespace=full,
                           custom=conn.preset_id is None and conn.custom) as v:
        try:
            info = await v.lookup_self()
        except VaultError as e:
            raise HTTPException(400 if e.status in (400, 403, 404) else 502, detail={
                "message": f"Can't use namespace {full}: {e.message}", "vault_status": e.status}) from e
    derived = conn.model_copy(update={"id": secrets.token_hex(4), "namespace": full, "minted": False,
                                      "parent": root.id, "name": f"{root.name} · {full}",
                                      "display_name": info.get("display_name") or conn.display_name})
    add_connection(session, derived)
    save_session(response, session, settings)
    log.info("opened namespace %s on %s for connection %s, as connection %s", full, conn.name, conn.id, derived.id)
    return to_out(derived, "ok")


class RenewOut(ConnectionOut):
    capped: bool  # Vault gave less time than asked for: the token is near its max TTL


@router.post("/{conn_id}/renew", response_model=RenewOut)
async def renew_connection(conn_id: str, response: Response, session: Sess, settings: Conf):
    """Extend the connection's token (auth/token/renew-self) by its original TTL, up to its max TTL."""
    conn = get_connection(session, conn_id)
    async with client_for(conn, settings) as v:
        try:
            before = await v.lookup_self()
            if not before.get("renewable") or not before.get("ttl"):
                raise HTTPException(400, detail={"message": "This token can't be renewed"
                                                 + ("" if before.get("ttl") else ": it doesn't expire")})
            asked = int(before.get("creation_ttl") or before.get("ttl") or 0)
            res = await v.request("POST", "auth/token/renew-self", json={"increment": f"{asked}s"} if asked else {})
            info = await v.lookup_self()
        except VaultError as e:
            raise vault_http_error(e) from e
    ttl = int(info.get("ttl") or 0)
    conn.expires_at = time.time() + ttl if ttl else None
    conn.renewable = bool(ttl and info.get("renewable"))
    save_session(response, session, settings)
    capped = any("max_ttl" in w for w in res.get("warnings") or [])
    return RenewOut(**to_out(conn, "ok").model_dump(), capped=capped)


@router.get("/{conn_id}/mounts", response_model=MountsOut)
async def list_mounts(conn_id: str, session: Sess, settings: Conf, kv1: bool = False):
    """KV v2 mounts; with kv1=true, KV v1 mounts too (for comparing: Lockstep never writes them)."""
    conn = get_connection(session, conn_id)
    async with client_for(conn, settings) as v:
        try:
            mounts, source = await v.list_kv2_mounts(include_v1=kv1)
        except VaultError as e:
            raise vault_http_error(e) from e
    return MountsOut(mounts=[MountOut(path=m.path, description=m.description, version=m.version) for m in mounts],
                     source=source, complete=source == "sys/mounts")


@router.get("/{conn_id}/mounts/{path:path}", response_model=MountOut)
async def describe_mount(conn_id: str, path: str, session: Sess, settings: Conf, kv1: bool = False):
    """For a manually typed mount path: check it exists, is KV v2 (or v1, with kv1=true) and is accessible."""
    conn = get_connection(session, conn_id)
    async with client_for(conn, settings) as v:
        try:
            m = await v.describe_mount(path, include_v1=kv1)
        except VaultError as e:
            if e.status in (400, 403, 404):
                raise HTTPException(404, detail={"message": f"No accessible mount at '{path}'",
                                                 "vault_status": e.status}) from e
            raise vault_http_error(e) from e
    if m is None:
        raise HTTPException(400, detail={"message": f"'{path}' is not a KV {'' if kv1 else 'v2 '}mount"})
    return MountOut(path=m.path, description=m.description, version=m.version)


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
