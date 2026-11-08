"""Browser redirect login (Vault's OIDC auth method), the same flow the Vault UI uses.

  1. POST /api/auth/oidc/start   → Vault gives us the IdP login URL (with our callback and a
                                    client nonce). The pending login goes into the encrypted
                                    session cookie; the browser goes to the IdP.
  2. IdP → GET /api/auth/oidc/callback?state&code
                                 → state must match the pending login; Vault exchanges the code
                                    for a token; the connection is added; redirect back to the app.

The session cookie is SameSite=Lax, which is sent on the IdP's top-level redirect back to us.
"""

from __future__ import annotations

import secrets
from typing import Annotated
from urllib.parse import parse_qs, urlencode, urlparse

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel, Field

from ..config import Settings, get_settings
from ..session import PendingOidc, SessionData, load_session, save_session
from ..vault import VaultClient, VaultError
from .connections import (ConnectionCreate, TokenAuth, add_connection, connection_from_token,
                          resolve_target, vault_http_error)

router = APIRouter(prefix="/api/auth", tags=["auth"])

Sess = Annotated[SessionData, Depends(load_session)]
Conf = Annotated[Settings, Depends(get_settings)]


class Target(BaseModel):
    preset_id: int | None = None
    url: str | None = None
    namespace: str | None = None
    name: str | None = None

    def as_create(self) -> ConnectionCreate:
        # resolve_target only looks at the target fields; the auth part is a placeholder.
        return ConnectionCreate(preset_id=self.preset_id, url=self.url, namespace=self.namespace,
                                name=self.name, auth=TokenAuth(method="token", token="-"))


class OidcStart(Target):
    mount: str = Field(default="oidc", min_length=1)
    role: str | None = None
    side: str | None = Field(default=None, pattern="^(left|right)$")


def callback_url(settings: Settings) -> str:
    return settings.public_url.rstrip("/") + "/api/auth/oidc/callback"


@router.post("/methods")
async def login_methods(body: Target, settings: Conf):
    """Auth methods the chosen Vault shows on its login screen (unauthenticated)."""
    url, namespace, _, _ = resolve_target(body.as_create(), settings)
    async with VaultClient(url, settings, namespace=namespace) as v:
        try:
            return {"methods": await v.login_methods()}
        except VaultError as e:
            raise vault_http_error(e) from e


@router.post("/oidc/start")
async def oidc_start(body: OidcStart, session: Sess, settings: Conf):
    url, namespace, name, preset_id = resolve_target(body.as_create(), settings)
    nonce = secrets.token_urlsafe(24)
    async with VaultClient(url, settings, namespace=namespace) as v:
        try:
            auth_url = await v.oidc_auth_url(body.mount, body.role, callback_url(settings), nonce)
        except VaultError as e:
            raise vault_http_error(e) from e
    state = (parse_qs(urlparse(auth_url).query).get("state") or [""])[0]
    if not state:
        raise HTTPException(502, detail={"message": "Vault's login URL has no state parameter"})
    session.pending_oidc = PendingOidc(state=state, nonce=nonce, url=url, namespace=namespace, name=name,
                                       preset_id=preset_id, mount=body.mount.strip("/"), role=body.role,
                                       side=body.side)
    response = JSONResponse({"auth_url": auth_url})
    save_session(response, session, settings)
    return response


def _back(settings: Settings, **params) -> str:
    return settings.public_url.rstrip("/") + "/?" + urlencode({k: v for k, v in params.items() if v})


@router.get("/oidc/callback", include_in_schema=False)
async def oidc_callback(session: Sess, settings: Conf, state: str = Query(""), code: str = Query(""),
                        error: str | None = None, error_description: str | None = None):
    pending = session.pending_oidc
    session.pending_oidc = None  # single use, whatever happens next

    def fail(msg: str) -> RedirectResponse:
        r = RedirectResponse(_back(settings, oidc_error=msg), status_code=303)
        save_session(r, session, settings)
        return r

    if error:
        return fail(f"The identity provider refused the login: {error_description or error}")
    if pending is None:
        return fail("No login in progress (it may have been started in another browser). Try again.")
    if pending.expired():
        return fail("The login took too long. Try again.")
    if not state or not secrets.compare_digest(state, pending.state):
        return fail("Login state mismatch, so the response was rejected. Try again.")
    if not code:
        return fail("The identity provider returned no authorisation code.")

    async with VaultClient(pending.url, settings, namespace=pending.namespace) as v:
        try:
            auth = await v.oidc_callback(pending.mount, state, code, pending.nonce)
        except VaultError as e:
            return fail(f"Vault rejected the login: {e.message}")
    token = auth["client_token"]
    async with VaultClient(pending.url, settings, token=token, namespace=pending.namespace) as v:
        try:
            info = await v.lookup_self()
        except VaultError as e:
            return fail(f"Vault issued a token that doesn't work: {e.message}")

    conn = connection_from_token(token=token, info=info, url=pending.url, namespace=pending.namespace,
                                 name=pending.name, preset_id=pending.preset_id, method="oidc", minted=True)
    try:
        add_connection(session, conn)
    except HTTPException as e:
        return fail(e.detail["message"] if isinstance(e.detail, dict) else str(e.detail))
    r = RedirectResponse(_back(settings, oidc="ok", conn=conn.id, side=pending.side), status_code=303)
    save_session(r, session, settings)
    return r
