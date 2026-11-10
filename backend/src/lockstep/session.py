"""Stateless sessions: Vault tokens live in an encrypted, authenticated httpOnly cookie.

Because no server-side state is kept, any replica can serve any request (Kubernetes).
The cookie is encrypted with Fernet (AES-128-CBC + HMAC-SHA256) using a key derived
from LOCKSTEP_SESSION_KEY, so the browser can neither read nor change the tokens.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import time

from cryptography.fernet import Fernet, InvalidToken
from fastapi import Depends, Request, Response
from pydantic import BaseModel, Field

from .config import Settings, get_settings

COOKIE_NAME = "lockstep_session"
MAX_COOKIE_BYTES = 4000  # browsers cap a cookie at roughly 4 KB


class Connection(BaseModel):
    id: str = Field(default_factory=lambda: secrets.token_hex(4))
    name: str
    url: str
    namespace: str | None = None
    preset_id: int | None = None
    token: str
    auth_method: str  # token | userpass | ldap | oidc | kubernetes | jwt
    minted: bool = False  # True if we created this token by logging in, so we should revoke it
    display_name: str = ""
    policies: list[str] = []
    expires_at: float | None = None  # epoch seconds; None means no expiry


class PendingOidc(BaseModel):
    """Login state kept between redirecting to the IdP and handling its callback."""

    state: str  # Vault's state parameter, checked on the callback
    nonce: str  # our client_nonce, sent to Vault on both legs
    url: str
    namespace: str | None = None
    name: str
    preset_id: int | None = None
    mount: str
    role: str | None = None
    side: str | None = None  # which side of the comparison started the login
    created_at: float = Field(default_factory=time.time)

    def expired(self, max_age: float = 600) -> bool:
        return time.time() - self.created_at > max_age


class SessionData(BaseModel):
    connections: list[Connection] = []
    pending_oidc: PendingOidc | None = None

    def get(self, conn_id: str) -> Connection | None:
        return next((c for c in self.connections if c.id == conn_id), None)


def _fernet(settings: Settings) -> Fernet:
    digest = hashlib.sha256(settings.session_key.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def decode(raw: str | None, settings: Settings) -> SessionData:
    if not raw:
        return SessionData()
    try:
        plain = _fernet(settings).decrypt(raw.encode(), ttl=settings.session_ttl_seconds)
        data = SessionData.model_validate_json(plain)
    except (InvalidToken, ValueError):
        return SessionData()
    now = time.time()
    data.connections = [c for c in data.connections if c.expires_at is None or c.expires_at > now]
    return data


def encode(data: SessionData, settings: Settings) -> str:
    return _fernet(settings).encrypt(data.model_dump_json(exclude_defaults=True).encode()).decode()


class SessionTooLarge(Exception):
    pass


def load_session(request: Request, settings: Settings = Depends(get_settings)) -> SessionData:
    return decode(request.cookies.get(COOKIE_NAME), settings)


def save_session(response: Response, data: SessionData, settings: Settings) -> None:
    value = encode(data, settings)
    if len(value) > MAX_COOKIE_BYTES:
        raise SessionTooLarge(f"session cookie would be {len(value)} bytes")
    response.set_cookie(
        COOKIE_NAME, value,
        max_age=settings.session_ttl_seconds,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
        path="/",
    )
