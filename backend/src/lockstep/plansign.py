"""Signing plan files so they can travel between Lockstep installations.

With LOCKSTEP_PLAN_SIGNING_KEY (an Ed25519 private key), plans are signed with it, and any
installation that lists the matching public key in LOCKSTEP_PLAN_TRUSTED_KEYS can verify and
apply them. An installation always trusts its own key. Without a signing key, plans are signed
with an HMAC key derived from LOCKSTEP_SESSION_KEY, as before: they verify only where that
session key is set.

Each new plan also says who issued it (`issuer`: the installation's name and key ID), which
installations may apply it (`audience`, optional), and when it's valid (`not_before`,
`expires_at`; LOCKSTEP_PLAN_TTL_HOURS, 7 days by default).

  lockstep plan-key      prints a new key pair, as the settings to use
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any
from urllib.parse import urlparse

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from fastapi import HTTPException
from pydantic import BaseModel

from .config import Settings

PREFIX = "ed25519:"
SKEW = 300  # seconds of clock difference allowed between installations


class Issuer(BaseModel):
    name: str
    key_id: str = ""  # "": signed with this installation's HMAC key, not a key pair


class KeyError_(ValueError):
    pass


def _raw_public(pub: Ed25519PublicKey) -> bytes:
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def key_id(pub: Ed25519PublicKey) -> str:
    return hashlib.sha256(_raw_public(pub)).hexdigest()[:16]


def load_private(text: str) -> Ed25519PrivateKey:
    """A private key as base64 of its 32 raw bytes, or PEM (PKCS#8)."""
    text = text.strip()
    try:
        if text.startswith("-----BEGIN"):
            key = serialization.load_pem_private_key(text.encode(), password=None)
            if not isinstance(key, Ed25519PrivateKey):
                raise KeyError_("LOCKSTEP_PLAN_SIGNING_KEY isn't an Ed25519 key")
            return key
        return Ed25519PrivateKey.from_private_bytes(base64.b64decode(text, validate=True))
    except KeyError_:
        raise
    except (ValueError, TypeError) as e:
        raise KeyError_(f"LOCKSTEP_PLAN_SIGNING_KEY isn't a valid Ed25519 private key: {e}") from e


def load_public(text: str) -> Ed25519PublicKey:
    """A public key as base64 of its 32 raw bytes, or PEM."""
    text = text.strip()
    try:
        if text.startswith("-----BEGIN"):
            key = serialization.load_pem_public_key(text.encode())
            if not isinstance(key, Ed25519PublicKey):
                raise KeyError_("not an Ed25519 key")
            return key
        return Ed25519PublicKey.from_public_bytes(base64.b64decode(text, validate=True))
    except KeyError_:
        raise
    except (ValueError, TypeError) as e:
        raise KeyError_(f"not a valid Ed25519 public key: {e}") from e


@dataclass(frozen=True)
class Keys:
    name: str  # this installation's name
    private: Ed25519PrivateKey | None
    own_id: str  # "" without a key pair
    trusted: dict[str, tuple[str, Ed25519PublicKey]]  # key id -> (installation name, key)


def installation_name(settings: Settings) -> str:
    return settings.plan_issuer or urlparse(settings.public_url).hostname or "lockstep"


@lru_cache(maxsize=8)
def _keys(signing: str, trusted: tuple[tuple[str, str], ...], name: str) -> Keys:
    private = load_private(signing) if signing else None
    out: dict[str, tuple[str, Ed25519PublicKey]] = {}
    for tname, tkey in trusted:
        try:
            pub = load_public(tkey)
        except KeyError_ as e:
            raise KeyError_(f"LOCKSTEP_PLAN_TRUSTED_KEYS: {tname}: {e}") from e
        out[key_id(pub)] = (tname, pub)
    own = ""
    if private:
        own = key_id(private.public_key())
        out[own] = (name, private.public_key())
    return Keys(name=name, private=private, own_id=own, trusted=out)


def keys(settings: Settings) -> Keys:
    try:
        return _keys(settings.plan_signing_key, tuple((t.name, t.key) for t in settings.plan_trusted_keys),
                     installation_name(settings))
    except KeyError_ as e:
        raise HTTPException(500, detail={"message": f"Plan signing is misconfigured: {e}"}) from e


def public_key(settings: Settings) -> dict:
    k = keys(settings)
    if not k.private:
        return {"issuer": k.name, "key_id": None, "public_key": None}
    return {"issuer": k.name, "key_id": k.own_id,
            "public_key": base64.b64encode(_raw_public(k.private.public_key())).decode()}


def now_iso(offset: float = 0) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + offset))


def validity(settings: Settings) -> dict[str, Any]:
    """The fields a new plan gets: issuer, not_before, expires_at."""
    k = keys(settings)
    return {"issuer": Issuer(name=k.name, key_id=k.own_id), "not_before": now_iso(),
            "expires_at": now_iso(settings.plan_ttl_hours * 3600)}


def sign(body: bytes, settings: Settings, hmac_key: bytes) -> str:
    """The signature of a plan's canonical bytes: Ed25519 with a key pair, else the old HMAC."""
    k = keys(settings)
    if k.private:
        return PREFIX + base64.b64encode(k.private.sign(body)).decode()
    return hmac.new(hmac_key, body, hashlib.sha256).hexdigest()


TAMPERED = ("This plan file was changed after it was created, or was made by a Lockstep server this one "
            "doesn't trust. Nothing can be applied from it: create the plan again.")


def verify(body: bytes, signature: str, issuer: Issuer | None, settings: Settings, hmac_key: bytes) -> bool:
    """Check a plan's signature. Returns True when this installation issued it (so the check codes
    of typed values can be verified here). Raises 400 when it can't be trusted."""
    k = keys(settings)
    if signature.startswith(PREFIX):
        if not issuer or not issuer.key_id:
            raise HTTPException(400, detail={"message": TAMPERED})
        found = k.trusted.get(issuer.key_id)
        if not found:
            raise HTTPException(400, detail={"message": (
                f"This plan was signed by {issuer.name} (key {issuer.key_id}), which this Lockstep server doesn't "
                "trust. An admin can add its public key to LOCKSTEP_PLAN_TRUSTED_KEYS.")})
        try:
            found[1].verify(base64.b64decode(signature[len(PREFIX):]), body)
        except (InvalidSignature, ValueError) as e:
            raise HTTPException(400, detail={"message": TAMPERED}) from e
        return issuer.key_id == k.own_id
    want = hmac.new(hmac_key, body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(want, signature):
        raise HTTPException(400, detail={"message": TAMPERED})
    return True


def _parse(t: str) -> float:
    return datetime.strptime(t, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()


def check_valid(settings: Settings, not_before: str | None, expires_at: str | None, audience: list[str]) -> None:
    """Refuse a plan that isn't valid yet, has expired, or is meant for other installations."""
    now = time.time()
    if expires_at and now > _parse(expires_at) + SKEW:
        raise HTTPException(400, detail={"message": f"This plan expired at {expires_at}. Create it again from a new comparison."})
    if not_before and now < _parse(not_before) - SKEW:
        raise HTTPException(400, detail={"message": f"This plan isn't valid until {not_before}. Check the clocks."})
    name = installation_name(settings)
    if audience and name not in audience:
        raise HTTPException(400, detail={"message": (
            f"This plan is for {', '.join(audience)}, not this Lockstep server ({name}).")})


def generate() -> tuple[str, str]:
    """A new key pair: (private, public), each as base64 of the raw 32 bytes."""
    private = Ed25519PrivateKey.generate()
    raw = private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    return base64.b64encode(raw).decode(), base64.b64encode(_raw_public(private.public_key())).decode()
