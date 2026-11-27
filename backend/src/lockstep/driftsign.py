"""Signed drift files: a baseline (accepted drift) or a waivers file, signed with the plan key.

A drift check passes when every difference is in the baseline or waived, and both are files in a
repository: anyone who can push could hide new drift by adding a line. Signed with the plan
signing key (LOCKSTEP_PLAN_SIGNING_KEY, Ed25519), a change needs that key too. The checking side
needs only the public key (LOCKSTEP_PLAN_TRUSTED_KEYS).

The signature covers the file's parsed content and its issuer (so reformatting or a comment in a
waivers file doesn't break it, but changing a waiver does), under a label per kind of file, so a
signed baseline can't pass as signed waivers or as a plan.
"""

from __future__ import annotations

import base64
import json
from typing import Any, Literal

from cryptography.exceptions import InvalidSignature

from .plansign import PREFIX, Issuer, Keys

Kind = Literal["baseline", "waivers"]


class SignatureProblem(ValueError):
    """A signed file that can't be trusted, or an unsigned one where a signature is required."""


def _canonical(kind: Kind, body: dict[str, Any], issuer: Issuer) -> bytes:
    doc = body | {"issuer": issuer.model_dump()}
    return f"lockstep-{kind}-v1\0".encode() + json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sign(kind: Kind, body: dict[str, Any], keys: Keys) -> tuple[Issuer, str]:
    """The issuer and signature for a file's content (`body`, without issuer or signature)."""
    if not keys.private:
        raise SignatureProblem("Signing needs the plan signing key in LOCKSTEP_PLAN_SIGNING_KEY "
                               "(`lockstep plan-key` makes a key pair).")
    issuer = Issuer(name=keys.name, key_id=keys.own_id)
    return issuer, PREFIX + base64.b64encode(keys.private.sign(_canonical(kind, body, issuer))).decode()


def check(kind: Kind, body: dict[str, Any], issuer: Issuer | None, signature: str | None, keys: Keys,
          name: str, require: bool = False) -> str | None:
    """Check a file's signature. Returns a line for the summary (who signed it, or that it couldn't
    be checked), None for an unsigned file. Raises SignatureProblem when it can't be trusted, and for
    an unsigned file or no trusted keys with `require`."""
    sign_cmd = f"lockstep {kind} sign {name}"
    if not signature:
        if require:
            raise SignatureProblem(f"{name} isn't signed, and signed files are required. Once its content is "
                                   f"approved, sign it with: {sign_cmd}")
        return None
    if not signature.startswith(PREFIX) or not issuer or not issuer.key_id:
        raise SignatureProblem(f"{name} has a signature Lockstep can't read: the file was edited. Sign it again "
                               f"once its content is approved: {sign_cmd}")
    if not keys.trusted:
        if require:
            raise SignatureProblem("Checking signed files needs the signer's public key in LOCKSTEP_PLAN_TRUSTED_KEYS.")
        return (f"{name} is signed by {issuer.name}, but not checked: set LOCKSTEP_PLAN_TRUSTED_KEYS to check it.")
    found = keys.trusted.get(issuer.key_id)
    if not found:
        raise SignatureProblem(f"{name} is signed by {issuer.name} (key {issuer.key_id}), which isn't a trusted key "
                               "here. Add its public key to LOCKSTEP_PLAN_TRUSTED_KEYS, or sign it with a trusted one.")
    try:
        found[1].verify(base64.b64decode(signature[len(PREFIX):]), _canonical(kind, body, issuer))
    except (InvalidSignature, ValueError) as e:
        raise SignatureProblem(f"{name} was changed after {found[0]} signed it, so nothing is checked against it. "
                               f"Once the change is approved, sign it again: {sign_cmd}") from e
    return f"{name}: signed by {found[0]} (key {issuer.key_id})."
