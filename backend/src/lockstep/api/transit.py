"""A Transit playground for developers testing their integration: keys (read-only) and the crypto
operations, with the signed-in user's own token.

  GET  /api/transit/mounts?conn_id=          Transit secrets engines
  GET  /api/transit/keys?conn_id=&mount=     keys with their settings (no key material)
  POST /api/transit/run                      encrypt, decrypt, rewrap, sign, verify or hmac

Plaintext is UTF-8 text in the browser and base64 to Vault. Nothing is stored or logged by
Lockstep: Vault's own audit log records the operations.
"""

from __future__ import annotations

import asyncio
import base64
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ..config import Settings, get_settings
from ..session import SessionData, load_session
from ..vault import VaultClient, VaultError, _q
from .connections import client_for, get_connection, vault_http_error

router = APIRouter(prefix="/api/transit", tags=["transit"])

Sess = Annotated[SessionData, Depends(load_session)]
Conf = Annotated[Settings, Depends(get_settings)]
KEY_FIELDS = ("type", "latest_version", "min_decryption_version", "min_encryption_version", "supports_encryption",
              "supports_decryption", "supports_signing", "supports_derivation", "derived", "exportable",
              "deletion_allowed", "auto_rotate_period", "convergent_encryption")


async def transit_mounts(v: VaultClient) -> list[dict]:
    try:
        data = (await v.request("GET", "sys/mounts")).get("data") or {}
    except VaultError as e:
        if not e.denied:
            raise
        data = ((await v.request("GET", "sys/internal/ui/mounts")).get("data") or {}).get("secret") or {}
    return [{"path": p.strip("/"), "description": m.get("description") or ""} for p, m in sorted(data.items())
            if m.get("type") == "transit"]


@router.get("/mounts")
async def mounts(session: Sess, settings: Conf, conn_id: str):
    async with client_for(get_connection(session, conn_id), settings) as v:
        try:
            return await transit_mounts(v)
        except VaultError as e:
            raise vault_http_error(e) from e


@router.get("/keys")
async def keys(session: Sess, settings: Conf, conn_id: str, mount: str):
    mount = mount.strip("/")
    async with client_for(get_connection(session, conn_id), settings) as v:
        try:
            names = ((await v.request("LIST", f"{mount}/keys")).get("data") or {}).get("keys") or []
        except VaultError as e:
            if e.status == 404:
                return {"keys": []}
            raise vault_http_error(e) from e

        async def one(n: str) -> dict:
            try:
                d = (await v.request("GET", f"{mount}/keys/{_q(n)}"))["data"]
                return {"name": n, **{k: d.get(k) for k in KEY_FIELDS}}
            except VaultError as e:
                return {"name": n, "error": e.message}
        return {"keys": list(await asyncio.gather(*(one(n) for n in names[:200])))}


class TransitOp(BaseModel):
    conn_id: str
    mount: str = Field(min_length=1)
    key: str = Field(min_length=1, max_length=256)
    op: Literal["encrypt", "decrypt", "rewrap", "sign", "verify", "hmac"]
    text: str = Field(default="", max_length=64 * 1024)  # plaintext (encrypt, sign, verify, hmac) or ciphertext
    signature: str = Field(default="", max_length=8192)  # verify
    context: str = Field(default="", max_length=1024)  # derived keys: the context, as text


def _b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


@router.post("/run")
async def run(body: TransitOp, session: Sess, settings: Conf):
    mount, key = body.mount.strip("/"), _q(body.key)
    ctx = {"context": _b64(body.context)} if body.context else {}
    async with client_for(get_connection(session, body.conn_id), settings) as v:
        try:
            if body.op == "encrypt":
                d = (await v.request("POST", f"{mount}/encrypt/{key}", json={"plaintext": _b64(body.text), **ctx}))["data"]
                return {"result": d["ciphertext"], "key_version": d.get("key_version")}
            if body.op == "decrypt":
                d = (await v.request("POST", f"{mount}/decrypt/{key}", json={"ciphertext": body.text.strip(), **ctx}))["data"]
                raw = base64.b64decode(d["plaintext"])
                try:
                    return {"result": raw.decode()}
                except UnicodeDecodeError:
                    return {"result": d["plaintext"], "note": "Not UTF-8 text: shown as base64."}
            if body.op == "rewrap":
                d = (await v.request("POST", f"{mount}/rewrap/{key}", json={"ciphertext": body.text.strip(), **ctx}))["data"]
                return {"result": d["ciphertext"], "key_version": d.get("key_version")}
            if body.op == "sign":
                d = (await v.request("POST", f"{mount}/sign/{key}", json={"input": _b64(body.text), **ctx}))["data"]
                return {"result": d["signature"], "key_version": d.get("key_version")}
            if body.op == "verify":
                if not body.signature.strip():
                    raise HTTPException(400, detail={"message": "Give the signature to check"})
                d = (await v.request("POST", f"{mount}/verify/{key}", json={"input": _b64(body.text),
                                                                           "signature": body.signature.strip(), **ctx}))["data"]
                return {"result": "valid" if d.get("valid") else "not valid", "valid": bool(d.get("valid"))}
            d = (await v.request("POST", f"{mount}/hmac/{key}", json={"input": _b64(body.text)}))["data"]
            return {"result": d["hmac"], "key_version": d.get("key_version")}
        except VaultError as e:
            raise vault_http_error(e) from e
