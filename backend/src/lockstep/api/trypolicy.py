"""Try a draft policy for real: Vault's own answer, next to Lockstep's prediction.

  POST /api/policies/try   write the draft as a temporary policy, mint a short-lived token with it,
                           ask Vault what that token may do on each secret (sys/capabilities-self),
                           then revoke the token and delete the policy

The temporary policy is named lockstep-try-<random>, the token lives two minutes at most and is a
child of the connection's token, and both are removed before the response is sent (the token's TTL
is the backstop if removing fails). Needs write on sys/policies/acl and sudo on auth/token/create
(to give a token a policy the signed-in token doesn't hold). Refused when LOCKSTEP_READ_ONLY is on.
"""

from __future__ import annotations

import json
import logging
import secrets
import time
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ..config import Settings, get_settings
from ..policy.explain import COLUMNS
from ..policy.hcl import PolicyParseError, parse_policy
from ..session import SessionData, load_session
from ..vault import VaultError
from .connections import client_for, get_connection, vault_http_error
from .guard import require_writable
from .. import writepolicy
from .policies import MAX_TEXT, ExplainError, PastedPolicy, _from_vault, run_explain

router = APIRouter(prefix="/api/policies", tags=["policies"])
audit = logging.getLogger("lockstep.audit")
log = logging.getLogger(__name__)

Sess = Annotated[SessionData, Depends(load_session)]
Conf = Annotated[Settings, Depends(get_settings)]
TRY_TTL = "2m"


class TryRequest(BaseModel):
    conn_id: str
    mount: str = Field(min_length=1)
    prefix: str = ""
    name: str = Field(default="draft", min_length=1, max_length=128)  # for display only
    text: str = Field(min_length=1, max_length=MAX_TEXT)
    with_default: bool = True  # tokens normally get the default policy too


def _cells(rows: list[dict]) -> dict[tuple[str, str], bool]:
    return {(r["path"], col): r["cells"][col]["ok"] for r in rows for col, *_ in COLUMNS if col in r["cells"]}


@router.post("/try")
async def try_policy(body: TryRequest, session: Sess, settings: Conf):
    require_writable(settings)
    try:
        parse_policy(body.text, body.name)
    except PolicyParseError as e:
        raise HTTPException(400, detail={"message": f"The draft can't be parsed: {e}"}) from e
    conn = get_connection(session, body.conn_id)
    temp = f"lockstep-try-{secrets.token_hex(4)}"
    writepolicy.check(settings, conn, f"sys/policies/acl/{temp}", event="policy.try")
    async with client_for(conn, settings) as v:
        try:
            # Lockstep's prediction, from the policy texts
            predicted = await run_explain(v, body.mount, body.prefix, names=["default"] if body.with_default else [],
                                          pasted=[PastedPolicy(name=body.name, text=body.text)], token=False,
                                          max_secrets=settings.max_tree_secrets)
        except ExplainError as e:
            raise HTTPException(e.status, detail={"message": e.message}) from e
        except VaultError as e:
            raise vault_http_error(e) from e
        guess = _cells(predicted["rows"])

        token = accessor = None
        try:
            try:
                await v.request("PUT", f"sys/policies/acl/{temp}", json={"policy": body.text})
            except VaultError as e:
                if e.denied:
                    raise HTTPException(403, detail={"message": "Trying a policy writes a temporary one: this token "
                                                                "needs create on sys/policies/acl/lockstep-try-*"}) from e
                raise vault_http_error(e) from e
            try:
                res = await v.request("POST", "auth/token/create", json={
                    "policies": [temp], "no_default_policy": not body.with_default, "ttl": TRY_TTL,
                    "explicit_max_ttl": TRY_TTL, "renewable": False, "display_name": "lockstep-try",
                    "meta": {"lockstep": "try-policy"}})
            except VaultError as e:
                if e.denied or e.status == 400:
                    raise HTTPException(403, detail={"message": "Vault wouldn't create a token with the draft policy. "
                                                                "Giving a token a policy you don't hold needs sudo on "
                                                                f"auth/token/create ({e.message})"}) from e
                raise vault_http_error(e) from e
            token, accessor = res["auth"]["client_token"], res["auth"]["accessor"]
            try:
                await _from_vault(v, predicted["mount"], predicted, token=token)
            except VaultError as e:
                raise vault_http_error(e) from e
        finally:
            await _clean_up(v, token, temp)

    actual = _cells(predicted["rows"])
    disagree = [{"path": p, "column": c, "predicted": guess[(p, c)], "vault": ok}
                for (p, c), ok in sorted(actual.items()) if (p, c) in guess and guess[(p, c)] != ok]
    audit.info(json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "event": "policy.try",
                           "outcome": "applied", "actor": {"identity": conn.display_name, "auth": conn.auth_method, "entity_id": conn.entity_id, "accessor": conn.accessor},
                           "target": {"vault": conn.name, "url": conn.url, "mount": predicted["mount"]},
                           "temporary_policy": temp, "token_accessor": accessor}, sort_keys=True))
    return {**predicted, "mode": "vault", "complete": True, "temporary_policy": temp, "disagreements": disagree,
            "with_default": body.with_default}


async def _clean_up(v, token: str | None, temp: str) -> None:
    if token:
        try:
            await v.request("POST", "auth/token/revoke-self", token=token)
        except VaultError as e:  # its two minute TTL ends it anyway
            log.warning("couldn't revoke the try-policy token: %s", e.message)
    try:
        await v.request("DELETE", f"sys/policies/acl/{temp}")
    except VaultError as e:
        log.warning("couldn't delete the temporary policy %s: %s", temp, e.message)
