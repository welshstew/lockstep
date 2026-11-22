"""Signing in to a Vault that asks for a second factor (login MFA with TOTP)."""

import base64
import hashlib
import hmac
import struct
import time
import urllib.parse

from playwright.sync_api import expect

from conftest import field, side


def totp(secret_b32: str) -> str:
    key = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8), casefold=True)
    mac = hmac.new(key, struct.pack(">Q", int(time.time() // 30)), hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    return str((struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF) % 1_000_000).zfill(6)


def test_sign_in_with_a_totp_code(page, sandbox, vault_a):
    tag = sandbox.replace("/", "")[-6:]
    v = vault_a.c
    mount, created = f"mfa-{tag}", []
    try:
        v.post(f"sys/auth/{mount}", json={"type": "userpass"}).raise_for_status()
        accessor = v.get("sys/auth").json()["data"][f"{mount}/"]["accessor"]
        v.post(f"auth/{mount}/users/dave", json={"password": "password", "token_policies": "lockstep-readonly"}).raise_for_status()
        ent = v.post("identity/entity", json={"name": f"dave-{tag}"}).json()["data"]["id"]
        created.append(f"identity/entity/id/{ent}")
        v.post("identity/entity-alias", json={"name": "dave", "canonical_id": ent, "mount_accessor": accessor}).raise_for_status()
        mid = v.post("identity/mfa/method/totp", json={"issuer": "lockstep-e2e", "period": 30}).json()["data"]["method_id"]
        created.append(f"identity/mfa/method/totp/{mid}")
        url = v.post("identity/mfa/method/totp/admin-generate", json={"method_id": mid, "entity_id": ent}).json()["data"]["url"]
        secret = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)["secret"][0]
        v.post(f"identity/mfa/login-enforcement/enf-{tag}", json={"mfa_method_ids": [mid], "auth_method_accessors": [accessor]}).raise_for_status()
        created.append(f"identity/mfa/login-enforcement/enf-{tag}")

        card = side(page, "left")
        sel = field(card, "Vault").locator("select")
        sel.select_option(value=sel.locator("option", has_text="Vault A").first.get_attribute("value"))
        card.get_by_role("button", name="Username", exact=True).click()
        card.get_by_label("Username").fill("dave")
        card.get_by_label("Password").fill("password")
        card.get_by_label("Auth mount path").fill(mount)
        card.get_by_role("button", name="Connect", exact=True).click()

        prompt = card.get_by_role("form", name="Second factor")
        expect(prompt).to_contain_text("Vault asks for a second factor")
        prompt.get_by_label("Passcode").fill("000000")
        prompt.get_by_role("button", name="Verify").click()
        expect(prompt.locator(".notice.error")).to_contain_text("didn't accept")
        if time.time() % 30 > 27:  # don't race the end of the 30-second window
            time.sleep(4)
        prompt.get_by_label("Passcode").fill(totp(secret))
        prompt.get_by_role("button", name="Verify").click()
        expect(card.locator(".conn-chip")).to_contain_text(f"{mount}-dave")
    finally:
        for p in reversed(created):
            v.delete(p)
        v.delete(f"sys/auth/{mount}")
