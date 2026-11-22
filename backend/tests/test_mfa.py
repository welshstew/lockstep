"""Login MFA: a Vault that enforces a second factor (TOTP here) at sign-in."""

import base64
import hashlib
import hmac
import struct
import time
import urllib.parse
import uuid

import httpx
import pytest

pytestmark = pytest.mark.usefixtures("vaults")


def totp(secret_b32: str, at: float | None = None, step: int = 30, digits: int = 6) -> str:
    key = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8), casefold=True)
    counter = int((at or time.time()) // step)
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    return str((struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF) % 10 ** digits).zfill(digits)


@pytest.fixture
def mfa_user(vaults):
    """A userpass mount whose logins need a TOTP code, and a user enrolled in it."""
    tag = uuid.uuid4().hex[:6]
    v = httpx.Client(base_url=f"{vaults[0]}/v1/", headers={"X-Vault-Token": "root-a"}, timeout=10)
    mount = f"mfa-{tag}"
    created = []
    try:
        v.post(f"sys/auth/{mount}", json={"type": "userpass"}).raise_for_status()
        accessor = v.get("sys/auth").json()["data"][f"{mount}/"]["accessor"]
        v.post(f"auth/{mount}/users/dave", json={"password": "password", "token_policies": "lockstep-readonly"}).raise_for_status()
        ent = v.post("identity/entity", json={"name": f"dave-{tag}"}).json()["data"]["id"]
        created.append(("entity", ent))
        v.post("identity/entity-alias", json={"name": "dave", "canonical_id": ent, "mount_accessor": accessor}).raise_for_status()
        mid = v.post("identity/mfa/method/totp", json={"issuer": "lockstep-test", "period": 30, "key_size": 20,
                                                       "algorithm": "SHA1", "digits": 6}).json()["data"]["method_id"]
        created.append(("method", mid))
        url = v.post("identity/mfa/method/totp/admin-generate", json={"method_id": mid, "entity_id": ent}).json()["data"]["url"]
        secret = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)["secret"][0]
        v.post(f"identity/mfa/login-enforcement/enf-{tag}", json={"mfa_method_ids": [mid], "auth_method_accessors": [accessor]}).raise_for_status()
        created.append(("enforcement", f"enf-{tag}"))
        yield mount, mid, secret
    finally:
        for kind, x in reversed(created):
            v.delete({"entity": f"identity/entity/id/{x}", "method": f"identity/mfa/method/totp/{x}",
                      "enforcement": f"identity/mfa/login-enforcement/{x}"}[kind])
        v.delete(f"sys/auth/{mount}")


def test_login_asks_for_a_second_factor(client, mfa_user):
    mount, mid, secret = mfa_user
    r = client.post("/api/connections", json={"preset_id": 0, "auth": {"method": "userpass", "username": "dave",
                                                                         "password": "password", "mount": mount}})
    assert r.status_code == 202, r.text
    out = r.json()
    assert out["mfa_required"] and out["constraints"][0]["methods"][0] == {"id": mid, "type": "totp", "uses_passcode": True, "name": "totp"}
    assert client.get("/api/connections/mfa").json()["constraints"] == out["constraints"]
    assert client.get("/api/connections").json() == []  # not connected yet

    bad = client.post("/api/connections/mfa", json={"payload": {mid: "000000"}})
    assert bad.status_code == 401 and "didn't accept" in bad.text
    assert client.post("/api/connections/mfa", json={"payload": {"other-id": "1"}}).status_code == 400

    r = client.post("/api/connections/mfa", json={"payload": {mid: totp(secret)}})
    if r.status_code == 401:  # a code at the edge of its 30 s window: try the next one
        time.sleep(31 - time.time() % 30)
        r = client.post("/api/connections/mfa", json={"payload": {mid: totp(secret)}})
    assert r.status_code == 201, r.text
    conn = r.json()
    assert conn["auth_method"] == "userpass" and "lockstep-readonly" in conn["policies"]
    assert client.get("/api/connections/mfa").status_code == 404  # used up


def test_no_pending_mfa(client):
    assert client.post("/api/connections/mfa", json={"payload": {"x": "1"}}).status_code == 410


def test_cli_sign_in_with_an_mfa_code(mfa_user, vaults, monkeypatch, capsys, tmp_path):
    mount, mid, secret = mfa_user
    for var in ("VAULT_ADDR", "VAULT_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("LOCKSTEP_VAULT_PASSWORD", "password")
    monkeypatch.chdir(tmp_path)
    from lockstep.cli import main
    args = ["policy", "explain", "--self", "--mount", "app-config", "--prefix", "payments", "--vault-addr", vaults[0],
            "--vault-auth", "userpass", "--vault-user", "dave", "--vault-auth-mount", mount]
    assert main(args) == 2
    assert "LOCKSTEP_VAULT_MFA_CODE" in capsys.readouterr().err
    if time.time() % 30 > 27:
        time.sleep(4)
    monkeypatch.setenv("LOCKSTEP_VAULT_MFA_CODE", totp(secret))
    assert main(args) == 0
    assert "payments/db" in capsys.readouterr().out
