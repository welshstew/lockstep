"""Configuration drift beyond mounts: audit devices, password policies, token roles, quotas, MFA,
plugins and identity entities (by name, not cluster IDs), and engines Lockstep compares generically."""

import asyncio
import uuid

import httpx
import pytest

from lockstep.api.vaultconfig import HIDDEN, read_engine_objects
from lockstep.vault import VaultError

pytestmark = pytest.mark.usefixtures("vaults")

TOTP_URL = "otpauth://totp/Lockstep:alice?secret=Y64VEVMBTSXCYIWRSHRNDZW62MPGVU2G&issuer=Lockstep"


@pytest.fixture
def setup(client, vaults):
    tag = uuid.uuid4().hex[:6]
    a = httpx.Client(base_url=f"{vaults[0]}/v1/", headers={"X-Vault-Token": "root-a"}, timeout=10)
    b = httpx.Client(base_url=f"{vaults[1]}/v1/", headers={"X-Vault-Token": "root-b"}, timeout=10)
    policy = 'length = 20\nrule "charset" {\n  charset = "abcdefghijklmnopqrstuvwxyz"\n}\n'
    a.put(f"sys/policies/password/pp-{tag}", json={"policy": policy}).raise_for_status()
    b.put(f"sys/policies/password/pp-{tag}", json={"policy": policy.replace("20", "24")}).raise_for_status()
    a.put(f"sys/policies/password/pp-only-{tag}", json={"policy": policy}).raise_for_status()
    for v, ttl in ((a, "1h"), (b, "1h")):
        v.post(f"auth/token/roles/tr-{tag}", json={"allowed_policies": ["default"], "token_ttl": ttl}).raise_for_status()
    b.post(f"auth/token/roles/tr-{tag}", json={"allowed_policies": ["default", "ops"], "token_ttl": "1h"}).raise_for_status()
    for v, rate in ((a, 100), (b, 50)):
        v.post(f"sys/quotas/rate-limit/rl-{tag}", json={"rate": rate, "path": "app-config/"}).raise_for_status()
    # A Duo MFA method on the left only: its keys are secrets
    a.post("identity/mfa/method/duo", json={"method_name": f"duo-{tag}", "secret_key": "duo-secret-value",
                                            "integration_key": "duo-ikey-value", "api_hostname": "api-1.duosecurity.com"}
           ).raise_for_status()
    # A generically compared engine on both sides: TOTP keys
    for v in (a, b):
        v.post(f"sys/mounts/totp-{tag}", json={"type": "totp"}).raise_for_status()
        v.post(f"totp-{tag}/keys/alice", json={"url": TOTP_URL}).raise_for_status()
    b.post(f"totp-{tag}/keys/bob", json={"url": TOTP_URL.replace("alice", "bob")}).raise_for_status()
    ids = [client.post("/api/connections", json={"preset_id": i, "auth": {"method": "token", "token": t}}).json()["id"]
           for i, t in ((0, "root-a"), (1, "root-b"))]
    yield tag, ids
    for v in (a, b):
        v.delete(f"sys/policies/password/pp-{tag}")
        v.delete(f"auth/token/roles/tr-{tag}")
        v.delete(f"sys/quotas/rate-limit/rl-{tag}")
        v.delete(f"sys/mounts/totp-{tag}")
    a.delete(f"sys/policies/password/pp-only-{tag}")
    for i, info in ((a.request("LIST", "identity/mfa/method").json().get("data") or {}).get("key_info") or {}).items():
        if info.get("name") == f"duo-{tag}" or info.get("method_name") == f"duo-{tag}":
            a.delete(f"identity/mfa/method/duo/{i}")


def test_system_settings_compared_by_name(client, setup):
    tag, (ca, cb) = setup
    r = client.post("/api/config/compare", json={"left": ca, "right": cb})
    assert r.status_code == 200, r.text
    out = r.json()
    sys_ = {p["path"]: p for p in out["system"]}
    pp = sys_[f"password-policy/pp-{tag}"]
    assert pp["status"] == "different" and pp["type"] == "password policy"
    assert pp["fields"][0]["field"] == "policy" and "length = 24" in pp["fields"][0]["right"]
    assert sys_[f"password-policy/pp-only-{tag}"]["status"] == "left_only"
    tr = sys_[f"token-role/tr-{tag}"]
    assert tr["status"] == "different" and [f["field"] for f in tr["fields"]] == ["allowed_policies"]
    rl = sys_[f"quota/rate-limit/rl-{tag}"]
    assert rl["status"] == "different" and {f["field"] for f in rl["fields"]} == {"rate"}

    duo = sys_[f"mfa-method/duo/duo-{tag}"]  # by its name, not its ID
    assert duo["status"] == "left_only" and duo["left"]["api_hostname"] == "api-1.duosecurity.com"
    assert "duo-secret-value" not in r.text and "duo-ikey-value" not in r.text

    # Generic engine: TOTP keys listed and compared, never the key itself
    eng = {p["path"]: p for p in out["engines"]}
    assert eng[f"totp-{tag}/keys/alice"]["status"] == "equal" and eng[f"totp-{tag}/keys/alice"]["type"] == "totp"
    assert eng[f"totp-{tag}/keys/bob"]["status"] == "right_only"
    assert eng[f"totp-{tag}/keys/alice"]["copyable"] is False
    assert "Y64VEVMBTSXCYIWRSHRNDZW62MPGVU2G" not in r.text
    assert set(out["truncated"]) == {"left", "right"} and set(out["warnings"]) == {"left", "right"}


def test_unknown_engine_is_probed_and_cut_off_lists_say_so():
    many = [f"r{i:03}" for i in range(205)]

    class Stub:
        async def request(self, method, path, **kw):
            if method == "LIST":
                if path == "custom/roles":
                    return {"data": {"keys": many}}
                if path == "custom/role":
                    raise VaultError(403, "permission denied", path)  # a guess the plugin answers 403 to
                raise VaultError(404, "not found", path)
            return {"data": {"ttl_seconds": 60, "client_secret": "shh"}}

    truncated: list[str] = []
    out, missing = asyncio.run(read_engine_objects(Stub(), {"custom/": {"type": "my-plugin"}, "kv/": {"type": "kv"}}, truncated))
    assert len(out) == 200 and out["custom/roles/r000"]["client_secret"] == HIDDEN
    assert missing == []  # a guessed path that's refused isn't a missing right
    assert truncated == ["custom/roles: 205 objects, the first 200 compared"]


def test_no_audit_device_is_a_warning():
    from lockstep.api.vaultconfig import read_system

    class Stub:
        async def request(self, method, path, **kw):
            if path == "sys/audit":
                return {"data": {}}
            raise VaultError(404, "not found", path)

    out = asyncio.run(read_system(Stub()))
    assert out["warnings"] == ["No audit device: requests to this Vault aren't logged."] and out["objects"] == {}


def test_entities_and_enforcements_use_names():
    from lockstep.api.vaultconfig import read_system

    data = {
        "sys/auth": {"data": {"userpass/": {"type": "userpass", "accessor": "auth_userpass_123"}}},
        "identity/entity/name/alice": {"data": {"id": "e-1", "name": "alice", "policies": ["dev"],
                                                "aliases": [{"mount_accessor": "auth_userpass_123", "name": "alice"}]}},
        "identity/mfa/method/totp/m-1": {"data": {"id": "m-1", "type": "totp", "method_name": "phone", "issuer": "Acme",
                                                  "period": 30}},
        "identity/mfa/login-enforcement/admins": {"data": {"id": "x", "name": "admins", "mfa_method_ids": ["m-1"],
                                                           "auth_method_accessors": ["auth_userpass_123"],
                                                           "identity_entity_ids": ["e-1"]}},
        "identity/entity/id/e-1": {"data": {"name": "alice"}},
    }
    data["identity/entity/name/entity_1a2b3c4d"] = {"data": {"name": "entity_1a2b3c4d", "policies": ["ops"], "aliases": [
        {"mount_accessor": "auth_userpass_123", "name": "bob"}]}}
    data["identity/entity/name/entity_99999999"] = {"data": {"name": "entity_99999999", "aliases": []}}
    data["identity/entity/name/entity_88888888"] = {"data": {"name": "entity_88888888", "aliases": [
        {"mount_accessor": "auth_userpass_123", "name": "carol"}]}}  # just signed in once
    lists = {"identity/entity/name": ["alice", "entity_1a2b3c4d", "entity_99999999", "entity_88888888"], "identity/mfa/login-enforcement": ["admins"]}

    class Stub:
        async def request(self, method, path, **kw):
            if method == "LIST":
                if path == "identity/mfa/method":
                    return {"data": {"keys": ["m-1"], "key_info": {"m-1": {"type": "totp"}}}}
                if path in lists:
                    return {"data": {"keys": lists[path]}}
                raise VaultError(404, "not found", path)
            if path in data:
                return data[path]
            raise VaultError(404, "not found", path)

    objs = asyncio.run(read_system(Stub()))["objects"]
    assert objs["entity/alice"]["aliases"] == ["userpass/alice"] and "id" not in objs["entity/alice"]
    # an entity Vault named at login pairs by its alias; one with no policies or aliases says nothing
    assert "entity/userpass/bob" in objs and not any("entity_" in k for k in objs)
    assert objs["mfa-method/totp/phone"]["issuer"] == "Acme" and "id" not in objs["mfa-method/totp/phone"]
    enf = objs["mfa-enforcement/admins"]
    assert enf["mfa_methods"] == ["totp/phone"] and enf["auth_methods"] == ["userpass/"]
    assert enf["identity_entities"] == ["alice"]


def test_cli_prints_system_settings(setup, vaults, monkeypatch, capsys):
    tag, _ = setup
    for var in ("VAULT_ADDR", "VAULT_TOKEN", "VAULT_NAMESPACE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("LOCKSTEP_LEFT_TOKEN", "root-a")
    monkeypatch.setenv("LOCKSTEP_RIGHT_TOKEN", "root-b")
    from lockstep.cli import main
    assert main(["config", "compare", "--left-addr", vaults[0], "--right-addr", vaults[1]]) == 1
    out = capsys.readouterr().out
    line = next(ln for ln in out.splitlines() if f"password policy password-policy/pp-{tag} " in ln)
    assert line.startswith("different")
    assert '              policy: length = 20 rule "charset" {' in out  # on one line, cut short
    assert f"right only  key totp-{tag}/keys/bob (totp)" in out
