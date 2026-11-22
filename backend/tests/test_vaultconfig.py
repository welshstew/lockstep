"""Vault configuration compared across two Vaults: mounts, auth methods, their tuning and config."""

import uuid

import httpx
import pytest

from lockstep.api.vaultconfig import diff, normalise_mount

pytestmark = pytest.mark.usefixtures("vaults")


def test_normalise_and_diff():
    m = {"type": "kv", "accessor": "kv_1", "uuid": "u", "local": False, "options": {"version": "2"},
         "config": {"default_lease_ttl": 0, "max_lease_ttl": 3600, "listing_visibility": ""},
         "plugin_version": "", "running_plugin_version": "v0.25.0+builtin", "description": ""}
    assert normalise_mount(m) == {"type": "kv", "options": {"version": "2"}, "config": {"max_lease_ttl": 3600},
                                  "plugin_version": "v0.25.0+builtin"}
    assert diff({"config": {"a": 1, "b": 2}}, {"config": {"a": 1, "b": 3}, "x": True}) == [
        {"field": "config.b", "left": 2, "right": 3}, {"field": "x", "left": None, "right": True}]
    assert "bindpass" not in normalise_mount({"type": "ldap", "bindpass": "x", "client_secret": "y", "url": "ldap://h"})


@pytest.fixture
def two(client, vaults):
    tag = uuid.uuid4().hex[:6]
    a = httpx.Client(base_url=f"{vaults[0]}/v1/", headers={"X-Vault-Token": "root-a"}, timeout=10)
    b = httpx.Client(base_url=f"{vaults[1]}/v1/", headers={"X-Vault-Token": "root-b"}, timeout=10)
    a.post(f"sys/mounts/cfg-{tag}", json={"type": "kv", "options": {"version": "2"}, "config": {"max_lease_ttl": "1h"}}).raise_for_status()
    b.post(f"sys/mounts/cfg-{tag}", json={"type": "kv", "options": {"version": "2"}, "config": {"max_lease_ttl": "2h"}}).raise_for_status()
    a.post(f"sys/mounts/cfg-only-{tag}", json={"type": "kv"}).raise_for_status()
    a.post(f"sys/auth/up-{tag}", json={"type": "userpass", "config": {"listing_visibility": "unauth"}}).raise_for_status()
    b.post(f"sys/auth/up-{tag}", json={"type": "userpass"}).raise_for_status()
    ids = [client.post("/api/connections", json={"preset_id": i, "auth": {"method": "token", "token": t}}).json()["id"]
           for i, t in ((0, "root-a"), (1, "root-b"))]
    yield tag, ids
    for v in (a, b):
        v.delete(f"sys/mounts/cfg-{tag}")
        v.delete(f"sys/auth/up-{tag}")
    a.delete(f"sys/mounts/cfg-only-{tag}")


def test_compare_two_vaults(client, two):
    tag, (ca, cb) = two
    r = client.post("/api/config/compare", json={"left": ca, "right": cb})
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["overview"]["left"]["version"] and out["overview"]["left"]["sealed"] is False
    mounts = {p["path"]: p for p in out["mounts"]}
    cfg = mounts[f"cfg-{tag}/"]
    assert cfg["status"] == "different" and cfg["fields"] == [{"field": "config.max_lease_ttl", "left": 3600, "right": 7200}]
    assert mounts[f"cfg-only-{tag}/"]["status"] == "left_only"
    assert mounts["app-config/"]["status"] == "equal"
    assert mounts["sys/"]["system"] and not mounts["app-config/"]["system"]
    auth = {p["path"]: p for p in out["auth"]}
    up = auth[f"up-{tag}/"]
    assert up["status"] == "different" and up["fields"][0]["field"] == "config.listing_visibility"
    jwt = auth["jwt/"]
    assert "configuration" in jwt["left"] and jwt["left"]["configuration"]["bound_issuer"]
    assert out["summary"]["different"] >= 2


def test_overview_and_missing_rights(client, two):
    tag, (ca, cb) = two
    o = client.get("/api/config/overview", params={"conn_id": ca}).json()
    assert o["version"].startswith("1.") or o["version"].startswith("2.")
    carol = client.post("/api/connections", json={"preset_id": 0, "auth": {"method": "userpass", "username": "carol", "password": "password"}}).json()["id"]
    out = client.post("/api/config/compare", json={"left": carol, "right": cb}).json()
    assert "read on sys/mounts" in out["missing"]["left"]
    assert any(p["path"] == "app-config/" and p["left"] for p in out["mounts"])  # from the UI listing


def test_cli_config_compare(two, vaults, monkeypatch, capsys, tmp_path):
    tag, _ = two
    for var in ("VAULT_ADDR", "VAULT_TOKEN", "VAULT_NAMESPACE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("LOCKSTEP_LEFT_TOKEN", "root-a")
    monkeypatch.setenv("LOCKSTEP_RIGHT_TOKEN", "root-b")
    monkeypatch.chdir(tmp_path)
    from lockstep.cli import main
    assert main(["config", "compare", "--left-addr", vaults[0], "--right-addr", vaults[1]]) == 1
    out = capsys.readouterr().out
    assert f"different   secrets engine cfg-{tag}/" in out and "config.max_lease_ttl: 3600 → 7200" in out
    assert f"left only   secrets engine cfg-only-{tag}/" in out


def test_engine_roles_and_keys(client):
    left = client.post("/api/connections", json={"preset_id": 0, "auth": {"method": "token", "token": "root-a"}}).json()["id"]
    right = client.post("/api/connections", json={"preset_id": 1, "auth": {"method": "token", "token": "root-b"}}).json()["id"]
    out = client.post("/api/config/compare", json={"left": left, "right": right}).json()
    eng = {p["path"]: p for p in out["engines"]}
    assert eng["transit/keys/signing-key"]["status"] == "equal"
    app = eng["transit/keys/app-key"]
    assert app["status"] == "different" and app["type"] == "transit"
    assert {f["field"] for f in app["fields"]} == {"auto_rotate_period", "deletion_allowed"}
    assert not any(p.startswith("pki-dev/") or p.startswith("database/") for p in eng)  # only on Vault A


def test_engine_clean_redacts():
    from lockstep.api.vaultconfig import _engine_clean
    d = _engine_clean("config", {"plugin_name": "pg", "connection_details": {"connection_url": "postgresql://app:hunter2@db/x", "username": "app", "password": "x"}})
    assert d["connection_details"] == {"connection_url": "postgresql://app:…@db/x", "username": "app"}
    t = _engine_clean("config", {"connection_details": {"connection_url": "postgresql://{{username}}:{{password}}@db/x"}})
    assert t["connection_details"]["connection_url"].endswith("{{password}}@db/x")
    assert "keys" not in _engine_clean("keys", {"type": "aes", "keys": {"1": 123}, "latest_version": 3})
