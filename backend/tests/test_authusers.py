"""Userpass users and LDAP group mappings, against the seeded dev Vaults."""

import logging
import uuid

import httpx
import pytest

from conftest import has_plugin_b

pytestmark = pytest.mark.usefixtures("vaults")


def connect(client, preset=0, **auth):
    auth.setdefault("method", "token")
    r = client.post("/api/connections", json={"preset_id": preset, "auth": auth})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def test_mounts_and_userpass_users(client):
    a = connect(client, token="root-a")
    mounts = {m["path"]: m["type"] for m in client.get("/api/authusers/mounts", params={"conn_id": a}).json()}
    assert mounts["userpass"] == "userpass" and mounts["ldap"] == "ldap"
    out = client.get("/api/authusers", params={"conn_id": a, "mount": "userpass"}).json()
    users = {u["name"]: u for u in out["users"]}
    assert users["alice"]["token_policies"] == ["lockstep-admin"]
    assert users["svc-ci"]["token_ttl"] == 900
    assert not any("password" in u for u in out["users"])


def test_ldap_mappings_without_bind_password(client):
    a = connect(client, token="root-a")
    out = client.get("/api/authusers", params={"conn_id": a, "mount": "ldap"}).json()
    assert out["type"] == "ldap" and out["config"]["url"] == "ldaps://ldap.example.internal"
    assert "bindpass" not in out["config"]
    groups = {g["name"]: g for g in out["groups"]}
    assert groups["payments-devs"]["policies"] == ["payments-dev"]
    assert {u["name"]: u for u in out["users"]}["dana"]["groups"] == ["payments-devs", "platform"]


def test_compare_two_vaults(client):
    if not has_plugin_b("auth", "ldap"):
        pytest.skip("Vault B has no LDAP auth method (OpenBao)")
    a, b = connect(client, 0, token="root-a"), connect(client, 1, token="root-b")
    out = client.post("/api/authusers/compare", json={"left": {"conn_id": a, "mount": "ldap"},
                                                      "right": {"conn_id": b, "mount": "ldap"}}).json()
    groups = {g["name"]: g for g in out["groups"]}
    assert groups["payments-devs"]["status"] == "different" and groups["platform"]["status"] == "equal"
    assert groups["sandbox-users"]["status"] == "left_only"
    assert {c["field"] for c in out["config"]} == {"token_ttl"}
    up = client.post("/api/authusers/compare", json={"left": {"conn_id": a, "mount": "userpass"},
                                                     "right": {"conn_id": b, "mount": "userpass"}}).json()
    users = {u["name"]: u for u in up["users"]}
    assert users["alice"]["status"] == "equal" and users["svc-ci"]["status"] == "different"
    r = client.post("/api/authusers/compare", json={"left": {"conn_id": a, "mount": "ldap"},
                                                    "right": {"conn_id": b, "mount": "userpass"}})
    assert r.status_code == 400


def test_create_and_reset_a_user(client, vaults, caplog):
    a = connect(client, token="root-a")
    name = f"dev-{uuid.uuid4().hex[:6]}"
    try:
        with caplog.at_level(logging.INFO, logger="lockstep.audit"):
            r = client.post("/api/authusers/userpass", json={"conn_id": a, "mount": "userpass", "username": name,
                                                             "action": "create", "policies": ["lockstep-readonly"]})
        assert r.status_code == 200, r.text
        pw = r.json()["password"]
        assert len(pw) == 24 and pw not in caplog.text
        login = httpx.post(f"{vaults[0]}/v1/auth/userpass/login/{name}", json={"password": pw})
        assert login.status_code == 200 and "lockstep-readonly" in login.json()["auth"]["policies"]
        r = client.post("/api/authusers/userpass", json={"conn_id": a, "mount": "userpass", "username": name, "action": "create"})
        assert r.status_code == 409
        r = client.post("/api/authusers/userpass", json={"conn_id": a, "mount": "userpass", "username": name,
                                                         "action": "reset", "password": "a-new-password"})
        assert r.status_code == 200 and "password" not in r.json()
        assert httpx.post(f"{vaults[0]}/v1/auth/userpass/login/{name}", json={"password": "a-new-password"}).status_code == 200
        r = client.post("/api/authusers/userpass", json={"conn_id": a, "mount": "ldap", "username": name, "action": "reset"})
        assert r.status_code == 400
    finally:
        httpx.delete(f"{vaults[0]}/v1/auth/userpass/users/{name}", headers={"X-Vault-Token": "root-a"})


def test_user_write_off_by_setting(client, monkeypatch):
    from lockstep.config import get_settings
    monkeypatch.setattr(get_settings(), "user_write", "off")
    a = connect(client, token="root-a")
    r = client.post("/api/authusers/userpass", json={"conn_id": a, "mount": "userpass", "username": "x1", "action": "create"})
    assert r.status_code == 403 and "LOCKSTEP_USER_WRITE" in r.json()["detail"]["message"]
    assert client.get("/api/config").json()["user_write"] is False


def test_bob_cannot_list(client):
    bob = connect(client, method="userpass", username="bob", password="password")
    r = client.get("/api/authusers", params={"conn_id": bob, "mount": "userpass"})
    assert r.status_code == 200 and r.json()["missing"]
