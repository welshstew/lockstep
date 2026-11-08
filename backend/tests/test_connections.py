"""Integration tests against the seeded compose Vaults."""

import pytest

pytestmark = pytest.mark.usefixtures("vaults")


def connect(client, preset_id=0, **auth):
    auth.setdefault("method", "token")
    return client.post("/api/connections", json={"preset_id": preset_id, "auth": auth})


def test_config_hides_internal_urls(client):
    presets = client.get("/api/config").json()["presets"]
    assert [p["name"] for p in presets] == ["Vault A", "Vault B"]
    assert all("url" not in p for p in presets)


def test_csrf_header_required(client):
    r = client.post("/api/connections", json={}, headers={"X-Requested-With": ""})
    assert r.status_code == 403


def test_token_login_and_list(client):
    r = connect(client, 0, token="root-a")
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["policies"] == ["root"] and body["url"] is None
    listed = client.get("/api/connections").json()
    assert [c["status"] for c in listed] == ["ok"]


def test_bad_token_rejected(client):
    r = connect(client, 0, token="nope")
    assert r.status_code == 401


def test_userpass_login_and_logout_revokes(client, vaults):
    import httpx
    r = connect(client, 1, method="userpass", username="alice", password="password")
    assert r.status_code == 201, r.text
    assert "lockstep-admin" in r.json()["policies"]
    conn_id = r.json()["id"]
    # grab the minted token straight from the session to check that it gets revoked
    from lockstep.config import get_settings
    from lockstep.session import COOKIE_NAME, decode
    token = decode(client.cookies.get(COOKIE_NAME), get_settings()).connections[0].token
    assert client.delete(f"/api/connections/{conn_id}").status_code == 204
    assert client.get("/api/connections").json() == []
    r = httpx.get(f"{vaults[1]}/v1/auth/token/lookup-self", headers={"X-Vault-Token": token})
    assert r.status_code == 403


def test_userpass_bad_password(client):
    r = connect(client, 0, method="userpass", username="alice", password="wrong")
    assert r.status_code == 401


def test_mounts_full_listing(client):
    cid = connect(client, 0, token="root-a").json()["id"]
    body = client.get(f"/api/connections/{cid}/mounts").json()
    paths = [m["path"] for m in body["mounts"]]
    assert body["source"] == "sys/mounts" and body["complete"]
    assert {"app-config", "certs", "team-a-only", "secret"} <= set(paths)
    assert "legacy-kv" not in paths  # KV v1 is filtered out


def test_mounts_fallback_for_limited_user(client):
    cid = connect(client, 0, method="userpass", username="carol", password="password").json()["id"]
    body = client.get(f"/api/connections/{cid}/mounts").json()
    assert body["source"] == "sys/internal/ui/mounts" and not body["complete"]
    assert [m["path"] for m in body["mounts"]] == ["app-config"]


def test_manual_mount_entry(client):
    cid = connect(client, 0, token="root-a").json()["id"]
    assert client.get(f"/api/connections/{cid}/mounts/certs").json()["path"] == "certs"
    assert client.get(f"/api/connections/{cid}/mounts/legacy-kv").status_code == 400
    assert client.get(f"/api/connections/{cid}/mounts/does-not-exist").status_code == 404


def test_tree_full(client):
    cid = connect(client, 1, token="root-b").json()["id"]
    t = client.get(f"/api/connections/{cid}/tree", params={"mount": "app-config"}).json()
    assert t["denied"] == [] and not t["truncated"]
    assert {"payments/db", "payments/api", "team/x/y/z/deep", "new-service/config",
            "restricted/root-creds"} <= set(t["secrets"])


def test_tree_with_prefix(client):
    cid = connect(client, 1, token="root-b").json()["id"]
    t = client.get(f"/api/connections/{cid}/tree", params={"mount": "app-config", "prefix": "payments"}).json()
    assert t["secrets"] == ["payments/api", "payments/db"]


def test_tree_partial_access(client):
    cid = connect(client, 0, method="userpass", username="carol", password="password").json()["id"]
    t = client.get(f"/api/connections/{cid}/tree", params={"mount": "app-config"}).json()
    assert t["denied"] == ["restricted/"]
    assert "payments/db" in t["secrets"]
    assert "payments/api" in t["secrets"]  # listable even though its data can't be read
    assert not any(s.startswith("restricted/") for s in t["secrets"])


def test_unknown_connection(client):
    r = client.get("/api/connections/deadbeef/mounts")
    assert r.status_code == 404 and r.json()["detail"]["reconnect"]
