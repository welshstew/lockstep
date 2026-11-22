"""Copying a mount's tuning or an engine role to the other Vault, through the access review."""

import uuid

import httpx
import pytest

pytestmark = pytest.mark.usefixtures("vaults")


@pytest.fixture
def env(client, vaults):
    tag = uuid.uuid4().hex[:6]
    a = httpx.Client(base_url=f"{vaults[0]}/v1/", headers={"X-Vault-Token": "root-a"})
    b = httpx.Client(base_url=f"{vaults[1]}/v1/", headers={"X-Vault-Token": "root-b"})
    left = client.post("/api/connections", json={"preset_id": 0, "auth": {"method": "token", "token": "root-a"}}).json()["id"]
    right = client.post("/api/connections", json={"preset_id": 1, "auth": {"method": "token", "token": "root-b"}}).json()["id"]
    yield tag, a, b, left, right
    for c in (a, b):
        c.delete(f"sys/mounts/cp-{tag}")
        c.delete(f"sys/mounts/cpki-{tag}")


def review_and_apply(client, conn, changes):
    items = client.post("/api/access/preview", json={"conn_id": conn, **changes}).json()
    out = client.post("/api/access/apply", json={"conn_id": conn, **changes, "confirm": True,
                                                 "expected": {i["id"]: i["hash"] for i in items}}).json()
    return items, out


def test_copy_mount_tuning(client, env):
    tag, a, b, left, right = env
    a.post(f"sys/mounts/cp-{tag}", json={"type": "kv", "description": "shared", "config": {"max_lease_ttl": "2h"}}).raise_for_status()
    b.post(f"sys/mounts/cp-{tag}", json={"type": "kv", "config": {"max_lease_ttl": "1h"}}).raise_for_status()
    changes = client.post("/api/config/copy", json={"conn_id": left, "source": "mount", "path": f"cp-{tag}/"}).json()
    assert changes["tunes"][0]["config"]["max_lease_ttl"] == 7200
    items, out = review_and_apply(client, right, {"tunes": changes["tunes"]})
    assert items[0]["kind"] == "tune" and items[0]["action"] == "change" and "7200" in items[0]["diff"]
    assert out[0]["status"] == "applied"
    tune = b.get(f"sys/mounts/cp-{tag}/tune").json()["data"]
    assert tune["max_lease_ttl"] == 7200 and tune["description"] == "shared"
    # now the same: nothing to do
    items = client.post("/api/access/preview", json={"conn_id": right, "tunes": changes["tunes"]}).json()
    assert items[0]["status"] == "noop"


def test_copy_a_pki_role_and_save_as_plan(client, env):
    tag, a, b, left, right = env
    for c in (a, b):
        c.post(f"sys/mounts/cpki-{tag}", json={"type": "pki"}).raise_for_status()
    a.post(f"cpki-{tag}/roles/web", json={"allowed_domains": ["example.com"], "allow_subdomains": True, "max_ttl": "72h"}).raise_for_status()
    changes = client.post("/api/config/copy", json={"conn_id": left, "source": "engine", "path": f"cpki-{tag}/roles/web"}).json()
    obj = changes["engine_objects"][0]
    assert obj["mount"] == f"cpki-{tag}" and obj["body"]["allow_subdomains"] is True
    plan = client.post("/api/access/plans", json={"conn_id": right, "engine_objects": changes["engine_objects"]}).json()
    chk = client.post("/api/access/plans/check", json={"conn_ids": [right], "plan": plan}).json()
    assert chk["items"][0]["action"] == "new" and chk["items"][0]["status"] == "ready"
    out = client.post("/api/access/plans/apply", json={"conn_ids": [right], "plan": plan, "confirm": True}).json()
    assert [i["status"] for i in out] == ["applied"], out
    role = b.get(f"cpki-{tag}/roles/web").json()["data"]
    assert role["allowed_domains"] == ["example.com"] and role["max_ttl"] == 259200


def test_transit_key_settings_only_on_existing_key(client, env):
    tag, a, b, left, right = env
    changes = client.post("/api/config/copy", json={"conn_id": left, "source": "engine", "path": "transit/keys/app-key"}).json()
    assert set(changes["engine_objects"][0]["body"]) <= {"deletion_allowed", "auto_rotate_period"}
    missing = [{"mount": "transit", "kind": "keys", "name": f"nokey-{tag}", "body": {"deletion_allowed": True}}]
    [it] = client.post("/api/access/preview", json={"conn_id": right, "engine_objects": missing}).json()
    assert it["status"] == "invalid" and "create it first" in it["problems"][0]


def test_refused_kinds(client, env):
    tag, a, b, left, right = env
    r = client.post("/api/config/copy", json={"conn_id": left, "source": "engine", "path": "database/config/orders"})
    assert r.status_code == 400
    r = client.post("/api/access/preview", json={"conn_id": right, "engine_objects": [
        {"mount": "transit", "kind": "keys", "name": "app-key", "body": {"exportable": True}}]})
    assert r.status_code == 422
    r = client.post("/api/access/preview", json={"conn_id": right, "tunes": [{"kind": "secret", "path": "x", "config": {"options": {}}}]})
    assert r.status_code == 422
