"""Leases: list, look up, renew, revoke (token leases made for the test)."""

import httpx
import pytest

pytestmark = pytest.mark.usefixtures("vaults")


@pytest.fixture
def root(client):
    return client.post("/api/connections", json={"preset_id": 0, "auth": {"method": "token", "token": "root-a"}}).json()["id"]


def make_token(vaults):
    v = httpx.Client(base_url=f"{vaults[0]}/v1/", headers={"X-Vault-Token": "root-a"})
    t = v.post("auth/token/create", json={"ttl": "1h", "policies": ["default"]}).json()["auth"]
    return v, t


def test_tree_lookup_renew_revoke(client, root, vaults):
    v, tok = make_token(vaults)
    top = client.get("/api/leases", params={"conn_id": root}).json()
    assert "auth/" in top["folders"]
    level = client.get("/api/leases", params={"conn_id": root, "prefix": "auth/token/create"}).json()
    assert level["prefix"] == "auth/token/create/" and level["leases"]
    # The new token's lease is the one whose lookup has a 1 h TTL; find it by revoking-and-checking below
    info = client.post("/api/leases/lookup", json={"conn_id": root, "lease_ids": level["leases"][:100]}).json()["leases"]
    assert all("expire_time" in x or "error" in x for x in info)
    lid = next(x["id"] for x in info if "ttl" in x and x["ttl"] and x["ttl"] > 3000)
    r = client.post("/api/leases/renew", json={"conn_id": root, "lease_id": lid, "increment": 600})
    assert r.status_code in (200, 400), r.text  # tokens can refuse renewing below their TTL
    out = client.post("/api/leases/revoke", json={"conn_id": root, "lease_ids": [lid]}).json()
    assert out["revoked"] == 1
    after = client.get("/api/leases", params={"conn_id": root, "prefix": "auth/token/create/"}).json()
    assert lid not in after["leases"]
    v.close()


def test_listing_needs_sudo(client):
    alice = client.post("/api/connections", json={"preset_id": 0, "auth": {"method": "userpass", "username": "bob", "password": "password"}})
    assert alice.status_code == 201, alice.text
    r = client.get("/api/leases", params={"conn_id": alice.json()["id"]})
    assert r.status_code == 403 and "sudo" in r.json()["detail"]["message"]


def test_bad_prefix(client, root):
    assert client.get("/api/leases", params={"conn_id": root, "prefix": "auth/../sys"}).status_code == 400


def test_top_level_mount_by_mount(client):
    """alice has sudo on *, but the default policy's exact sys/leases/lookup rule hides the top level."""
    alice = client.post("/api/connections", json={"preset_id": 0, "auth": {"method": "userpass", "username": "alice", "password": "password"}}).json()["id"]
    top = client.get("/api/leases", params={"conn_id": alice}).json()
    assert "auth/" in top["folders"] and top["note"]
    assert client.get("/api/leases", params={"conn_id": alice, "prefix": "auth/"}).status_code == 200
