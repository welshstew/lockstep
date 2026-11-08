"""Compare-endpoint integration tests against the seeded compose Vaults."""

import pytest

pytestmark = pytest.mark.usefixtures("vaults")


def connect(client, preset_id, **auth):
    auth.setdefault("method", "token")
    r = client.post("/api/connections", json={"preset_id": preset_id, "auth": auth})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def compare(client, left, right):
    r = client.post("/api/compare", json={"left": left, "right": right})
    assert r.status_code == 200, r.text
    body = r.json()
    return body, {s["path"]: s for s in body["secrets"]}


@pytest.fixture
def ab(client):
    return connect(client, 0, token="root-a"), connect(client, 1, token="root-b")


def keys(s):
    return {k["key"]: k["status"] for k in s["keys"]}


def test_cross_vault_app_config(client, ab):
    a, b = ab
    body, s = compare(client, {"conn_id": a, "mount": "app-config"}, {"conn_id": b, "mount": "app-config"})

    assert s["payments/api"]["status"] == "equal"
    assert s["payments/db"]["status"] == "different"
    assert keys(s["payments/db"]) == {"host": "equal", "port": "equal", "username": "equal", "password": "different"}
    # versions are reported but never count as a difference (re-seeding makes the numbers grow)
    assert s["payments/api"]["left"]["version"] >= 1 and s["payments/api"]["right"]["version"] >= 1

    assert keys(s["frontend/settings"]) == {"banner_b64": "equal", "timeout": "equal",
                                            "feature_flags": "different", "cdn_url": "right_only"}
    assert s["legacy/old-service"]["status"] == "left_only"
    assert s["new-service/config"]["status"] == "right_only"
    assert s["team/x/y/z/deep"]["status"] == "equal"
    assert s["odd names/with space"]["status"] == "equal"

    mixed = {k["key"]: k for k in s["types/mixed"]["keys"]}
    assert mixed["port"]["status"] == "different" and mixed["port"]["type_differs"]
    assert mixed["tags"]["status"] == "equal" and mixed["enabled"]["status"] == "equal"

    retired = s["retired/thing"]
    assert retired["status"] == "right_only" and retired["left"]["state"] == "deleted"

    assert body["summary"]["total"] == len(body["secrets"])


def test_no_values_leak(client, ab):
    a, b = ab
    r = client.post("/api/compare", json={"left": {"conn_id": a, "mount": "app-config"},
                                          "right": {"conn_id": b, "mount": "app-config"}})
    assert "s3cret-A" not in r.text and "s3cret-B" not in r.text and "hunter2" not in r.text
    assert r.headers["cache-control"] == "no-store"


def test_same_vault_different_mounts(client, ab):
    _, b = ab
    _, s = compare(client, {"conn_id": b, "mount": "app-config", "prefix": "payments"},
                   {"conn_id": b, "mount": "app-config-staging", "prefix": "payments/"})
    assert set(s) == {"api", "db"}  # paths are relative to each side's prefix
    assert keys(s["db"])["host"] == "different"
    assert keys(s["api"]) == {"api_key": "different", "endpoint": "equal"}


def test_partial_access(client, ab):
    a, b = ab
    carol = connect(client, 0, method="userpass", username="carol", password="password")
    body, s = compare(client, {"conn_id": carol, "mount": "app-config"}, {"conn_id": b, "mount": "app-config"})
    assert body["left"]["denied"] == ["restricted/"]
    # hidden folder on the left: no_access, not "right_only"
    assert s["restricted/root-creds"]["status"] == "no_access"
    assert s["restricted/root-creds"]["left"]["state"] == "no_access"
    assert set(keys(s["restricted/root-creds"]).values()) == {"unknown"}
    # listable but unreadable on the left
    assert s["payments/api"]["status"] == "no_access"
    assert s["payments/db"]["status"] == "different"


def test_certs_differences(client, ab):
    a, b = ab
    _, s = compare(client, {"conn_id": a, "mount": "certs"}, {"conn_id": b, "mount": "certs"})
    assert s["ca/root"]["status"] == "equal"
    assert s["web/app"]["status"] == "different"
    assert keys(s["web/app"])["ca.crt"] == "equal" and keys(s["web/app"])["tls.crt"] == "different"
    assert s["keystores/app"]["status"] == "different"
    assert keys(s["keystores/app"])["keystore.password"] == "equal"
    assert s["web/untrusted"]["status"] == "right_only"


def test_reveal_reads_values(client, ab):
    a, _ = ab
    r = client.get(f"/api/connections/{a}/secret", params={"mount": "app-config", "path": "payments/db"})
    assert r.status_code == 200
    assert r.json()["data"]["password"] == "s3cret-A" and r.json()["version"] >= 2
    r = client.get(f"/api/connections/{a}/secret", params={"mount": "app-config", "path": "odd names/with space"})
    assert r.json()["data"] == {"k": "v"}
    r = client.get(f"/api/connections/{a}/secret", params={"mount": "app-config", "path": "retired/thing"})
    assert r.json()["state"] == "deleted" and r.json()["data"] is None
    r = client.get(f"/api/connections/{a}/secret", params={"mount": "app-config", "path": "nope"})
    assert r.status_code == 404


def test_reveal_denied(client):
    carol = connect(client, 0, method="userpass", username="carol", password="password")
    r = client.get(f"/api/connections/{carol}/secret", params={"mount": "app-config", "path": "payments/api"})
    assert r.status_code == 403
