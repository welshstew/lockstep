"""Namespaces: a connection signs in to a namespace and everything it does stays there, so two
sides can be two namespaces. Needs a Vault B with namespaces: OpenBao (make test-openbao), or
Vault Enterprise. The seed gives Vault B team-a, team-a/apps and team-c."""

import pytest

from conftest import has_namespaces_b

pytestmark = [pytest.mark.usefixtures("vaults"),
              pytest.mark.skipif(not has_namespaces_b(), reason="Vault B has no namespaces (run make test-openbao)")]


def connect(client, namespace=None, **auth):
    auth.setdefault("method", "userpass")
    if auth["method"] == "userpass":
        auth.setdefault("username", "alice")
        auth.setdefault("password", "password")
    r = client.post("/api/connections", json={"preset_id": 1, "auth": auth, **({"namespace": namespace} if namespace else {})})
    assert r.status_code == 201, r.text
    return r.json()


def compare(client, left, right, mount="app-config"):
    r = client.post("/api/compare", json={"left": {"conn_id": left, "mount": mount}, "right": {"conn_id": right, "mount": mount}})
    assert r.status_code == 200, r.text
    return {s["path"]: s for s in r.json()["secrets"]}


def test_sign_in_to_a_namespace(client):
    conn = connect(client, "team-a")
    assert conn["namespace"] == "team-a" and "ns-admin" in conn["policies"]
    mounts = client.get(f"/api/connections/{conn['id']}/mounts").json()
    assert "app-config" in {m["path"].strip("/") for m in mounts["mounts"]}


def test_compare_two_namespaces(client):
    a, c = connect(client, "team-a")["id"], connect(client, "team-c")["id"]
    s = compare(client, a, c)
    assert s["payments/db"]["status"] == "left_only" and s["service/config"]["status"] == "right_only"


def test_compare_a_namespace_with_its_child(client):
    # The root token, working in a namespace below it, against a user signed in to the parent
    apps = connect(client, "team-a/apps", method="token", token="root-b")["id"]
    parent = connect(client, "team-a")["id"]
    s = compare(client, parent, apps)
    assert s["web/config"]["status"] == "right_only" and s["payments/api"]["status"] == "left_only"


def test_a_user_is_only_in_their_namespace(client):
    r = client.post("/api/connections", json={"preset_id": 1, "namespace": "team-c",
                                              "auth": {"method": "userpass", "username": "carol", "password": "password"}})
    assert r.status_code in (400, 401, 403), r.text  # carol exists at the root only


def test_configuration_across_namespaces(client):
    a, c = connect(client, "team-a")["id"], connect(client, "team-c")["id"]
    out = client.post("/api/config/compare", json={"left": a, "right": c}).json()
    mounts = {p["path"]: p for p in out["mounts"]}
    assert mounts["app-config/"]["status"] == "different"  # the description names the namespace
    assert [f["field"] for f in mounts["app-config/"]["fields"]] == ["description"]
    assert out["overview"]["left"]["product"] == "OpenBao"
