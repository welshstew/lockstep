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


def test_namespace_picker_lists_children_and_opens_one(client):
    root = connect(client, method="token", token="root-b")
    out = client.get(f"/api/connections/{root['id']}/namespaces").json()
    assert out["supported"] and {"team-a", "team-c"} <= {n["path"] for n in out["namespaces"]}

    r = client.post(f"/api/connections/{root['id']}/namespaces", json={"namespace": "team-a"})
    assert r.status_code == 201, r.text
    a = r.json()
    assert a["namespace"] == "team-a" and a["parent"] == root["id"] and a["name"].endswith("· team-a")
    # opening it again gives the same connection
    assert client.post(f"/api/connections/{root['id']}/namespaces", json={"namespace": "team-a"}).json()["id"] == a["id"]
    # its children, listed and opened from it
    kids = client.get(f"/api/connections/{a['id']}/namespaces").json()
    assert [n["path"] for n in kids["namespaces"]] == ["team-a/apps"]
    apps = client.post(f"/api/connections/{a['id']}/namespaces", json={"namespace": "apps"}).json()
    assert apps["namespace"] == "team-a/apps" and apps["parent"] == root["id"]

    # the same path across namespaces, with one sign-in
    s = compare(client, a["id"], apps["id"])
    assert s["web/config"]["status"] == "right_only" and s["payments/api"]["status"] == "left_only"

    assert client.post(f"/api/connections/{root['id']}/namespaces", json={"namespace": "../x"}).status_code == 400
    assert client.post(f"/api/connections/{root['id']}/namespaces", json={"namespace": "no-such"}).status_code == 400

    # signing out of a namespace keeps the token; signing out of the parent closes them all
    assert client.delete(f"/api/connections/{apps['id']}").status_code == 204
    assert client.get(f"/api/connections/{root['id']}/mounts").status_code == 200
    assert client.delete(f"/api/connections/{root['id']}").status_code == 204
    assert a["id"] not in {c["id"] for c in client.get("/api/connections").json()}


def test_vault_without_namespaces_says_so(client):
    r = client.post("/api/connections", json={"preset_id": 0, "auth": {"method": "token", "token": "root-a"}})
    out = client.get(f"/api/connections/{r.json()['id']}/namespaces").json()
    assert out["supported"] is False and out["namespaces"] == []
