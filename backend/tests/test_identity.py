"""Explaining someone else's access (entity, group, token) and comparing identity groups."""

import uuid

import httpx
import pytest

pytestmark = pytest.mark.usefixtures("vaults")
MOUNT = "app-config"


@pytest.fixture
def grp(client, vaults):
    tag = uuid.uuid4().hex[:6]
    a = httpx.Client(base_url=f"{vaults[0]}/v1/", headers={"X-Vault-Token": "root-a"}, timeout=10)
    b = httpx.Client(base_url=f"{vaults[1]}/v1/", headers={"X-Vault-Token": "root-b"}, timeout=10)
    alice = a.get("identity/entity/name/alice").json()["data"]["id"]
    names = [f"g-{tag}", f"parent-{tag}"]
    try:
        child = a.post("identity/group", json={"name": names[0], "policies": ["lockstep-limited"], "member_entity_ids": [alice]}).json()["data"]["id"]
        a.post("identity/group", json={"name": names[1], "policies": ["lockstep-readonly"], "member_group_ids": [child]}).raise_for_status()
        b.post("identity/group", json={"name": names[0], "policies": ["lockstep-readonly"]}).raise_for_status()
        conns = [client.post("/api/connections", json={"preset_id": i, "auth": {"method": "token", "token": t}}).json()["id"]
                 for i, t in ((0, "root-a"), (1, "root-b"))]
        yield tag, a, conns
    finally:
        for v in (a, b):
            for n in names:
                v.delete(f"identity/group/name/{n}")


def explain(client, conn, **body):
    r = client.post("/api/policies/explain", json={"conn_id": conn, "mount": MOUNT, "prefix": "payments"} | body)
    assert r.status_code == 200, r.text
    return r.json()


def test_explain_an_entity_with_its_groups(client, grp):
    tag, _, (ca, _) = grp
    out = explain(client, ca, identity={"kind": "entity", "name": "alice"})
    names = {p["name"]: p["origin"] for p in out["policies"]}
    assert names == {"lockstep-admin": "identity", "lockstep-limited": "identity", "lockstep-readonly": "identity"}
    froms = [s["from"] for s in out["identity"]["sources"]]
    assert "entity alice" in froms and any(f"g-{tag}" in f and f"parent-{tag}" in f for f in froms)


def test_explain_a_group_and_a_token(client, grp, vaults):
    tag, a, (ca, _) = grp
    out = explain(client, ca, identity={"kind": "group", "name": f"g-{tag}"})
    assert {p["name"] for p in out["policies"]} == {"lockstep-limited", "lockstep-readonly"}
    acc = httpx.post(f"{vaults[0]}/v1/auth/userpass/login/bob", json={"password": "password"}).json()["auth"]["accessor"]
    out = explain(client, ca, identity={"kind": "token", "name": acc})
    assert {p["name"] for p in out["policies"]} >= {"lockstep-readonly", "default"}
    assert out["identity"]["label"] == "userpass-bob"
    r = client.post("/api/policies/explain", json={"conn_id": ca, "mount": MOUNT, "identity": {"kind": "group", "name": "no-such"}})
    assert r.status_code == 404


def test_missing_rights_are_named(client, grp):
    carol = client.post("/api/connections", json={"preset_id": 0, "auth": {"method": "userpass", "username": "carol", "password": "password"}}).json()["id"]
    out = explain(client, carol, identity={"kind": "entity", "name": "alice"})
    assert any("identity/entity/name/alice" in m for m in out["missing"])


def test_groups_list_compare_and_granting(client, grp):
    tag, _, (ca, cb) = grp
    gs = {g["name"]: g for g in client.get("/api/identity/groups", params={"conn_id": ca}).json()["groups"]}
    assert gs[f"g-{tag}"]["members"] == ["alice"] and gs[f"g-{tag}"]["policies"] == ["lockstep-limited"]
    assert gs[f"parent-{tag}"]["member_groups"] == 1
    out = client.post("/api/identity/compare-groups", json={"left": ca, "right": cb}).json()
    pairs = {(p["left"], p["right"]): p for p in out["pairs"]}
    diff = pairs[(f"g-{tag}", f"g-{tag}")]
    assert diff["status"] == "different" and {f["field"] for f in diff["fields"]} == {"policies", "members"}
    assert pairs[(f"parent-{tag}", None)]["status"] == "left_only"
    g = client.get("/api/roles/granting", params={"conn_id": ca, "policy": "lockstep-limited"}).json()
    assert f"g-{tag}" in g["groups"]
