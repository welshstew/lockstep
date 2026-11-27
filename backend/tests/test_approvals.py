"""Four-eyes approvals: a plan applied to a Vault that asks for them needs an approval from someone
whose Vault entity isn't the creator's, and that Vault's secrets change only through plans."""

import copy

import pytest

from test_sync import MOUNT, env  # noqa: F401  (fixture)

pytestmark = pytest.mark.usefixtures("vaults")


@pytest.fixture
def approvals_b(monkeypatch):
    from lockstep.config import get_settings
    monkeypatch.setattr(get_settings().preset_connections[1], "approvals", 1)


def test_four_eyes(client, env, approvals_b):  # noqa: F811
    env.a.put(f"{env.prefix}/db", {"k": "new"})
    env.b.put(f"{env.prefix}/db", {"k": "old"})
    alice_a = env.connect(0, method="userpass", username="alice", password="password")
    alice_b = env.connect(1, method="userpass", username="alice", password="password")
    bob_a = env.connect(0, method="userpass", username="bob", password="password")
    bob_b = env.connect(1, method="userpass", username="bob", password="password")
    ch = env.change(env.compare(left=alice_a, right=alice_b)["db"])

    # Direct copies to Vault B are refused, but can go into a plan
    p = env.preview([ch], left=alice_a, right=alice_b).json()[0]
    assert p["status"] == "denied" and "only through approved plans" in p["problems"][0]
    assert env.apply([ch], left=alice_a, right=alice_b).json()["summary"].get("applied", 0) == 0
    sides = {"left": {"conn_id": alice_a, "mount": MOUNT, "prefix": env.prefix},
             "right": {"conn_id": alice_b, "mount": MOUNT, "prefix": env.prefix}}
    plan = client.post("/api/plans", json=sides | {"changes": [ch]}).json()
    assert plan["right"]["entity_id"]

    as_alice = {"plan": plan, "left_conn_id": alice_a, "right_conn_id": alice_b}
    chk = client.post("/api/plans/check", json=as_alice).json()
    assert chk["status"] == "ready" and chk["approvals"] == {"required": 1, "approved_by": [], "problems": []}
    r = client.post("/api/plans/apply", json=as_alice | {"confirm": True})
    assert r.status_code == 409 and "needs an approval" in r.json()["detail"]["message"]
    r = client.post("/api/plans/approve", json=as_alice)
    assert r.status_code == 409 and "You made this plan" in r.json()["detail"]["message"]
    r = client.post("/api/plans/approve", json=as_alice | {"right_conn_id": env.cb})  # a root token: no entity
    assert r.status_code == 400 and "needs a Vault identity" in r.json()["detail"]["message"]

    # bob (read-only) checks and approves; the plan itself is unchanged
    r = client.post("/api/plans/approve", json={"plan": plan, "left_conn_id": bob_a, "right_conn_id": bob_b})
    assert r.status_code == 200, r.text
    approved = r.json()["plan"]
    assert approved["signature"] == plan["signature"] and approved["approvals"][0]["by"] == "userpass-bob"
    assert client.post("/api/plans/check", json=as_alice | {"plan": approved}).json()["approvals"]["approved_by"] == ["userpass-bob"]

    forged = copy.deepcopy(approved)
    forged["approvals"][0]["by"] = "someone-important"
    r = client.post("/api/plans/apply", json=as_alice | {"plan": forged, "confirm": True})
    assert r.status_code == 409 and "isn't valid here" in r.json()["detail"]["message"]

    out = client.post("/api/plans/apply", json=as_alice | {"plan": approved, "confirm": True}).json()
    assert out["outcome"] == "applied" and env.b.get(f"{env.prefix}/db")[0] == {"k": "new"}


def test_approval_only_vault_refuses_direct_edits(client, env, approvals_b):  # noqa: F811
    env.b.put(f"{env.prefix}/x", {"k": "v"})
    out = client.post("/api/browse/apply", json={"conn_id": env.cb, "mount": MOUNT, "confirm": True, "edits": [
        {"path": f"{env.prefix}/x", "action": "write", "expected_version": 1, "set": {"k": "w"}}]}).json()
    assert out[0]["status"] == "invalid" and "only through approved plans" in out[0]["message"]
    r = client.post("/api/destroy", json={"side": {"conn_id": env.cb, "mount": MOUNT, "prefix": env.prefix},
                                          "secrets": [{"path": "x"}], "confirm": True})
    assert r.status_code == 403
    assert env.b.get(f"{env.prefix}/x")[0] == {"k": "v"}


def test_global_setting_needs_approval_but_leaves_direct_writes(client, env, monkeypatch):  # noqa: F811
    from lockstep.config import get_settings
    monkeypatch.setattr(get_settings(), "plan_approvals", 1)
    env.a.put(f"{env.prefix}/db", {"k": "new"})
    ch = env.change(env.compare()["db"])
    plan = client.post("/api/plans", json={"left": {"conn_id": env.ca, "mount": MOUNT, "prefix": env.prefix},
                                           "right": {"conn_id": env.cb, "mount": MOUNT, "prefix": env.prefix},
                                           "changes": [ch]}).json()
    r = client.post("/api/plans/apply", json={"plan": plan, "left_conn_id": env.ca, "right_conn_id": env.cb, "confirm": True})
    assert r.status_code == 409 and "needs an approval" in r.json()["detail"]["message"]
    assert env.apply([ch]).json()["summary"]["applied"] == 1  # copies without a plan still go
