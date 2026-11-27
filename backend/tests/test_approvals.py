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
    assert chk["status"] == "ready" and chk["approvals"] == {"required": 1, "approved_by": [], "problems": [], "approver_policies": []}
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


def test_two_approvers_holding_an_approver_policy(client, env, monkeypatch):  # noqa: F811
    """Two approvals from different people, each holding an approver policy; one person counts once."""
    from lockstep.config import get_settings
    preset = get_settings().preset_connections[1]
    monkeypatch.setattr(preset, "approvals", 2)
    monkeypatch.setattr(preset, "approver_policies", ["lockstep-readonly", "lockstep-limited"])
    env.a.put(f"{env.prefix}/db", {"k": "new"})
    env.b.put(f"{env.prefix}/db", {"k": "old"})
    alice = [env.connect(i, method="userpass", username="alice", password="password") for i in (0, 1)]
    bob = [None, env.connect(1, method="userpass", username="bob", password="password")]  # the plan writes Vault B only
    carol = [None, env.connect(1, method="userpass", username="carol", password="password")]  # the plan writes Vault B only
    ch = env.change(env.compare(left=alice[0], right=alice[1])["db"])
    sides = {"left": {"conn_id": alice[0], "mount": MOUNT, "prefix": env.prefix},
             "right": {"conn_id": alice[1], "mount": MOUNT, "prefix": env.prefix}}
    plan = client.post("/api/plans", json=sides | {"changes": [ch]}).json()

    def as_(who, p):  # everyone reads Vault A through alice's sign-in
        return {"plan": p, "left_conn_id": alice[0], "right_conn_id": who[1]}

    chk = client.post("/api/plans/check", json=as_(alice, plan)).json()["approvals"]
    assert chk["required"] == 2 and chk["approver_policies"] == ["lockstep-limited", "lockstep-readonly"]

    r = client.post("/api/plans/approve", json=as_(bob, plan))
    assert r.status_code == 200, r.text
    one = r.json()["plan"]
    assert one["approvals"][0]["policies"]["right"] == ["default", "lockstep-readonly"]
    r = client.post("/api/plans/approve", json=as_(bob, one))
    assert r.status_code == 409 and "approved this plan already" in r.json()["detail"]["message"]
    r = client.post("/api/plans/apply", json=as_(alice, one) | {"confirm": True})
    assert r.status_code == 409 and "2 approvals from different people" in r.json()["detail"]["message"]
    # A repeated approval by the same person (made elsewhere) still counts once
    twice = copy.deepcopy(one)
    twice["approvals"].append(copy.deepcopy(one["approvals"][0]))
    assert client.post("/api/plans/check", json=as_(alice, twice)).json()["approvals"]["approved_by"] == ["userpass-bob"]

    r = client.post("/api/plans/approve", json=as_(carol, one))
    assert r.status_code == 200, r.text
    both = r.json()["plan"]
    chk = client.post("/api/plans/check", json=as_(alice, both)).json()["approvals"]
    assert chk["approved_by"] == ["userpass-bob", "userpass-carol"]
    out = client.post("/api/plans/apply", json=as_(alice, both) | {"confirm": True}).json()
    assert out["outcome"] == "applied" and env.b.get(f"{env.prefix}/db")[0] == {"k": "new"}


def test_approver_policy_is_required_and_recorded(client, env, monkeypatch):  # noqa: F811
    from lockstep.config import get_settings
    monkeypatch.setattr(get_settings(), "plan_approvals", 1)
    monkeypatch.setattr(get_settings(), "plan_approver_policies", ["lockstep-readonly"])
    env.a.put(f"{env.prefix}/db", {"k": "new"})
    env.b.put(f"{env.prefix}/db", {"k": "old"})
    alice = [env.connect(i, method="userpass", username="alice", password="password") for i in (0, 1)]
    carol = [None, env.connect(1, method="userpass", username="carol", password="password")]  # the plan writes Vault B only
    bob = [None, env.connect(1, method="userpass", username="bob", password="password")]  # the plan writes Vault B only
    ch = env.change(env.compare(left=alice[0], right=alice[1])["db"])
    plan = client.post("/api/plans", json={"left": {"conn_id": alice[0], "mount": MOUNT, "prefix": env.prefix},
                                           "right": {"conn_id": alice[1], "mount": MOUNT, "prefix": env.prefix},
                                           "changes": [ch]}).json()

    def as_(who, p):  # everyone reads Vault A through alice's sign-in
        return {"plan": p, "left_conn_id": alice[0], "right_conn_id": who[1]}

    r = client.post("/api/plans/approve", json=as_(carol, plan))
    assert r.status_code == 403 and "needs one of the Vault policies lockstep-readonly" in r.json()["detail"]["message"]

    # An approval given where no policy was required records none: it doesn't count where one is
    monkeypatch.setattr(get_settings(), "plan_approver_policies", [])
    loose = client.post("/api/plans/approve", json=as_(carol, plan)).json()["plan"]
    assert not loose["approvals"][0].get("policies")
    monkeypatch.setattr(get_settings(), "plan_approver_policies", ["lockstep-readonly"])
    chk = client.post("/api/plans/check", json=as_(alice, loose)).json()["approvals"]
    assert chk["approved_by"] == [] and "didn't hold one" in chk["problems"][0]

    ok = client.post("/api/plans/approve", json=as_(bob, plan)).json()["plan"]
    edited = copy.deepcopy(ok)
    edited["approvals"][0]["policies"]["right"] = ["lockstep-admin"]
    chk = client.post("/api/plans/check", json=as_(alice, edited)).json()["approvals"]
    assert chk["approved_by"] == [] and "isn't valid here" in chk["problems"][0]  # the policies are signed
    out = client.post("/api/plans/apply", json=as_(alice, ok) | {"confirm": True}).json()
    assert out["outcome"] == "applied"


POLICY = 'path "lockstep-approval-test/*" { capabilities = ["read"] }'


def test_access_plans_take_approvals(client, env, approvals_b):  # noqa: F811
    """On a Vault that changes only through approved plans, policy writes go through approved access
    plans too: the Policies tab's direct writes are refused (but can be saved as a plan)."""
    name = f"lockstep-approval-{env.prefix}"
    alice_b = env.connect(1, method="userpass", username="alice", password="password")
    bob_b = env.connect(1, method="userpass", username="bob", password="password")
    changes = {"conn_id": alice_b, "policies": [{"name": name, "text": POLICY}]}
    try:
        prev = client.post("/api/access/preview", json=changes).json()
        assert prev[0]["status"] == "denied" and "only through approved access plans" in prev[0]["problems"][-1]
        out = client.post("/api/access/apply", json=changes | {"expected": {i["id"]: i["hash"] for i in prev},
                                                               "confirm": True}).json()
        assert out[0]["status"] == "denied" and env.b.c.get(f"sys/policies/acl/{name}").status_code == 404

        plan = client.post("/api/access/plans", json=changes).json()
        as_alice = {"conn_ids": [alice_b], "plan": plan}
        chk = client.post("/api/access/plans/check", json=as_alice).json()
        assert chk["items"][0]["status"] == "ready" and chk["approvals"] == {"required": 1, "approved_by": [], "problems": [], "approver_policies": []}
        r = client.post("/api/access/plans/apply", json=as_alice | {"confirm": True})
        assert r.status_code == 409 and "needs an approval" in r.json()["detail"]["message"]
        r = client.post("/api/access/plans/approve", json=as_alice)
        assert r.status_code == 409 and "You made this plan" in r.json()["detail"]["message"]

        r = client.post("/api/access/plans/approve", json={"conn_ids": [bob_b], "plan": plan})  # bob can't write: fine
        assert r.status_code == 200, r.text
        approved = r.json()
        assert approved["signature"] == plan["signature"] and approved["approvals"][0]["by"] == "userpass-bob"
        forged = copy.deepcopy(approved)
        forged["approvals"][0]["entities"]["vault"] = "someone-else"
        r = client.post("/api/access/plans/apply", json=as_alice | {"plan": forged, "confirm": True})
        assert r.status_code == 409 and "isn't valid here" in r.json()["detail"]["message"]

        out = client.post("/api/access/plans/apply", json=as_alice | {"plan": approved, "confirm": True}).json()
        assert out[0]["status"] == "applied", out
        assert env.b.c.get(f"sys/policies/acl/{name}").status_code == 200
    finally:
        env.b.c.delete(f"sys/policies/acl/{name}")


def test_undo_plans_take_approvals(client, env, monkeypatch):  # noqa: F811
    from lockstep.config import get_settings
    from test_undo import writes
    monkeypatch.setattr(get_settings(), "plan_approvals", 1)
    env.a.put(f"{env.prefix}/db", {"k": "new"})
    env.b.put(f"{env.prefix}/db", {"k": "old"})
    alice_a = env.connect(0, method="userpass", username="alice", password="password")
    alice_b = env.connect(1, method="userpass", username="alice", password="password")
    bob_b = env.connect(1, method="userpass", username="bob", password="password")
    res = env.apply([env.change(env.compare(left=alice_a, right=alice_b)["db"])], left=alice_a, right=alice_b).json()
    assert res["summary"]["applied"] == 1  # the global setting leaves direct copies alone
    plan = client.post("/api/undo", json={"writes": writes(res["results"])}).json()
    as_alice = {"plan": plan, "conn_ids": [alice_a, alice_b]}
    assert client.post("/api/undo/check", json=as_alice).json()["approvals"]["required"] == 1
    r = client.post("/api/undo/apply", json=as_alice | {"confirm": True})
    assert r.status_code == 409 and "needs an approval" in r.json()["detail"]["message"]
    r = client.post("/api/undo/approve", json=as_alice)
    assert r.status_code == 409 and "You made this plan" in r.json()["detail"]["message"]
    r = client.post("/api/undo/approve", json={"plan": plan, "conn_ids": [bob_b]})
    assert r.status_code == 200, r.text
    approved = r.json()
    assert approved["signature"] == plan["signature"]
    assert client.post("/api/undo/check", json=as_alice | {"plan": approved}).json()["approvals"]["approved_by"] == ["userpass-bob"]
    out = client.post("/api/undo/apply", json=as_alice | {"plan": approved, "confirm": True}).json()
    assert out["outcome"] == "applied" and env.b.get(f"{env.prefix}/db")[0] == {"k": "old"}
