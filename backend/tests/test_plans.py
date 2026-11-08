"""Saved sync plans: create, verify, check and apply, all or nothing."""

import copy
import json
import logging

import pytest

from test_sync import env  # noqa: F401  (fixture)

pytestmark = pytest.mark.usefixtures("vaults")


def sides(env, left=None, right=None):
    return {"left": {"conn_id": left or env.ca, "mount": "app-config", "prefix": env.prefix},
            "right": {"conn_id": right or env.cb, "mount": "app-config", "prefix": env.prefix}}


def create(client, env, changes, left=None, **extra):
    return client.post("/api/plans", json=sides(env, left=left) | {"changes": changes} | extra)


def check(client, plan, left, right):
    return client.post("/api/plans/check", json={"plan": plan, "left_conn_id": left, "right_conn_id": right})


def apply(client, plan, left, right, confirm=True):
    return client.post("/api/plans/apply", json={"plan": plan, "left_conn_id": left, "right_conn_id": right,
                                                 "confirm": confirm})


@pytest.fixture
def two_secrets(env):
    env.a.put(f"{env.prefix}/db", {"user": "app", "password": "new-pw", "same": "x"})
    env.b.put(f"{env.prefix}/db", {"user": "app", "password": "old-pw", "same": "x", "only_b": "kept"})
    env.a.put(f"{env.prefix}/api", {"token": "t-123"})
    diffs = env.compare()
    return [env.change(diffs["db"]), env.change(diffs["api"])]


def test_plan_round_trip(client, env, two_secrets):
    r = create(client, env, two_secrets, note="Rotate the db password", profile="Prod vs staging")
    assert r.status_code == 200, r.text
    plan = r.json()
    assert plan["format"] == "lockstep.sync-plan" and plan["signature"]
    assert plan["left"]["vault"] == "Vault A" and plan["left"]["preset"] and plan["left"]["identity"] == "token"
    by_path = {c["path"]: c for c in plan["changes"]}
    # Only keys that change are planned, with the versions they were at
    assert [(k["key"], k["action"]) for k in by_path["db"]["keys"]] == [("password", "update")]
    assert by_path["db"]["target_version"] == 1 and by_path["api"]["target_version"] is None
    assert "new-pw" not in json.dumps(plan) and "t-123" not in json.dumps(plan)  # never values

    assert client.post("/api/plans/verify", json={"plan": plan}).json()["plan"]["id"] == plan["id"]
    md = client.post("/api/plans/report", json={"plan": plan})
    assert md.status_code == 200 and md.headers["content-type"].startswith("text/markdown")
    assert "Rotate the db password" in md.text and f"app-config/{env.prefix}/db" in md.text and "new-pw" not in md.text

    c = check(client, plan, env.ca, env.cb).json()
    assert c["status"] == "ready" and {x["status"] for x in c["changes"]} == {"ready"}

    records: list[str] = []

    class H(logging.Handler):
        def emit(self, rec):
            records.append(rec.getMessage())

    log = logging.getLogger("lockstep.audit")
    h = H()
    log.addHandler(h)
    try:
        out = apply(client, plan, env.ca, env.cb).json()
    finally:
        log.removeHandler(h)
    assert out["summary"]["applied"] == 2 and out["plan_id"] == plan["id"]
    assert env.b.get(f"{env.prefix}/db")[0] == {"user": "app", "password": "new-pw", "same": "x", "only_b": "kept"}
    assert env.b.get(f"{env.prefix}/api")[0] == {"token": "t-123"}
    assert all(json.loads(r)["plan_id"] == plan["id"] for r in records) and len(records) == 2

    # Applied once: the targets moved on, so the same plan is now out of date
    again = apply(client, plan, env.ca, env.cb)
    assert again.status_code == 409 and "out of date" in again.json()["detail"]["message"]


@pytest.mark.parametrize("edit", [
    lambda p: p["changes"][0]["keys"].append({"key": "extra", "action": "add"}),
    lambda p: p.__setitem__("note", "edited"),
    lambda p: p["right"].__setitem__("mount", "other"),
    lambda p: p.__setitem__("signature", "0" * 64),
])
def test_edited_plan_is_refused(client, env, two_secrets, edit):
    plan = create(client, env, two_secrets).json()
    bad = copy.deepcopy(plan)
    edit(bad)
    for path in ("/api/plans/verify", "/api/plans/report"):
        r = client.post(path, json={"plan": bad})
        assert r.status_code == 400 and "changed after it was created" in r.json()["detail"]["message"]
    assert apply(client, bad, env.ca, env.cb).status_code == 400
    assert env.b.get(f"{env.prefix}/api")[0] is None


def test_not_a_plan(client):
    r = client.post("/api/plans/verify", json={"plan": {"name": "a profile"}})
    assert r.status_code == 400 and "isn't a Lockstep sync plan" in r.json()["detail"]["message"]


@pytest.mark.parametrize("who", ["target", "source"])
def test_any_change_since_the_plan_blocks_the_whole_plan(client, env, two_secrets, who):
    plan = create(client, env, two_secrets).json()
    if who == "target":
        env.b.put(f"{env.prefix}/db", {"user": "app", "password": "edited meanwhile"})
    else:
        env.a.put(f"{env.prefix}/db", {"user": "app", "password": "newer-pw", "same": "x"})

    c = check(client, plan, env.ca, env.cb).json()
    assert c["status"] == "stale" and "created again" in c["message"]
    by_path = {x["path"]: x for x in c["changes"]}
    assert by_path["db"]["status"] == "stale" and by_path["api"]["status"] == "ready"
    assert any(("target" if who == "target" else "source") + " changed" in m for m in by_path["db"]["problems"])

    r = apply(client, plan, env.ca, env.cb)
    assert r.status_code == 409
    # Nothing written, not even the secret that hadn't changed
    assert env.b.get(f"{env.prefix}/api")[0] is None


def test_read_only_user_creates_writer_applies(client, env, two_secrets):
    bob_b = env.connect(1, method="userpass", username="bob", password="password")
    bob_a = env.connect(0, method="userpass", username="bob", password="password")
    r = client.post("/api/plans", json={"left": sides(env, left=bob_a)["left"],
                                         "right": sides(env, right=bob_b)["right"], "changes": two_secrets})
    assert r.status_code == 200, r.text  # bob can't write, but can prepare a plan
    plan = r.json()
    assert plan["right"]["identity"] == "userpass-bob"

    c = check(client, plan, bob_a, bob_b).json()
    assert c["status"] == "denied" and "write access" in c["message"]
    assert apply(client, plan, bob_a, bob_b).status_code == 409

    assert apply(client, plan, env.ca, env.cb).json()["summary"]["applied"] == 2  # root can


def test_plan_needs_the_same_vaults(client, env, two_secrets):
    plan = create(client, env, two_secrets).json()
    r = check(client, plan, env.cb, env.ca)  # sides swapped
    assert r.status_code == 409 and "Connect the left side to Vault A" in r.json()["detail"]["message"]


def test_nothing_to_plan(client, env):
    env.a.put(f"{env.prefix}/same", {"k": "v"})
    env.b.put(f"{env.prefix}/same", {"k": "v"})
    env.a.put(f"{env.prefix}/diff", {"k": "a"})
    d = env.compare()
    r = create(client, env, [env.change(d["same"])])
    assert r.status_code == 400 and "Nothing to plan" in r.json()["detail"]["message"]
    # Unchanged secrets are left out of a plan that has other changes
    plan = create(client, env, [env.change(d["same"]), env.change(d["diff"])]).json()
    assert [c["path"] for c in plan["changes"]] == ["diff"]


def test_conflicting_change_cannot_be_planned(client, env):
    env.a.put(f"{env.prefix}/cfg", {"k": "A"})
    env.b.put(f"{env.prefix}/cfg", {"k": "B"})
    ch = env.change(env.compare()["cfg"])
    env.b.put(f"{env.prefix}/cfg", {"k": "edited"})
    r = create(client, env, [ch])
    assert r.status_code == 409 and "Compare again" in r.json()["detail"]["message"]
