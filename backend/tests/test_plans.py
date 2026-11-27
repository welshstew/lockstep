"""Saved sync plans: create, verify, check and apply. The check is all or nothing; applying stops at
the first secret that isn't written."""

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


@pytest.mark.parametrize("moved", [0, 1])
def test_source_moving_during_apply_stops_the_plan(client, env, two_secrets, monkeypatch, moved):
    """Between the plan's check and a write, a source that moves is a conflict for that secret, and
    applying stops there: what was reviewed is what gets written, and nothing after it is tried."""
    import lockstep.api.plans as plans
    plan = create(client, env, two_secrets).json()
    order = [c["path"] for c in plan["changes"]]
    newer = {"db": {"user": "app", "password": "racing-pw", "same": "x"}, "api": {"token": "t-racing"}}
    before = {p: env.b.get(f"{env.prefix}/{p}")[0] for p in order}
    real_check = plans._check

    async def check_then_move(*a, **k):
        out = await real_check(*a, **k)
        env.a.put(f"{env.prefix}/{order[moved]}", newer[order[moved]])  # someone edits the source meanwhile
        return out

    monkeypatch.setattr(plans, "_check", check_then_move)
    out = apply(client, plan, env.ca, env.cb).json()
    by = {r["path"]: r for r in out["results"]}
    assert out["stopped"] is True
    assert by[order[moved]]["status"] == "conflict" and "source changed since the plan" in by[order[moved]]["message"]
    assert env.b.get(f"{env.prefix}/{order[moved]}")[0] == before[order[moved]]  # the newer source wasn't copied
    if moved == 0:
        assert out["outcome"] == "not_applied" and by[order[1]]["status"] == "skipped"
        assert env.b.get(f"{env.prefix}/{order[1]}")[0] == before[order[1]]  # not attempted
        assert out["message"].startswith("Not applied: 0 of 2")
    else:
        assert out["outcome"] == "partially_applied" and by[order[0]]["status"] == "applied"
        assert out["message"].startswith("Partially applied: 1 of 2") and order[1] in out["message"]
    assert out["summary"]["skipped"] == (1 if moved == 0 else 0)


def test_applied_plan_reports_its_outcome(client, env, two_secrets):
    out = apply(client, create(client, env, two_secrets).json(), env.ca, env.cb).json()
    assert out["outcome"] == "applied" and out["stopped"] is False and out["message"] == "Plan applied: 2 of 2 secret(s) written."


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


def test_plan_with_typed_values_and_removals(client, env, two_secrets):
    """Typed values stay out of the plan file: it keeps a check code, and whoever applies the plan
    types them again. A value that doesn't match the creator's is refused."""
    db = two_secrets[0] | {"keys": [], "set": {"password": "typed-pw"}, "remove": ["only_b"]}
    r = create(client, env, [db, two_secrets[1]])
    assert r.status_code == 200, r.text
    plan = r.json()
    assert plan["holds_values"] is False and "typed-pw" not in json.dumps(plan) and "t-123" not in json.dumps(plan)
    i = [c["path"] for c in plan["changes"]].index("db")
    by_path = {c["path"]: c for c in plan["changes"]}
    assert [(k["key"], k["action"], k["override"]) for k in by_path["db"]["keys"]] == [
        ("password", "update", True), ("only_b", "remove", False)]
    assert by_path["db"]["set"] is None and set(by_path["db"]["typed"]) == {"password"}

    md = client.post("/api/plans/report", json={"plan": plan}).text
    assert "update (typed)" in md and "types them again" in md and "typed-pw" not in md

    # Editing a check code breaks the signature
    edited = copy.deepcopy(plan)
    edited["changes"][i]["typed"]["password"] = "0" * 32
    assert check(client, edited, env.ca, env.cb).status_code == 400

    # Checking works without the values; the source moving doesn't matter to a change that copies nothing
    env.a.put(f"{env.prefix}/db", {"user": "app", "password": "moved-on", "same": "x"})
    assert check(client, plan, env.ca, env.cb).json()["status"] == "ready"
    missing = apply(client, plan, env.ca, env.cb)
    assert missing.status_code == 400 and missing.json()["detail"]["typed"] == "missing"
    body = {"plan": plan, "left_conn_id": env.ca, "right_conn_id": env.cb, "confirm": True}
    wrong = client.post("/api/plans/apply", json=body | {"values": {str(i): {"password": "typed-pq"}}})
    assert wrong.status_code == 400 and "don't match" in wrong.json()["detail"]["message"]
    assert check(client, plan, env.ca, env.cb).status_code == 200
    assert client.post("/api/plans/check", json={k: body[k] for k in ("plan", "left_conn_id", "right_conn_id")}
                       | {"values": {str(i): {"password": "nope"}}}).status_code == 400
    assert env.b.get(f"{env.prefix}/db")[0]["password"] == "old-pw"  # nothing written
    out = client.post("/api/plans/apply", json=body | {"values": {str(i): {"password": "typed-pw"}}})
    assert out.status_code == 200, out.text
    assert env.b.get(f"{env.prefix}/db")[0] == {"user": "app", "password": "typed-pw", "same": "x"}
    assert env.b.get(f"{env.prefix}/api")[0] == {"token": "t-123"}


def test_older_plan_holding_typed_values_still_applies(client, env, two_secrets):
    from lockstep.api.plans import Plan, sign
    from lockstep.config import get_settings
    db = two_secrets[0] | {"keys": [], "set": {"password": "typed-pw"}}
    plan = create(client, env, [db]).json()
    old = copy.deepcopy(plan)
    old["changes"][0]["set"], old["changes"][0]["typed"], old["holds_values"] = {"password": "typed-pw"}, None, True
    old = sign(Plan.model_validate(old), get_settings()).model_dump(mode="json")
    out = apply(client, old, env.ca, env.cb)
    assert out.status_code == 200, out.text
    assert env.b.get(f"{env.prefix}/db")[0]["password"] == "typed-pw"


def test_typed_value_as_json_matches():
    from lockstep.api.plans import match_typed, typed_check
    from lockstep.config import Settings
    s = Settings(session_key="k" * 32)
    code = typed_check(s, "plan", "app/db", "port", 5432)
    assert match_typed(s, "plan", "app/db", "port", code, "5432") == (True, 5432)  # typed as text, written as a number
    assert match_typed(s, "plan", "app/db", "port", code, "5433")[0] is False
    assert match_typed(s, "other-plan", "app/db", "port", code, 5432)[0] is False  # bound to the plan
