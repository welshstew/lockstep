"""Undo plans: put back what an apply changed, reading the old versions from Vault's history."""

import copy

import pytest

from test_sync import env  # noqa: F401  (fixture)

pytestmark = pytest.mark.usefixtures("vaults")


def writes(results):
    return [{"conn_id": r["target_conn_id"], "mount": r["target_mount"], "path": r["target_path"], "action": r["action"],
             "old_version": r["old_version"], "new_version": r["new_version"]} for r in results if r["status"] == "applied"]


@pytest.fixture
def applied(client, env):  # noqa: F811
    env.a.put(f"{env.prefix}/db", {"user": "app", "password": "new"})
    env.b.put(f"{env.prefix}/db", {"user": "app", "password": "old", "only_b": "x"})
    env.a.put(f"{env.prefix}/fresh", {"k": "v"})
    d = env.compare()
    res = env.apply([env.change(d["db"]), env.change(d["fresh"])]).json()
    assert res["summary"]["applied"] == 2, res
    assert env.b.get(f"{env.prefix}/db")[0]["password"] == "new"
    return res["results"]


def test_undo_puts_old_versions_back(client, env, applied):  # noqa: F811
    r0 = next(r for r in applied if r["path"] == "db")
    assert r0["target_conn_id"] == env.cb and r0["target_mount"] == "app-config" and r0["target_path"] == f"{env.prefix}/db"
    r = client.post("/api/undo", json={"writes": writes(applied)})
    assert r.status_code == 200, r.text
    plan = r.json()
    assert plan["format"] == "lockstep.undo-plan" and "old" not in str(plan["entries"])  # no values
    assert sorted(e["action"] for e in plan["entries"]) == ["delete", "restore"]
    body = {"plan": plan, "conn_ids": [env.ca, env.cb]}
    chk = client.post("/api/undo/check", json=body).json()
    assert chk["status"] == "ready", chk

    bad = copy.deepcopy(plan)
    bad["entries"][0]["restore_version"] = 99
    assert client.post("/api/undo/check", json=body | {"plan": bad}).status_code == 400

    out = client.post("/api/undo/apply", json=body | {"confirm": True}).json()
    assert out["outcome"] == "applied", out
    data, version = env.b.get(f"{env.prefix}/db")
    assert data == {"user": "app", "password": "old", "only_b": "x"} and version == 3  # v1 written back as v3
    assert env.b.get(f"{env.prefix}/fresh")[0] is None  # created by the apply: soft-deleted
    # Applying it again: the secrets have moved on, so nothing happens
    again = client.post("/api/undo/apply", json=body | {"confirm": True})
    assert again.status_code == 409 and "changed since the apply" in again.json()["detail"]["message"]


def test_undo_refuses_when_someone_wrote_since(client, env, applied):  # noqa: F811
    plan = client.post("/api/undo", json={"writes": writes(applied)}).json()
    env.b.put(f"{env.prefix}/db", {"user": "app", "password": "someone-else"})
    chk = client.post("/api/undo/check", json={"plan": plan, "conn_ids": [env.cb]}).json()
    assert chk["status"] == "stale" and any("someone else's change" in e["message"] for e in chk["entries"])
    assert client.post("/api/undo/apply", json={"plan": plan, "conn_ids": [env.cb], "confirm": True}).status_code == 409
    assert env.b.get(f"{env.prefix}/db")[0]["password"] == "someone-else"


def test_undo_needs_the_old_version(client, env, applied):  # noqa: F811
    env.b.c.put(f"app-config/destroy/{env.prefix}/db", json={"versions": [1]}).raise_for_status()
    r = client.post("/api/undo", json={"writes": writes(applied)})
    assert r.status_code == 409 and "v1 has been destroyed" in r.json()["detail"]["message"]


def test_undo_needs_the_vault_signed_in(client, env, applied):  # noqa: F811
    plan = client.post("/api/undo", json={"writes": writes(applied)}).json()
    r = client.post("/api/undo/check", json={"plan": plan, "conn_ids": [env.ca]})
    assert r.status_code == 409 and "sign in to it" in r.json()["detail"]["message"]
