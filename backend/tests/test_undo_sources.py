"""Undo plans for Browse edits and imports: the UI turns their results into undo input
(frontend/src/plans.ts browseUndoWrites / downloadUndoPlan); these tests do the same."""

import pytest

from test_exports import env  # noqa: F401  (fixture)
from test_undo import writes

pytestmark = pytest.mark.usefixtures("vaults")
MOUNT = "app-config"


def browse_writes(conn_id, results):
    """What browseUndoWrites sends: writes and rollbacks, and a soft-delete of the latest version."""
    out = []
    for r in results:
        if r["status"] != "applied":
            continue
        if r["action"] in ("write", "rollback") and r["new_version"]:
            out.append({"conn_id": conn_id, "mount": MOUNT, "path": r["path"], "action": "write",
                        "old_version": r["old_version"], "new_version": r["new_version"]})
        elif r["action"] == "delete" and r["old_version"] and r["versions"] == [r["old_version"]]:
            out.append({"conn_id": conn_id, "mount": MOUNT, "path": r["path"], "action": "delete",
                        "old_version": r["old_version"], "new_version": None})
    return out


def undo(client, conn_ids, ws):
    plan = client.post("/api/undo", json={"writes": ws})
    assert plan.status_code == 200, plan.text
    out = client.post("/api/undo/apply", json={"plan": plan.json(), "conn_ids": conn_ids, "confirm": True}).json()
    assert out["outcome"] == "applied", out
    return plan.json()


def test_undo_browse_edits(client, env):  # noqa: F811
    env.b.put(f"{env.prefix}/edited", {"k": "old"})
    env.b.put(f"{env.prefix}/gone", {"k": "v"})
    res = client.post("/api/browse/apply", json={"conn_id": env.cb, "mount": MOUNT, "confirm": True, "edits": [
        {"path": f"{env.prefix}/edited", "action": "write", "expected_version": 1, "set": {"k": "new"}},
        {"path": f"{env.prefix}/created", "action": "write", "set": {"k": "v"}},
        {"path": f"{env.prefix}/gone", "action": "delete", "expected_version": 1}]}).json()
    assert [r["status"] for r in res] == ["applied"] * 3
    ws = browse_writes(env.cb, res)
    assert [w["action"] for w in ws] == ["write", "write", "delete"]
    # An undelete or a destroy isn't offered: there's nothing to put back
    assert browse_writes(env.cb, [{"status": "applied", "action": "undelete", "path": "x", "old_version": 1,
                                   "new_version": None, "versions": [1]}]) == []
    plan = undo(client, [env.cb], ws)
    assert sorted(e["action"] for e in plan["entries"]) == ["delete", "restore", "undelete"]
    assert env.b.get(f"{env.prefix}/edited")[0] == {"k": "old"}
    assert env.b.get(f"{env.prefix}/created")[0] is None  # created by the edit: soft-deleted
    assert env.b.get(f"{env.prefix}/gone")[0] == {"k": "v"}  # undeleted


def test_undo_an_import(client, env):  # noqa: F811
    env.a.put(f"{env.prefix}/app", {"k": "from-file"})
    env.b.put(f"{env.prefix}/app", {"k": "target", "extra": "x"})
    env.b.put(f"{env.prefix}/stale", {"s": "1"})
    body = {"export": env.export()["file"], "name": "a.json", "target": env.side_b, "delete_missing": True}
    pv = client.post("/api/import/preview", json=body).json()
    expected = {p["path"]: p["target"]["version"] for p in pv["plans"] if p["status"] == "ready"}
    out = client.post("/api/import/apply", json=body | {"expected": expected, "confirm": True}).json()
    assert out["summary"]["applied"] == 2 and env.b.get(f"{env.prefix}/stale")[0] is None
    assert all(r["target_conn_id"] == env.cb for r in out["results"])
    undo(client, [env.cb], writes(out["results"]))
    assert env.b.get(f"{env.prefix}/app")[0] == {"k": "target", "extra": "x"}
    assert env.b.get(f"{env.prefix}/stale")[0] == {"s": "1"}
