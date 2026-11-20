"""Destroying secrets (every version and the metadata) on one side."""

import json
import logging

import pytest

from test_sync import MOUNT, env  # noqa: F401  (the fixture)

pytestmark = pytest.mark.usefixtures("vaults")


def destroy(client, env, secrets, side="right", conn=None, confirm=True):
    s = {"conn_id": conn or (env.cb if side == "right" else env.ca), "mount": MOUNT, "prefix": env.prefix}
    return client.post("/api/destroy", json={"side": s, "secrets": secrets, "confirm": confirm})


def meta(raw, path):
    return raw.c.get(f"{MOUNT}/metadata/{path}")


def test_destroy_removes_every_version_and_is_audited(client, env, caplog):
    env.b.put(f"{env.prefix}/cfg", {"pw": "1"})
    env.b.put(f"{env.prefix}/cfg", {"pw": "2"})
    env.b.put(f"{env.prefix}/dir/other", {"x": "y"})
    d = env.compare()
    items = [{"path": p, "expected_version": d[p]["right"]["version"]} for p in ("cfg", "dir/other")]
    with caplog.at_level(logging.INFO, logger="lockstep.audit"):
        r = destroy(client, env, items)
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["summary"]["destroyed"] == 2
    cfg = next(x for x in out["results"] if x["path"] == "cfg")
    assert (cfg["status"], cfg["version"], cfg["versions"]) == ("destroyed", 2, 2)
    assert meta(env.b, f"{env.prefix}/cfg").status_code == 404
    assert meta(env.b, f"{env.prefix}/dir/other").status_code == 404
    logs = [json.loads(m) for m in caplog.messages if '"event": "destroy"' in m]
    assert {(x["target"]["path"], x["outcome"]) for x in logs} == {
        (f"{env.prefix}/cfg", "destroyed"), (f"{env.prefix}/dir/other", "destroyed")}
    assert all("pw" not in json.dumps(x) for x in logs)  # metadata only, never values
    assert "cfg" not in env.compare()  # gone from both sides


def test_destroy_refuses_a_secret_that_changed_since_the_compare(client, env):
    env.b.put(f"{env.prefix}/cfg", {"pw": "1"})
    seen = env.compare()["cfg"]["right"]["version"]
    env.b.put(f"{env.prefix}/cfg", {"pw": "2"})
    res = destroy(client, env, [{"path": "cfg", "expected_version": seen}]).json()["results"][0]
    assert res["status"] == "conflict" and "Compare again" in res["message"]
    assert env.b.get(f"{env.prefix}/cfg")[0] == {"pw": "2"}


def test_destroy_a_soft_deleted_secret_and_a_missing_one(client, env):
    env.b.put(f"{env.prefix}/cfg", {"pw": "1"})
    env.b.c.delete(f"{MOUNT}/data/{env.prefix}/cfg").raise_for_status()
    d = env.compare()["cfg"]
    assert d["right"]["state"] == "deleted"
    out = destroy(client, env, [{"path": "cfg", "expected_version": d["right"]["version"]},
                                {"path": "never-was"}]).json()
    assert {r["path"]: r["status"] for r in out["results"]} == {"cfg": "destroyed", "never-was": "absent"}
    assert meta(env.b, f"{env.prefix}/cfg").status_code == 404


def test_destroy_needs_permission_and_confirm(client, env):
    env.b.put(f"{env.prefix}/cfg", {"pw": "1"})
    bob = env.connect(1, method="userpass", username="bob", password="password")
    res = destroy(client, env, [{"path": "cfg"}], conn=bob).json()["results"][0]
    assert res["status"] in ("denied", "absent")  # bob may not even be allowed to read the metadata
    assert meta(env.b, f"{env.prefix}/cfg").status_code == 200
    assert destroy(client, env, [{"path": "cfg"}], confirm=False).status_code == 400
    assert meta(env.b, f"{env.prefix}/cfg").status_code == 200


@pytest.mark.parametrize("secrets", [
    [],
    [{"path": "a"}, {"path": "a"}],
    [{"path": "/a"}],
    [{"path": "dir/"}],
])
def test_destroy_validation(client, env, secrets):
    assert destroy(client, env, secrets).status_code == 422


def test_destroy_can_be_turned_off(client, env, monkeypatch):
    from lockstep.config import get_settings
    env.b.put(f"{env.prefix}/cfg", {"pw": "1"})
    monkeypatch.setattr(get_settings(), "allow_destroy", False)
    assert client.get("/api/config").json()["allow_destroy"] is False
    r = destroy(client, env, [{"path": "cfg"}])
    assert r.status_code == 403 and "LOCKSTEP_ALLOW_DESTROY" in r.text
    assert meta(env.b, f"{env.prefix}/cfg").status_code == 200
