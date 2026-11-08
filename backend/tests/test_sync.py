"""Sync (copy) integration tests. Each test works in its own random prefix."""

import json
import logging
import uuid

import httpx
import pytest

pytestmark = pytest.mark.usefixtures("vaults")
MOUNT = "app-config"


class Raw:
    """Direct root access to a dev Vault, for setting up and checking data."""

    def __init__(self, addr: str, token: str):
        self.c = httpx.Client(base_url=f"{addr}/v1/", headers={"X-Vault-Token": token}, timeout=10)

    def put(self, path: str, data: dict) -> int:
        r = self.c.post(f"{MOUNT}/data/{path}", json={"data": data})
        r.raise_for_status()
        return r.json()["data"]["version"]

    def purge(self, prefix: str) -> None:
        """Permanently delete everything under prefix (test cleanup)."""
        r = self.c.request("LIST", f"{MOUNT}/metadata/{prefix}/")
        if r.status_code == 404:
            return
        for k in r.json()["data"]["keys"]:
            if k.endswith("/"):
                self.purge(f"{prefix}/{k.rstrip('/')}")
            else:
                self.c.delete(f"{MOUNT}/metadata/{prefix}/{k}").raise_for_status()

    def get(self, path: str) -> tuple[dict | None, int | None]:
        r = self.c.get(f"{MOUNT}/data/{path}")
        if r.status_code == 404:
            return None, None
        r.raise_for_status()
        d = r.json()["data"]
        return d["data"], d["metadata"]["version"]


@pytest.fixture
def env(client, vaults):
    prefix = f"synctest-{uuid.uuid4().hex[:8]}"
    a, b = Raw(vaults[0], "root-a"), Raw(vaults[1], "root-b")

    def connect(preset, **auth):
        auth.setdefault("method", "token")
        r = client.post("/api/connections", json={"preset_id": preset, "auth": auth})
        assert r.status_code == 201, r.text
        return r.json()["id"]

    ca, cb = connect(0, token="root-a"), connect(1, token="root-b")

    class E:
        pass

    e = E()
    e.prefix, e.a, e.b, e.ca, e.cb, e.connect = prefix, a, b, ca, cb, connect

    def sides(left=None, right=None):
        return {"left": {"conn_id": left or ca, "mount": MOUNT, "prefix": prefix},
                "right": {"conn_id": right or cb, "mount": MOUNT, "prefix": prefix}}

    def compare(**kw):
        r = client.post("/api/compare", json=sides(**kw))
        assert r.status_code == 200, r.text
        return {s["path"]: s for s in r.json()["secrets"]}

    def change(diff, direction="left_to_right", keys=None):
        src, tgt = ("left", "right") if direction == "left_to_right" else ("right", "left")
        return {"path": diff["path"], "direction": direction, "keys": keys,
                "expected_target_version": diff[tgt]["version"] if diff[tgt]["state"] in ("present", "deleted") else None,
                "expected_source_version": diff[src]["version"]}

    def preview(changes, reveal=False, **kw):
        r = client.post("/api/sync/preview", json=sides(**kw) | {"changes": changes, "reveal": reveal})
        return r

    def apply(changes, confirm=True, **kw):
        return client.post("/api/sync/apply", json=sides(**kw) | {"changes": changes, "confirm": confirm})

    e.compare, e.change, e.preview, e.apply = compare, change, preview, apply
    yield e
    a.purge(prefix)
    b.purge(prefix)


def test_copy_one_key_keeps_target_only_keys(env):
    env.a.put(f"{env.prefix}/cfg", {"k1": "from-A", "k2": "same"})
    env.b.put(f"{env.prefix}/cfg", {"k1": "from-B", "k2": "same", "only_b": "keep me"})
    d = env.compare()["cfg"]
    ch = env.change(d, keys=["k1"])

    p = env.preview([ch]).json()[0]
    assert p["status"] == "ready" and p["can_write"]
    assert [(k["key"], k["action"]) for k in p["keys"]] == [("k1", "update")]
    assert p["keys"][0]["source_value"] is None  # no values without reveal

    r = env.apply([ch]).json()
    assert r["summary"]["applied"] == 1
    res = r["results"][0]
    assert res["keys"] == ["k1"] and res["new_version"] == res["old_version"] + 1
    data, _ = env.b.get(f"{env.prefix}/cfg")
    assert data == {"k1": "from-A", "k2": "same", "only_b": "keep me"}


def test_whole_secret_creates_missing_target_and_keeps_types(env):
    env.b.put(f"{env.prefix}/new/thing", {"port": 5432, "flags": {"x": True}, "name": "svc"})
    d = env.compare()["new/thing"]
    assert d["status"] == "right_only"
    ch = env.change(d, direction="right_to_left")
    assert ch["expected_target_version"] is None

    p = env.preview([ch]).json()[0]
    assert p["status"] == "ready" and {k["action"] for k in p["keys"]} == {"add"}
    assert env.apply([ch]).json()["summary"]["applied"] == 1
    data, version = env.a.get(f"{env.prefix}/new/thing")
    assert data == {"port": 5432, "flags": {"x": True}, "name": "svc"} and version == 1
    assert isinstance(data["port"], int)


def test_target_changed_since_compare_is_a_conflict(env):
    env.a.put(f"{env.prefix}/cfg", {"k": "A"})
    env.b.put(f"{env.prefix}/cfg", {"k": "B"})
    ch = env.change(env.compare()["cfg"])
    env.b.put(f"{env.prefix}/cfg", {"k": "someone else edited this"})

    assert env.preview([ch]).json()[0]["status"] == "conflict"
    r = env.apply([ch]).json()["results"][0]
    assert r["status"] == "conflict" and r["new_version"] is None
    assert env.b.get(f"{env.prefix}/cfg")[0] == {"k": "someone else edited this"}


def test_target_created_since_compare_is_a_conflict(env):
    env.a.put(f"{env.prefix}/cfg", {"k": "A"})
    ch = env.change(env.compare()["cfg"])
    env.b.put(f"{env.prefix}/cfg", {"k": "created meanwhile"})
    assert env.apply([ch]).json()["results"][0]["status"] == "conflict"
    assert env.b.get(f"{env.prefix}/cfg")[0] == {"k": "created meanwhile"}


def test_source_is_reread_at_apply_time(env):
    env.a.put(f"{env.prefix}/cfg", {"k": "old"})
    env.b.put(f"{env.prefix}/cfg", {"k": "B"})
    ch = env.change(env.compare()["cfg"])
    env.a.put(f"{env.prefix}/cfg", {"k": "newer"})

    p = env.preview([ch]).json()[0]
    assert p["status"] == "ready" and any("source changed" in w for w in p["warnings"])
    assert env.apply([ch]).json()["summary"]["applied"] == 1
    assert env.b.get(f"{env.prefix}/cfg")[0] == {"k": "newer"}


def test_read_only_target_is_denied(env):
    env.a.put(f"{env.prefix}/cfg", {"k": "A"})
    env.b.put(f"{env.prefix}/cfg", {"k": "B"})
    bob = env.connect(1, method="userpass", username="bob", password="password")
    ch = env.change(env.compare(right=bob)["cfg"])

    p = env.preview([ch], right=bob).json()[0]
    assert p["status"] == "denied" and not p["can_write"]
    assert env.apply([ch], right=bob).json()["results"][0]["status"] == "denied"
    assert env.b.get(f"{env.prefix}/cfg")[0] == {"k": "B"}


def test_invalid_and_noop(env):
    env.a.put(f"{env.prefix}/cfg", {"k": "same", "x": "1"})
    env.b.put(f"{env.prefix}/cfg", {"k": "same"})
    d = env.compare()["cfg"]
    bad = env.change(d, keys=["nope"])
    same = env.change(d, keys=["k"])
    assert env.preview([bad]).json()[0]["status"] == "invalid"
    assert env.preview([same]).json()[0]["status"] == "noop"
    r = env.apply([same]).json()
    assert r["results"][0]["status"] == "noop" and r["results"][0]["new_version"] is None
    assert env.b.get(f"{env.prefix}/cfg")[1] == 1  # nothing written


def test_reveal_includes_values_only_when_asked(env, client):
    env.a.put(f"{env.prefix}/cfg", {"pw": "secret-A"})
    env.b.put(f"{env.prefix}/cfg", {"pw": "secret-B"})
    ch = env.change(env.compare()["cfg"])
    hidden = env.preview([ch])
    assert "secret-A" not in hidden.text and "secret-B" not in hidden.text
    shown = env.preview([ch], reveal=True).json()[0]["keys"][0]
    assert shown["source_value"] == "secret-A" and shown["target_value"] == "secret-B"


def test_confirm_required_and_duplicates_rejected(env):
    env.a.put(f"{env.prefix}/cfg", {"k": "A"})
    ch = env.change(env.compare()["cfg"])
    assert env.apply([ch], confirm=False).status_code == 400
    assert env.preview([ch, ch]).status_code == 422
    assert env.b.get(f"{env.prefix}/cfg")[0] is None


def test_audit_log_has_no_values(env):
    records: list[str] = []

    class H(logging.Handler):
        def emit(self, rec):
            records.append(rec.getMessage())

    log = logging.getLogger("lockstep.audit")
    h = H()
    log.addHandler(h)
    try:
        env.a.put(f"{env.prefix}/cfg", {"pw": "very-secret-value"})
        env.apply([env.change(env.compare()["cfg"])])
    finally:
        log.removeHandler(h)
    assert len(records) == 1
    entry = json.loads(records[0])
    assert entry["event"] == "sync.apply" and entry["outcome"] == "applied"
    assert entry["keys"] == ["pw"] and entry["target"]["new_version"] == 1
    assert entry["actor"]["target_identity"] == "token"
    assert "very-secret-value" not in records[0]
