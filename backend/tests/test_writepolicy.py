"""Per-preset write policy: a read-only preset, write paths and protected paths, enforced by the API
on top of Vault's own policies, shown to the UI, and audit-logged when refused."""

import json
import logging

import pytest

from lockstep import writepolicy
from lockstep.config import PresetConnection, Settings
from lockstep.session import Connection
from test_sync import MOUNT, env  # noqa: F401  (the fixture)


def settings(*presets: dict, **kw) -> Settings:
    return Settings(session_key="x" * 32, preset_connections=[PresetConnection(**p) for p in presets], **kw)


def conn(preset_id=None, url="https://vault.dev:8200") -> Connection:
    return Connection(name="c", url=url, token="t", auth_method="token", preset_id=preset_id)


DEV = {"name": "Dev", "url": "https://vault.dev:8200", "write_paths": ["kv/apps/**", "sys/policies/acl/app-*"],
       "deny_paths": ["kv/apps/*/break-glass/**"], "allow_destroy": False}
PROD = {"name": "Prod", "url": "https://vault.prod:8200", "writable": False}


def test_refusals():
    s = settings(DEV, PROD)
    dev, prod = conn(0), conn(1, "https://vault.prod:8200")
    assert writepolicy.refusal(s, dev, "kv/apps/billing/db") is None
    assert writepolicy.refusal(s, dev, "kv/apps") is None  # `a/**` covers `a` itself
    assert "outside the paths" in writepolicy.refusal(s, dev, "kv/other/x")
    assert "protected" in writepolicy.refusal(s, dev, "kv/apps/billing/break-glass/root")
    assert writepolicy.refusal(s, dev, "sys/policies/acl/app-billing") is None
    assert writepolicy.refusal(s, dev, "sys/policies/acl/admin")
    assert "Destroying secrets is turned off for Dev" in writepolicy.refusal(s, dev, "kv/apps/x", "destroy")
    assert "Prod is read-only" in writepolicy.refusal(s, prod, "anything")
    assert writepolicy.refusal(s, conn(None, "https://elsewhere:8200"), "x") is None  # no preset: no rules
    # Typing a preset's address by hand doesn't get round its rules
    assert writepolicy.refusal(s, conn(None, "https://VAULT.prod:8200/"), "kv/x")
    assert writepolicy.summary(s, dev) == ("some", False)
    assert writepolicy.summary(s, prod) == ("none", False)
    assert writepolicy.summary(settings(DEV, read_only=True), dev) == ("none", False)
    assert writepolicy.summary(settings({"name": "x", "url": "https://x"}), conn(0, "https://x")) == ("all", True)


def test_strictest_preset_at_one_address():
    s = settings({"name": "Prod team-a", "url": "https://v", "namespace": "a"},
                 {"name": "Prod", "url": "https://v", "writable": False})
    assert "read-only" in writepolicy.refusal(s, conn(None, "https://v"), "kv/x")


@pytest.fixture
def read_only_b(monkeypatch):
    from lockstep.config import get_settings
    preset = get_settings().preset_connections[1]
    monkeypatch.setattr(preset, "writable", False)
    return preset


@pytest.mark.usefixtures("vaults")
def test_read_only_preset(client, env, read_only_b, caplog):  # noqa: F811
    env.a.put(f"{env.prefix}/db", {"user": "u", "pw": "a"})
    env.b.put(f"{env.prefix}/db", {"user": "u", "pw": "b"})
    conns = {c["id"]: c for c in client.get("/api/connections").json()}
    assert conns[env.cb]["writes"] == "none" and conns[env.cb]["destroy"] is False
    assert conns[env.ca]["writes"] == "all"
    cmp = client.post("/api/compare", json={"left": {"conn_id": env.ca, "mount": MOUNT, "prefix": env.prefix},
                                            "right": {"conn_id": env.cb, "mount": MOUNT, "prefix": env.prefix}}).json()
    assert cmp["right"]["writes"] == "none" and cmp["left"]["writes"] == "all"
    d = env.compare()["db"]

    p = env.preview([env.change(d)]).json()[0]
    assert p["status"] == "invalid" and "Vault B is read-only" in p["problems"][0]
    with caplog.at_level(logging.INFO, logger="lockstep.audit"):
        res = env.apply([env.change(d)]).json()
    assert res["summary"].get("applied", 0) == 0 and env.b.get(f"{env.prefix}/db")[0]["pw"] == "b"
    # Copying the other way, into the writable side, still works
    assert env.apply([env.change(d, direction="right_to_left")]).json()["summary"]["applied"] == 1

    r = client.post("/api/destroy", json={"side": {"conn_id": env.cb, "mount": MOUNT, "prefix": env.prefix},
                                          "secrets": [{"path": "db"}], "confirm": True})
    assert r.status_code == 403 and r.json()["detail"]["write_policy"] is True
    with caplog.at_level(logging.INFO, logger="lockstep.audit"):
        out = client.post("/api/browse/apply", json={"conn_id": env.cb, "mount": MOUNT, "confirm": True, "edits": [
            {"path": f"{env.prefix}/db", "action": "write", "expected_version": 1, "set": {"pw": "x"}}]}).json()
    assert out[0]["status"] == "invalid" and env.b.get(f"{env.prefix}/db")[0]["pw"] == "b"
    refused = [json.loads(r.message) for r in caplog.records if r.name == "lockstep.audit" and "write.refused" in r.message]
    assert refused and refused[-1]["request"] == "browse.write" and refused[-1]["target"]["path"] == f"{MOUNT}/{env.prefix}/db"

    # A policy write toward the read-only side is refused in the preview and the apply
    body = {"conn_id": env.cb, "policies": [{"name": "lockstep-wp-test", "text": 'path "x/*" { capabilities = ["read"] }'}]}
    prev = client.post("/api/access/preview", json=body).json()
    assert prev[0]["status"] == "invalid" and "read-only" in prev[0]["problems"][-1]


@pytest.mark.usefixtures("vaults")
def test_write_paths_and_protected_paths(client, env, monkeypatch):  # noqa: F811
    from lockstep.config import get_settings
    preset = get_settings().preset_connections[0]
    monkeypatch.setattr(preset, "write_paths", [f"{MOUNT}/{env.prefix}/apps/**"])
    monkeypatch.setattr(preset, "deny_paths", [f"{MOUNT}/{env.prefix}/apps/*/break-glass"])
    edits = [{"path": f"{env.prefix}/{p}", "action": "write", "set": {"k": "v"}}
             for p in ("apps/billing", "apps/billing/break-glass", "other")]
    out = client.post("/api/browse/apply", json={"conn_id": env.ca, "mount": MOUNT, "confirm": True, "edits": edits}).json()
    assert [r["status"] for r in out] == ["applied", "invalid", "invalid"]
    assert "protected" in out[1]["message"] and "outside the paths" in out[2]["message"]
    assert client.get("/api/connections").json()[0]["writes"] == "some"
