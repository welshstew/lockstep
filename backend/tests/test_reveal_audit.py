"""The secret.reveal audit event (LOCKSTEP_AUDIT_REVEALS=on): one per request that carries values,
with secrets and key names, never the values."""

import json
import logging
import uuid

import httpx
import pytest
from fastapi.testclient import TestClient

from lockstep.config import get_settings

pytestmark = pytest.mark.usefixtures("vaults")


@pytest.fixture
def setup(monkeypatch, vaults):
    """(make_client, path, events): a secret with two versions on both Vaults, and the audit lines."""
    events: list[dict] = []

    class H(logging.Handler):
        def emit(self, rec):
            d = json.loads(rec.getMessage())
            if d.get("event") == "secret.reveal":
                events.append(d)

    log = logging.getLogger("lockstep.audit")
    h = H()
    log.addHandler(h)
    path = f"reveal-{uuid.uuid4().hex[:8]}/db"
    clients = [httpx.Client(base_url=f"{a}/v1/", headers={"X-Vault-Token": t}) for a, t in zip(vaults, ("root-a", "root-b"))]
    for c in clients:
        c.post(f"app-config/data/{path}", json={"data": {"user": "app", "password": "pw-one"}}).raise_for_status()
    clients[0].post(f"app-config/data/{path}", json={"data": {"user": "app", "password": "pw-two", "cert": "-----BEGIN"}}).raise_for_status()

    def make(**env):
        for k, v in env.items():
            monkeypatch.setenv(f"LOCKSTEP_{k.upper()}", v)
        get_settings.cache_clear()
        from lockstep.main import create_app
        c = TestClient(create_app(), headers={"X-Requested-With": "lockstep"})
        ids = [c.post("/api/connections", json={"preset_id": i, "auth": {"method": "token", "token": t}}).json()["id"]
               for i, t in ((0, "root-a"), (1, "root-b"))]
        return c, ids

    yield make, path, events
    log.removeHandler(h)
    get_settings.cache_clear()
    for c in clients:
        c.delete(f"app-config/metadata/{path}")


def test_off_by_default(setup):
    make, path, events = setup
    c, (a, _) = make()
    assert c.get("/api/browse/values", params={"conn_id": a, "mount": "app-config", "path": path}).status_code == 200
    assert events == []


def test_browse_show_logs_one_event_without_values(setup):
    make, path, events = setup
    c, (a, _) = make(audit_reveals="on")
    r = c.get("/api/browse/values", params={"conn_id": a, "mount": "app-config", "path": path})
    assert r.status_code == 200 and r.json()["data"]["password"] == "pw-two"
    [e] = events
    assert e["how"] == "browse.show" and e["request_id"] == r.headers["x-request-id"]
    assert e["actor"] == [{"vault": "Vault A", "identity": "token", "auth": "token"}]
    assert e["secrets"] == [{"vault": "Vault A", "url": e["secrets"][0]["url"], "mount": "app-config", "path": path,
                             "version": 2, "keys": ["cert", "password", "user"]}]
    assert "pw-two" not in json.dumps(e) and "pw-one" not in json.dumps(e)


def test_each_feature_that_shows_values_is_logged(setup):
    make, path, events = setup
    c, (a, b) = make(audit_reveals="on")
    assert c.get(f"/api/connections/{a}/secret", params={"mount": "app-config", "path": path}).status_code == 200
    assert c.post("/api/browse/diff", json={"conn_id": a, "mount": "app-config", "path": path, "a": 1, "b": 2,
                                           "reveal": True}).status_code == 200
    assert c.post("/api/browse/diff", json={"conn_id": a, "mount": "app-config", "path": path, "a": 1, "b": 2}).status_code == 200
    r = c.post("/api/sync/preview", json={
        "left": {"conn_id": a, "mount": "app-config", "prefix": ""}, "right": {"conn_id": b, "mount": "app-config", "prefix": ""},
        "changes": [{"path": path, "direction": "left_to_right", "keys": ["password"]}], "reveal": True})
    assert r.status_code == 200, r.text
    assert c.post("/api/analyze", json={"conn_id": a, "mount": "app-config", "path": path, "key": "user"}).status_code == 200
    hows = [e["how"] for e in events]
    assert hows == ["compare.show", "browse.diff", "sync.preview", "inspect"]  # the diff without values isn't
    diff = events[1]
    assert [(s["version"], s["keys"]) for s in diff["secrets"]] == [(1, ["password", "user"]), (2, ["cert", "password", "user"])]
    sync = events[2]
    assert {(s["vault"], tuple(s["keys"])) for s in sync["secrets"]} == {("Vault A", ("password",)), ("Vault B", ("password",))}
    assert {x["vault"] for x in sync["actor"]} == {"Vault A", "Vault B"}  # both sides' identities
    assert events[3]["secrets"][0]["keys"] == ["user"]
    assert "pw-" not in json.dumps(events)
