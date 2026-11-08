"""Comparison profiles against the seeded Vaults: mapping, ignores, collisions, mapped copies."""

import json
import uuid

import httpx
import pytest
from fastapi.testclient import TestClient

from lockstep.config import Settings, get_settings
from lockstep.main import create_app

pytestmark = pytest.mark.usefixtures("vaults")

RULES = {"mappings": [{"left": "services/*/prod/**", "right": "services/*/staging/**"}],
         "ignore_keys": [{"key": "host", "path": "services/**"}],
         "ignore_paths": ["legacy/**"]}


@pytest.fixture
def ab(client):
    def connect(preset, token):
        return client.post("/api/connections", json={"preset_id": preset, "auth": {"method": "token", "token": token}}).json()["id"]
    return connect(0, "root-a"), connect(1, "root-b")


def compare(client, a, b, rules=None, prefix=""):
    r = client.post("/api/compare", json={"left": {"conn_id": a, "mount": "app-config", "prefix": prefix},
                                          "right": {"conn_id": b, "mount": "app-config", "prefix": prefix},
                                          **({"rules": rules} if rules else {})})
    assert r.status_code == 200, r.text
    return r.json()


def test_mapping_pairs_environments_and_ignores_host(client, ab):
    out = compare(client, *ab, RULES)
    s = {x["path"]: x for x in out["secrets"]}
    db = s["services/billing/staging/db"]
    assert (db["left_path"], db["right_path"]) == ("services/billing/prod/db", "services/billing/staging/db")
    assert db["status"] == "equal" and db["ignored_keys"] == 1  # only host differs, and it's ignored
    host = next(k for k in db["keys"] if k["key"] == "host")
    assert host["status"] == "different" and host["ignored"]
    api = s["services/billing/staging/api"]
    assert api["status"] == "different" and api["ignored_keys"] == 0
    search = s["services/search/staging/config"]
    assert search["status"] == "left_only" and search["left_path"] == "services/search/prod/config"
    orders = s["services/orders/staging/queue"]
    assert orders["status"] == "right_only" and orders["left_path"] == "services/orders/prod/queue"
    assert not any(p.startswith("legacy/") for p in s)
    assert out["summary"]["ignored_paths"] >= 1 and out["summary"]["mapped"] >= 4


def test_without_rules_paths_stay_apart(client, ab):
    s = {x["path"]: x for x in compare(client, *ab)["secrets"]}
    assert s["services/billing/prod/db"]["status"] == "left_only"
    assert s["services/billing/staging/db"]["status"] == "right_only"


def test_invalid_rules_rejected(client, ab):
    r = client.post("/api/compare", json={"left": {"conn_id": ab[0], "mount": "app-config"},
                                          "right": {"conn_id": ab[1], "mount": "app-config"},
                                          "rules": {"mappings": [{"left": "a/*", "right": "b/**"}]}})
    assert r.status_code == 422 and "same wildcards" in r.text


def test_collision_is_reported_as_error(client, ab, vaults):
    raw = httpx.Client(base_url=f"{vaults[0]}/v1/", headers={"X-Vault-Token": "root-a"})
    prefix = f"coll-{uuid.uuid4().hex[:6]}"
    raw.post(f"app-config/data/{prefix}/x/prod/s", json={"data": {"k": "1"}}).raise_for_status()
    raw.post(f"app-config/data/{prefix}/x/staging/s", json={"data": {"k": "2"}}).raise_for_status()
    try:
        out = compare(client, *ab, {"mappings": [{"left": "*/prod/**", "right": "*/staging/**"}]}, prefix=prefix)
        (only,) = out["secrets"]
        assert only["status"] == "error" and "several left paths" in only["note"]
    finally:
        for p in ("x/prod/s", "x/staging/s"):
            raw.delete(f"app-config/metadata/{prefix}/{p}")


def test_copy_follows_the_mapping(client, ab, vaults):
    raw_b = httpx.Client(base_url=f"{vaults[1]}/v1/", headers={"X-Vault-Token": "root-b"})
    out = compare(client, *ab, RULES)
    search = next(x for x in out["secrets"] if x["path"] == "services/search/staging/config")
    change = {"path": search["left_path"], "right_path": search["right_path"], "direction": "left_to_right",
              "keys": None, "expected_target_version": None, "expected_source_version": search["left"]["version"]}
    sides = {"left": {"conn_id": ab[0], "mount": "app-config"}, "right": {"conn_id": ab[1], "mount": "app-config"}}
    try:
        plan = client.post("/api/sync/preview", json=sides | {"changes": [change]}).json()[0]
        assert plan["target"]["path"] == "services/search/staging/config" and plan["status"] == "ready"
        res = client.post("/api/sync/apply", json=sides | {"changes": [change], "confirm": True}).json()
        assert res["results"][0]["status"] == "applied" and res["results"][0]["right_path"] == "services/search/staging/config"
        got = raw_b.get("app-config/data/services/search/staging/config").json()["data"]["data"]
        assert got == {"replicas": "3", "index": "products"}
        assert raw_b.get("app-config/data/services/search/prod/config").status_code == 404  # not the unmapped path
    finally:
        raw_b.delete("app-config/metadata/services/search/staging/config")


def test_shared_profiles_from_config():
    profile = {"name": "Envs", "left_mount": "app-config", "rules": RULES}
    app = create_app()
    base = get_settings().model_dump()
    app.dependency_overrides[get_settings] = lambda: Settings(**(base | {"profiles": [profile]}))
    with TestClient(app) as c:
        got = c.get("/api/profiles").json()
    assert got[0]["name"] == "Envs" and got[0]["rules"]["mappings"][0]["left"] == "services/*/prod/**"


def test_bad_profile_config_fails_at_startup(monkeypatch):
    monkeypatch.setenv("LOCKSTEP_PROFILES", json.dumps([{"name": "x", "rules": {"mappings": [{"left": "a/*", "right": "b"}]}}]))
    with pytest.raises(Exception, match="same wildcards"):
        Settings()
