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


# ---- the apps mount: test (Vault A) against dev (Vault B), after ELP was renamed in dev

ELP = {"mappings": [{"left": "enterprise-logging-app/**", "right": "ELP/**"}],
       "rewrites": [{"left": "enterprise-logging-app", "right": "elp"}, {"left": "test", "right": "dev"}],
       "ignore_keys": [{"key": "api_token", "path": "**"}, {"key": "log_level", "path": "**"},
                       {"key": "tls.*", "path": "**/certs"}]}


def apps(a, b):
    return {"left": {"conn_id": a, "mount": "apps"}, "right": {"conn_id": b, "mount": "apps"}}


def test_rename_profile_leaves_only_what_changed_in_dev(client, ab):
    r = client.post("/api/compare", json=apps(*ab) | {"rules": ELP})
    assert r.status_code == 200, r.text
    s = {x["path"]: x for x in r.json()["secrets"]}
    values = s["ELP/values"]
    assert values["left_path"] == "enterprise-logging-app/values"
    keys = {k["key"]: k for k in values["keys"]}
    assert {k for k, v in keys.items() if v["rewritten"]} == {
        "ingest_endpoint", "index_prefix", "service_account", "kafka_topic", "db_url"}
    assert keys["batch_size"]["status"] == "different" and not keys["batch_size"]["ignored"]
    assert keys["otlp_endpoint"]["status"] == "right_only"
    assert keys["api_token"]["ignored"] and keys["log_level"]["ignored"]
    assert values["status"] == "different" and values["rewritten_keys"] == 5
    assert s["ELP/certs"]["status"] == "equal"
    assert s["ELP/alerts"]["status"] == "right_only"
    assert s["ELP/legacy-syslog"]["status"] == "left_only"
    assert s["payments-gateway/config"]["status"] == "equal"
    assert s["search-indexer/config"]["status"] == "different"
    assert r.json()["summary"]["rewritten_keys"] >= 7


def test_suggest_builds_the_rename_profile(client, ab):
    r = client.post("/api/compare/suggest", json=apps(*ab))
    assert r.status_code == 200, r.text
    out = r.json()
    assert [(m["left"], m["right"]) for m in out["mappings"]] == [("enterprise-logging-app/**", "ELP/**")]
    assert {(w["left"], w["right"]) for w in out["rewrites"]} >= {("test", "dev"), ("enterprise-logging-app", "elp")}
    assert "ELP/values" in out["right_paths"] and "enterprise-logging-app/values" in out["left_paths"]
    assert out["before"]["left_only"] > out["after"]["left_only"]
    assert out["after"]["equal"] > out["before"]["equal"]
    assert "hunter" not in r.text and "tok-" not in r.text and "8f2a" not in r.text  # no values


def test_suggest_reads_each_secret_once_per_side(client, ab, monkeypatch):
    """Read both sides runs the comparison three times (as is, with mappings, with rewrites): every
    secret, listing and metadata read reaches Vault once, the later passes come from memory."""
    from collections import Counter

    from lockstep.vault import VaultClient
    counts: Counter = Counter()
    real = VaultClient.request

    async def counting(self, method, path, *a, **kw):
        if path.startswith("apps/"):
            counts[(self._host, method, path, str(kw.get("params") or ""))] += 1
        return await real(self, method, path, *a, **kw)

    monkeypatch.setattr(VaultClient, "request", counting)
    out = client.post("/api/compare/suggest", json=apps(*ab)).json()
    assert out["rewrites"]  # so all three passes ran
    reads = [k for k in counts if "/data/" in k[2]]
    assert len(reads) >= 10 and {n for n in counts.values()} == {1}, [k for k, n in counts.items() if n > 1]


def test_copy_applies_rewrites_in_the_copy_direction(client, ab, vaults):
    """Releasing ELP/alerts to test writes it at the old path, with dev words read back as test."""
    raw_a = httpx.Client(base_url=f"{vaults[0]}/v1/", headers={"X-Vault-Token": "root-a"})
    change = {"path": "enterprise-logging-app/alerts", "right_path": "ELP/alerts", "direction": "right_to_left",
              "keys": None, "expected_target_version": None}
    body = apps(*ab) | {"changes": [change], "rewrites": ELP["rewrites"]}
    try:
        plan = client.post("/api/sync/preview", json=body | {"reveal": True}).json()[0]
        assert plan["target"]["path"] == "enterprise-logging-app/alerts" and plan["status"] == "ready"
        svc = next(k for k in plan["keys"] if k["key"] == "pagerduty_service")
        assert svc["rewritten"] and svc["source_value"] == "enterprise-logging-app-test"
        res = client.post("/api/sync/apply", json=body | {"confirm": True}).json()
        assert res["results"][0]["status"] == "applied"
        got = raw_a.get("apps/data/enterprise-logging-app/alerts").json()["data"]["data"]
        assert got == {"pagerduty_service": "enterprise-logging-app-test", "errors_per_minute": "50"}
        after = client.post("/api/compare", json=apps(*ab) | {"rules": ELP}).json()
        assert next(x for x in after["secrets"] if x["path"] == "ELP/alerts")["status"] == "equal"
    finally:
        raw_a.delete("apps/metadata/enterprise-logging-app/alerts")


# ---- unordered lists, volatile patterns and scoped rewrites, through the API

def test_value_rules_through_compare_and_copy(client, ab, vaults):
    prefix = f"rules-{uuid.uuid4().hex[:8]}/"
    raw = [httpx.Client(base_url=f"{a}/v1/", headers={"X-Vault-Token": t}) for a, t in zip(vaults, ("root-a", "root-b"))]
    raw[0].post(f"app-config/data/{prefix}web", json={"data": {
        "sans": "a.example, b.example", "built": "v3 at 2026-01-01T10:00:00Z", "db_host": "db.test.internal",
        "password": "test-pw"}}).raise_for_status()
    raw[1].post(f"app-config/data/{prefix}web", json={"data": {
        "sans": "b.example,a.example", "built": "v3 at 2026-03-04T05:06:07Z", "db_host": "db.dev.internal",
        "password": "dev-pw"}}).raise_for_status()
    rules = {"unordered_keys": [{"key": "sans", "separator": ","}],
             "volatile": [{"key": "built", "pattern": r"\d{4}-\d{2}-\d{2}T[0-9:]+Z"}],
             "rewrites": [{"left": "test", "right": "dev", "key": "*host*"}]}
    try:
        out = compare(client, *ab, rules=rules, prefix=prefix)
        [s] = out["secrets"]
        keys = {k["key"]: k for k in s["keys"]}
        assert keys["sans"]["status"] == "equal" and keys["sans"]["reason"].startswith("same items in a different order")
        assert keys["built"]["ignored"] and "volatile pattern" in keys["built"]["reason"]
        assert keys["db_host"]["status"] == "equal" and keys["db_host"]["rewritten"]
        assert keys["password"]["status"] == "different" and not keys["password"]["rewritten"]  # out of the rewrite's scope
        bad = client.post("/api/compare", json={"left": {"conn_id": ab[0], "mount": "app-config"},
                                                "right": {"conn_id": ab[1], "mount": "app-config"},
                                                "rules": {"volatile": [{"key": "*", "pattern": "(a+)+"}]}})
        assert bad.status_code == 422 and "repeats a group" in bad.text
        # a copy to the right rewrites the host but never the password
        body = {"left": {"conn_id": ab[0], "mount": "app-config", "prefix": prefix},
                "right": {"conn_id": ab[1], "mount": "app-config", "prefix": prefix},
                "changes": [{"path": "web", "direction": "left_to_right", "keys": ["db_host", "password"],
                             "expected_target_version": 1}],
                "rewrites": rules["rewrites"], "reveal": True}
        [plan] = client.post("/api/sync/preview", json=body).json()
        got = {k["key"]: k for k in plan["keys"]}
        assert got["db_host"]["rewritten"] and not got["password"]["rewritten"]
    finally:
        for c in raw:
            c.delete(f"app-config/metadata/{prefix}web")


def test_builder_suggests_unordered_lists_and_volatile_values(client, ab, vaults):
    prefix = f"suggest-{uuid.uuid4().hex[:8]}/"
    raw = [httpx.Client(base_url=f"{a}/v1/", headers={"X-Vault-Token": t}) for a, t in zip(vaults, ("root-a", "root-b"))]
    for i, (sans, built, uid) in enumerate((("a.example, b.example", "v3 at 2026-01-01T10:00:00Z", "6f1c1d2e-0000-4000-8000-000000000001"),
                                            ("b.example,a.example", "v3 at 2026-03-04T05:06:07Z", "6f1c1d2e-0000-4000-8000-000000000002"))):
        for name in ("web", "api"):
            raw[i].post(f"app-config/data/{prefix}{name}", json={"data": {
                "sans": sans, "scopes": ["read", "write"] if i == 0 else ["write", "read"], "built": built,
                "run_id": uid, "password": f"pw-{i}"}}).raise_for_status()
    try:
        r = client.post("/api/compare/suggest", json={
            "left": {"conn_id": ab[0], "mount": "app-config", "prefix": prefix},
            "right": {"conn_id": ab[1], "mount": "app-config", "prefix": prefix}})
        assert r.status_code == 200, r.text
        out = r.json()
        assert {(u["key"], u["separator"], u["keys"]) for u in out["unordered"]} == {("sans", ",", 2), ("scopes", None, 2)}
        assert {(v["key"], v["what"], v["keys"]) for v in out["volatile"]} == {("built", "a timestamp", 2), ("run_id", "a UUID", 2)}
        assert all("pw-" not in v["reason"] and "2026" not in v["reason"] for v in out["volatile"] + out["unordered"])
        assert out["before"]["different"] == 2 and out["after"]["different"] == 2  # the password still differs
        rules = {"unordered_keys": [{"key": u["key"], "separator": u["separator"]} for u in out["unordered"]],
                 "volatile": [{"key": v["key"], "pattern": v["pattern"]} for v in out["volatile"]]}
        res = compare(client, *ab, rules=rules, prefix=prefix)
        keys = {k["key"]: k for k in res["secrets"][0]["keys"]}
        assert keys["sans"]["status"] == keys["scopes"]["status"] == "equal"
        assert keys["built"]["ignored"] and keys["run_id"]["ignored"] and keys["password"]["status"] == "different"
    finally:
        for c in raw:
            for name in ("web", "api"):
                c.delete(f"app-config/metadata/{prefix}{name}")
