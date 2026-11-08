"""Per-key "last changed" history, derived from KV v2 versions."""

import uuid

import httpx
import pytest

pytestmark = pytest.mark.usefixtures("vaults")


@pytest.fixture
def setup(client, vaults):
    raw = httpx.Client(base_url=f"{vaults[0]}/v1/", headers={"X-Vault-Token": "root-a"}, timeout=10)
    prefix = f"histtest-{uuid.uuid4().hex[:8]}"
    cid = client.post("/api/connections", json={"preset_id": 0, "auth": {"method": "token", "token": "root-a"}}).json()["id"]

    def put(path, data):
        raw.post(f"app-config/data/{prefix}/{path}", json={"data": data}).raise_for_status()

    def history(path):
        r = client.get(f"/api/connections/{cid}/history", params={"mount": "app-config", "path": f"{prefix}/{path}"})
        assert r.status_code == 200, r.text
        return r.json()

    yield raw, prefix, put, history
    for k in raw.request("LIST", f"app-config/metadata/{prefix}/").json().get("data", {}).get("keys", []):
        raw.delete(f"app-config/metadata/{prefix}/{k}")


def test_finds_version_each_key_last_changed(setup):
    _, _, put, history = setup
    put("s", {"a": "1", "b": "1"})
    put("s", {"a": "2", "b": "1"})
    put("s", {"a": "2", "b": "1", "c": "3"})
    h = history("s")
    assert h["current_version"] == 3 and h["updated"]
    k = h["keys"]
    assert (k["a"]["version"], k["a"]["exact"]) == (2, True)
    assert (k["b"]["version"], k["b"]["exact"]) == (1, True)  # unchanged since creation
    assert (k["c"]["version"], k["c"]["exact"]) == (3, True)
    assert all(v["time"] for v in k.values())
    assert "1" not in str(h["keys"]["a"].get("value", ""))  # no values returned


def test_deleted_version_stops_the_walk(setup):
    raw, prefix, put, history = setup
    put("s", {"a": "same"})
    put("s", {"a": "same"})
    raw.post(f"app-config/delete/{prefix}/s", json={"versions": [2]}).raise_for_status()
    put("s", {"a": "same"})
    k = history("s")["keys"]["a"]
    assert k["version"] == 3 and k["exact"] is False  # can't see past deleted v2


def test_deleted_current_version_has_no_keys(setup):
    raw, prefix, put, history = setup
    put("s", {"a": "1"})
    raw.delete(f"app-config/data/{prefix}/s").raise_for_status()
    h = history("s")
    assert h["current_version"] == 1 and h["keys"] == {}
