"""KV v1, read-only: list and compare KV v1 mounts, copy from KV v1 into KV v2, never write KV v1."""

import uuid

import httpx
import pytest

from test_sync import MOUNT, Raw

pytestmark = pytest.mark.usefixtures("vaults")


@pytest.fixture
def kv1(client, vaults):
    """A fresh KV v1 mount on Vault A with two secrets, a KV v2 prefix on Vault B, and connections."""
    name = f"kv1-{uuid.uuid4().hex[:6]}"
    root = httpx.Client(base_url=f"{vaults[0]}/v1/", headers={"X-Vault-Token": "root-a"}, timeout=10)
    root.post(f"sys/mounts/{name}", json={"type": "kv", "options": {"version": "1"}}).raise_for_status()
    root.post(f"{name}/app/db", json={"user": "svc", "password": "p1"}).raise_for_status()
    root.post(f"{name}/app/cache", json={"ttl": "60"}).raise_for_status()
    prefix = f"kv1test-{uuid.uuid4().hex[:6]}"
    b = Raw(vaults[1], "root-b")
    b.put(f"{prefix}/app/db", {"user": "svc", "password": "p2"})

    def connect(preset, token):
        r = client.post("/api/connections", json={"preset_id": preset, "auth": {"method": "token", "token": token}})
        assert r.status_code == 201, r.text
        return r.json()["id"]

    class E:
        pass

    e = E()
    e.mount, e.root, e.prefix, e.b = name, root, prefix, b
    e.ca, e.cb = connect(0, "root-a"), connect(1, "root-b")
    e.sides = {"left": {"conn_id": e.ca, "mount": name, "prefix": "app"},
               "right": {"conn_id": e.cb, "mount": MOUNT, "prefix": f"{prefix}/app"}}
    yield e
    root.delete(f"sys/mounts/{name}")
    b.purge(prefix)


def test_listed_only_when_asked(client, kv1):
    plain = client.get(f"/api/connections/{kv1.ca}/mounts").json()["mounts"]
    assert kv1.mount not in {m["path"] for m in plain}  # other tabs never see KV v1
    both = {m["path"]: m for m in client.get(f"/api/connections/{kv1.ca}/mounts?kv1=true").json()["mounts"]}
    assert both[kv1.mount]["version"] == "1" and both[MOUNT]["version"] == "2"
    assert client.get(f"/api/connections/{kv1.ca}/mounts/{kv1.mount}").status_code == 400
    assert client.get(f"/api/connections/{kv1.ca}/mounts/{kv1.mount}?kv1=true").json()["version"] == "1"


def test_compare_kv1_with_kv2_and_copy_into_kv2(client, kv1):
    r = client.post("/api/compare", json=kv1.sides)
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["left"]["kv_version"] == "1" and out["right"]["kv_version"] == "2"
    by = {s["path"]: s for s in out["secrets"]}
    assert by["db"]["status"] == "different" and by["cache"]["status"] == "left_only"
    assert by["db"]["left"]["version"] is None and by["db"]["left"]["state"] == "present"
    assert [k["key"] for k in by["db"]["keys"] if k["status"] == "different"] == ["password"]

    copy = {"path": "cache", "direction": "left_to_right", "expected_target_version": None}
    res = client.post("/api/sync/apply", json=kv1.sides | {"changes": [copy], "confirm": True}).json()
    assert res["summary"]["applied"] == 1, res
    assert kv1.b.get(f"{kv1.prefix}/app/cache")[0] == {"ttl": "60"}


def test_never_writes_kv1(client, kv1):
    back = {"path": "db", "direction": "right_to_left", "keys": ["password"], "expected_target_version": None}
    p = client.post("/api/sync/preview", json=kv1.sides | {"changes": [back]}).json()[0]
    assert p["status"] == "invalid" and "KV v1 mount: Lockstep only reads KV v1" in p["problems"][0]
    res = client.post("/api/sync/apply", json=kv1.sides | {"changes": [back], "confirm": True}).json()
    assert res["summary"].get("applied", 0) == 0
    assert kv1.root.get(f"{kv1.mount}/app/db").json()["data"]["password"] == "p1"  # untouched


async def test_every_write_method_refuses_kv1(kv1, vaults):
    from lockstep.config import get_settings
    from lockstep.vault import VaultClient, VaultError

    async with VaultClient(vaults[0], get_settings(), token="root-a") as v:
        assert await v.kv_version(kv1.mount) == "1" and await v.kv_version(MOUNT) == "2"
        assert (await v.kv_read(kv1.mount, "app/db")).data == {"user": "svc", "password": "p1"}
        assert sorted(await v.kv_list(kv1.mount, "app/")) == ["cache", "db"]
        assert (await v.kv_read(kv1.mount, "app/nope")).state == "absent"
        assert await v.kv_metadata(kv1.mount, "app/db") == {}
        calls = [v.kv_write(kv1.mount, "app/db", {"x": 1}, cas=None), v.kv_patch(kv1.mount, "app/db", {"x": 1}, None),
                 v.kv_delete(kv1.mount, "app/db"), v.kv_delete_versions(kv1.mount, "app/db", [1]),
                 v.kv_undelete(kv1.mount, "app/db", [1]), v.kv_destroy_versions(kv1.mount, "app/db", [1]),
                 v.kv_destroy_all(kv1.mount, "app/db"), v.kv_metadata_write(kv1.mount, "app/db", {"max_versions": 1})]
        for c in calls:
            with pytest.raises(VaultError, match="only reads KV v1"):
                await c
    data = kv1.root.get(f"{kv1.mount}/app/db").json()["data"]
    assert data == {"user": "svc", "password": "p1"}
    assert kv1.root.get(f"{kv1.mount}/app/db/metadata").status_code == 404  # no stray "metadata" secret


def test_cli_compares_kv1(kv1, vaults, monkeypatch, tmp_path, capsys):
    from lockstep.cli import main
    for var in ("VAULT_ADDR", "VAULT_TOKEN", "VAULT_NAMESPACE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("LOCKSTEP_LEFT_TOKEN", "root-a")
    monkeypatch.setenv("LOCKSTEP_RIGHT_TOKEN", "root-b")
    monkeypatch.chdir(tmp_path)
    rc = main(["compare", "--left-addr", vaults[0], "--left-mount", kv1.mount, "--left-prefix", "app",
               "--right-addr", vaults[1], "--right-mount", MOUNT, "--right-prefix", f"{kv1.prefix}/app", "-o", "r.yaml"])
    assert rc == 1
    out = capsys.readouterr().out
    assert "different   db" in out and "left only   cache" in out
