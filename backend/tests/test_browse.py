"""Browsing and editing one mount."""

import json
import logging

import pytest

from test_sync import MOUNT, env  # noqa: F401  (the fixture)

pytestmark = pytest.mark.usefixtures("vaults")


def get(client, endpoint, **params):
    r = client.get(f"/api/browse/{endpoint}", params=params)
    assert r.status_code == 200, r.text
    return r.json()


def edit(client, env, edits, apply=True, reveal=False, conn=None):
    body = {"conn_id": conn or env.ca, "mount": MOUNT, "edits": edits}
    if apply:
        body["confirm"] = True
    else:
        body["reveal"] = reveal
    r = client.post(f"/api/browse/{'apply' if apply else 'preview'}", json=body)
    assert r.status_code == 200, r.text
    return r.json()


def test_list_folders_first_with_capabilities_and_paging(client, env):
    for p in ("b", "a", "dir/x", "dir/y"):
        env.a.put(f"{env.prefix}/{p}", {"k": p})
    out = get(client, "list", conn_id=env.ca, mount=MOUNT, folder=env.prefix)
    assert [(e["name"], e["folder"]) for e in out["entries"]] == [("dir", True), ("a", False), ("b", False)]
    assert out["entries"][1]["caps"] == {"read": True, "write": True, "history": True}
    assert out["entries"][0]["path"] == f"{env.prefix}/dir"
    page = get(client, "list", conn_id=env.ca, mount=MOUNT, folder=env.prefix, offset=1, limit=1)
    assert page["total"] == 3 and [e["name"] for e in page["entries"]] == ["a"]


def test_carol_sees_no_access(client, env):
    carol = env.connect(0, method="userpass", username="carol", password="password")
    assert get(client, "list", conn_id=carol, mount=MOUNT, folder="restricted")["denied"]
    root = get(client, "list", conn_id=carol, mount=MOUNT, folder="payments")
    api = next(e for e in root["entries"] if e["name"] == "api")
    assert api["caps"]["read"] is False and api["caps"]["history"] is True


def test_secret_info_versions_values_and_diff(client, env):
    p = f"{env.prefix}/cfg"
    env.a.put(p, {"user": "u", "pw": "1"})
    env.a.put(p, {"user": "u", "pw": "2", "new": "x"})
    info = get(client, "secret", conn_id=env.ca, mount=MOUNT, path=p)
    assert info["state"] == "present" and info["current_version"] == 2 and info["keys"] == ["new", "pw", "user"]
    assert [v["version"] for v in info["versions"]] == [2, 1] and info["caps"]["destroy"]
    assert "pw" not in json.dumps({k: v for k, v in info.items() if k != "keys"})  # no values
    old = get(client, "secret", conn_id=env.ca, mount=MOUNT, path=p, version=1)
    assert old["version"] == 1 and old["keys"] == ["pw", "user"]
    assert get(client, "values", conn_id=env.ca, mount=MOUNT, path=p, version=1)["data"] == {"user": "u", "pw": "1"}
    d = client.post("/api/browse/diff", json={"conn_id": env.ca, "mount": MOUNT, "path": p, "a": 1, "b": 2}).json()
    assert {k["key"]: k["change"] for k in d["keys"]} == {"new": "added", "pw": "changed", "user": "same"}
    assert "a" not in d["keys"][0]
    assert client.get("/api/browse/secret", params={"conn_id": env.ca, "mount": MOUNT, "path": f"{env.prefix}/nope"}).status_code == 404


def test_find(client, env):
    for p in ("svc/alpha/db", "svc/beta/db", "other/x"):
        env.a.put(f"{env.prefix}/{p}", {"k": "v"})
    out = client.post("/api/browse/find", json={"conn_id": env.ca, "mount": MOUNT, "folder": env.prefix, "query": "/DB"}).json()
    assert out["matches"] == [f"{env.prefix}/svc/alpha/db", f"{env.prefix}/svc/beta/db"]


def test_write_preview_apply_conflict_and_audit(client, env, caplog):
    p = f"{env.prefix}/cfg"
    v1 = env.a.put(p, {"user": "u", "pw": "1", "old": "x"})
    w = {"path": p, "action": "write", "expected_version": v1, "set": {"pw": "2", "port": 5432}, "remove": ["old"]}
    pre = edit(client, env, [w], apply=False, reveal=True)[0]
    assert pre["status"] == "ready" and pre["new_version"] == 2
    assert {k["key"]: (k["action"], k["old"], k["new"]) for k in pre["keys"]} == {
        "old": ("remove", "x", None), "port": ("add", None, 5432), "pw": ("update", "1", "2"), "user": ("unchanged", "u", "u")}
    with caplog.at_level(logging.INFO, logger="lockstep.audit"):
        res = edit(client, env, [w])[0]
    assert res["status"] == "applied" and res["new_version"] == 2 and "old" not in str(res["keys"][0]["old"])
    assert env.a.get(p)[0] == {"user": "u", "pw": "2", "port": 5432}
    line = next(json.loads(m) for m in caplog.messages if '"browse.write"' in m)
    assert line["keys"] == ["old", "port", "pw"] and "5432" not in json.dumps(line)
    # The same edit again: the secret moved on, so it's a conflict and nothing is written
    again = edit(client, env, [w])[0]
    assert again["status"] == "conflict" and env.a.get(p)[1] == 2


def test_new_secret_rollback_delete_undelete_destroy(client, env):
    p = f"{env.prefix}/new"
    assert edit(client, env, [{"path": p, "action": "write", "set": {"a": "1"}}])[0]["status"] == "applied"
    assert edit(client, env, [{"path": p, "action": "write", "set": {"a": "1"}}])[0]["status"] == "conflict"  # exists now
    edit(client, env, [{"path": p, "action": "write", "expected_version": 1, "set": {"a": "2"}}])
    rb = edit(client, env, [{"path": p, "action": "rollback", "expected_version": 2, "rollback_to": 1}])[0]
    assert rb["status"] == "applied" and rb["new_version"] == 3 and env.a.get(p) == ({"a": "1"}, 3)
    assert edit(client, env, [{"path": p, "action": "delete", "expected_version": 3}])[0]["status"] == "applied"
    assert env.a.get(p) == (None, None)
    assert edit(client, env, [{"path": p, "action": "undelete", "versions": [3]}])[0]["status"] == "applied"
    assert env.a.get(p)[0] == {"a": "1"}
    assert edit(client, env, [{"path": p, "action": "destroy", "versions": [1]}])[0]["status"] == "applied"
    info = get(client, "secret", conn_id=env.ca, mount=MOUNT, path=p)
    assert next(v for v in info["versions"] if v["version"] == 1)["destroyed"]
    # Removing every key deletes the latest version instead of writing an empty one
    last = edit(client, env, [{"path": p, "action": "write", "expected_version": 3, "remove": ["a"]}])[0]
    assert last["status"] == "applied" and last["action"] == "delete" and last["new_version"] is None


def test_bob_is_denied_and_validation(client, env):
    p = f"{env.prefix}/cfg"
    env.a.put(p, {"k": "v"})
    bob = env.connect(0, method="userpass", username="bob", password="password")
    res = edit(client, env, [{"path": p, "action": "write", "expected_version": 1, "set": {"k": "x"}}], conn=bob)[0]
    assert res["status"] == "denied"
    bad = client.post("/api/browse/preview", json={"conn_id": env.ca, "mount": MOUNT,
                                                   "edits": [{"path": p, "action": "write", "set": {"k": 1}, "remove": ["k"]}]})
    assert bad.status_code == 422


def test_read_only_server_refuses_every_write(client, env, monkeypatch):
    from lockstep.config import get_settings
    p = f"{env.prefix}/cfg"
    env.a.put(p, {"k": "v"})
    monkeypatch.setattr(get_settings(), "read_only", True)
    cfg = client.get("/api/config").json()
    assert cfg["read_only"] is True and cfg["allow_destroy"] is False
    side = {"conn_id": env.ca, "mount": MOUNT, "prefix": env.prefix}
    calls = [
        ("/api/browse/apply", {"conn_id": env.ca, "mount": MOUNT, "confirm": True,
                               "edits": [{"path": p, "action": "write", "expected_version": 1, "set": {"k": "x"}}]}),
        ("/api/sync/apply", {"left": side, "right": side | {"conn_id": env.cb}, "confirm": True,
                             "changes": [{"path": "cfg", "direction": "left_to_right", "keys": ["k"]}]}),
        ("/api/destroy", {"side": side, "secrets": [{"path": "cfg"}], "confirm": True}),
        ("/api/plans/apply", {"plan": {}, "left_conn_id": env.ca, "right_conn_id": env.cb, "confirm": True}),
        ("/api/import/apply", {"export": {}, "target": side, "confirm": True}),
    ]
    for url, body in calls:
        r = client.post(url, json=body)
        assert r.status_code in (403, 422), (url, r.status_code, r.text)
        if r.status_code == 403:
            assert "read-only" in r.text
    assert client.post(calls[0][0], json=calls[0][1]).status_code == 403
    assert env.a.get(p)[0] == {"k": "v"}
    # Reading still works
    assert get(client, "secret", conn_id=env.ca, mount=MOUNT, path=p)["keys"] == ["k"]


def test_clipboard_setting_is_published(client, monkeypatch):
    from lockstep.config import get_settings
    assert client.get("/api/config").json()["allow_clipboard"] is True
    monkeypatch.setattr(get_settings(), "allow_clipboard", False)
    assert client.get("/api/config").json()["allow_clipboard"] is False


def test_version_attribution(client, env):
    p = f"{env.prefix}/who"
    alice = env.connect(0, method="userpass", username="alice", password="password")
    assert edit(client, env, [{"path": p, "action": "write", "set": {"k": "v"}}], conn=alice)[0]["status"] == "applied"
    info = get(client, "secret", conn_id=env.ca, mount=MOUNT, path=p)
    assert info["versions"][0]["by"] == "userpass-alice"
    assert info["metadata"]["updated_by"]


def test_edit_metadata_with_a_recheck(client, env, caplog):
    p = f"{env.prefix}/meta"
    env.a.put(p, {"k": "v"})
    info = get(client, "secret", conn_id=env.ca, mount=MOUNT, path=p)
    body = {"conn_id": env.ca, "mount": MOUNT, "path": p, "expected_hash": info["metadata"]["hash"],
            "max_versions": 5, "cas_required": True, "delete_version_after": "720h",
            "custom_metadata": {"owner": "payments", "ticket": "OPS-1"}}
    with caplog.at_level(logging.INFO, logger="lockstep.audit"):
        r = client.post("/api/browse/metadata", json=body)
    assert r.status_code == 200 and r.json()["status"] == "applied", r.text
    m = get(client, "secret", conn_id=env.ca, mount=MOUNT, path=p)["metadata"]
    assert (m["max_versions"], m["cas_required"], m["custom_metadata"]) == (5, True, {"owner": "payments", "ticket": "OPS-1"})
    assert m["delete_version_after"] == "720h0m0s"
    assert any('"browse.metadata"' in x for x in caplog.messages)
    # The same request again: the metadata changed since that hash was taken, so nothing is written
    again = client.post("/api/browse/metadata", json=body | {"max_versions": 9}).json()
    assert again["status"] == "conflict"
    assert get(client, "secret", conn_id=env.ca, mount=MOUNT, path=p)["metadata"]["max_versions"] == 5
    assert client.post("/api/browse/metadata", json={"conn_id": env.ca, "mount": MOUNT, "path": p,
                                                     "delete_version_after": "soon"}).status_code == 422
    # With cas_required on, Browse writes still work: they always send check-and-set
    assert edit(client, env, [{"path": p, "action": "write", "expected_version": 1, "set": {"k": "w"}}])[0]["status"] == "applied"


def test_share_once_and_unwrap(client, env, caplog):
    p = f"{env.prefix}/share"
    env.a.put(p, {"user": "u", "pw": "s3cret", "other": "x"})
    with caplog.at_level(logging.INFO, logger="lockstep.audit"):
        r = client.post("/api/browse/share", json={"conn_id": env.ca, "mount": MOUNT, "path": p, "keys": ["user", "pw"], "ttl": "5m"})
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["keys"] == ["pw", "user"] and out["ttl"] == 300 and out["token"]
    line = next(json.loads(m) for m in caplog.messages if '"browse.share"' in m)
    assert line["keys"] == ["pw", "user"] and "s3cret" not in json.dumps(line)
    bob = env.connect(0, method="userpass", username="bob", password="password")  # anyone on that Vault
    look = client.post("/api/browse/unwrap", json={"conn_id": bob, "token": out["token"]}).json()
    assert look["info"]["creation_ttl"] == 300 and "data" not in look
    opened = client.post("/api/browse/unwrap", json={"conn_id": bob, "token": out["token"], "open": True}).json()
    assert opened["data"] == {"user": "u", "pw": "s3cret"}
    again = client.post("/api/browse/unwrap", json={"conn_id": bob, "token": out["token"], "open": True})
    assert again.status_code == 400 and "used already" in again.text
    assert client.post("/api/browse/share", json={"conn_id": env.ca, "mount": MOUNT, "path": p, "keys": ["nope"]}).status_code == 400


@pytest.fixture
def limited_user(env, vaults):
    """A user who may see a secret's structure (subkeys) and patch it, but not read or update it."""
    import httpx
    tag = env.prefix
    v = httpx.Client(base_url=f"{vaults[0]}/v1/", headers={"X-Vault-Token": "root-a"}, timeout=10)
    name = f"subkeys-{tag}"
    v.put(f"sys/policies/acl/{name}", json={"policy": f'''
path "{MOUNT}/subkeys/{tag}/*" {{ capabilities = ["read"] }}
path "{MOUNT}/metadata/{tag}/*" {{ capabilities = ["read", "list"] }}
path "{MOUNT}/data/{tag}/*" {{ capabilities = ["patch"] }}
'''}).raise_for_status()
    tok = v.post("auth/token/create", json={"policies": [name], "ttl": "10m"}).json()["auth"]["client_token"]
    yield env.connect(0, token=tok)
    v.delete(f"sys/policies/acl/{name}")


def test_subkeys_when_values_cant_be_read(client, env, limited_user):
    p = f"{env.prefix}/structure"
    env.a.put(p, {"user": "u", "pw": "secret"})
    info = get(client, "secret", conn_id=limited_user, mount=MOUNT, path=p)
    assert info["read_error"] and info["keys"] == ["pw", "user"] and info["keys_only"]


def test_patch_when_update_isnt_allowed(client, env, limited_user):
    p = f"{env.prefix}/patchme"
    env.a.put(p, {"user": "u", "pw": "old", "gone": "x"})
    # This user can't read the values or update: the change goes through PATCH, planned from the
    # metadata and subkeys/.
    body = {"conn_id": limited_user, "mount": MOUNT, "confirm": True,
            "edits": [{"path": p, "action": "write", "expected_version": 1, "set": {"pw": "new"}, "remove": ["gone"]}]}
    res = client.post("/api/browse/apply", json=body).json()[0]
    assert res["status"] == "applied" and res["patch"], res
    assert env.a.get(p)[0] == {"user": "u", "pw": "new"}
