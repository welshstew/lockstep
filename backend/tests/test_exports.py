"""Secret-engine export and import: the format, encryption, import rules, and the API
(export, open, compare against a file, copy from a file, import with transforms)."""

import json
import logging
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from lockstep import exports as ex
from lockstep.config import Settings, get_settings
from lockstep.main import create_app

SCHEMAS = Path(__file__).resolve().parents[2] / "schemas"


def doc(*secrets: tuple[str, dict], **source) -> ex.ExportDoc:
    return ex.ExportDoc(created_at="2026-11-10T12:00:00Z",
                        source=ex.ExportSource(vault="Vault A", mount="app-config", **source),
                        secrets=[ex.ExportSecret(path=p, version=1, data=d) for p, d in secrets])


# --------------------------------------------------------------------------- unit: encryption


def test_encrypt_round_trip_and_key_format():
    d = doc(("db", {"password": "s3cret", "port": 5432}))
    env, key = ex.encrypt(d)
    assert key.startswith("lsk1.") and len(key) == 5 + 43
    raw = json.dumps(env.dump())
    assert "s3cret" not in raw and "password" not in raw  # values and key names are inside the ciphertext
    assert env.source.secrets == 1 and env.source.vault == "Vault A"
    back = ex.load(json.loads(raw), key)
    assert back == d


def test_wrong_key_and_tampering_are_refused():
    env, key = ex.encrypt(doc(("db", {"k": "v"})))
    other = ex.new_key()[1]
    with pytest.raises(ex.ExportError, match="Wrong key"):
        ex.load(env.dump(), other)
    tampered = env.dump() | {"source": env.dump()["source"] | {"vault": "Somewhere else"}}
    with pytest.raises(ex.ExportError, match="Wrong key, or the file was changed"):
        ex.load(tampered, key)  # the readable header is authenticated too
    with pytest.raises(ex.ExportError, match="encrypted: enter its key"):
        ex.load(env.dump())
    for bad in ("nope", "lsk1.!!!", "lsk1.AAAA"):
        with pytest.raises(ex.ExportError):
            ex.load(env.dump(), bad)


def test_not_an_export():
    for obj in ({}, [], {"format": "lockstep.sync-plan"}, {"format": ex.FORMAT, "version": 2}):
        with pytest.raises(ex.ExportError):
            ex.load(obj)
    with pytest.raises(ex.ExportError, match="isn't valid"):
        ex.load({"format": ex.FORMAT, "version": 1, "secrets": "x"})


# --------------------------------------------------------------------------- unit: import rules


def prep(d, **rules):
    return ex.prepare(d, ex.ImportRules.model_validate(rules))


def by_path(p: ex.Prepared) -> dict:
    return {s.path: s.data for s in p.doc.secrets}


def test_ignores_then_transforms_in_order():
    d = doc(("dev/app", {"env": "application-dev-env", "dba": "devDBA", "port": 5432, "note": "keep"}),
            ("dev/old", {"x": "1"}),
            ("shared/cfg", {"env": "application-dev-env", "token": "t"}))
    p = prep(d, ignore_paths=["dev/old"], ignore_keys=[{"key": "token", "path": "shared/**"}], transforms=[
        {"op": "replace", "find": "application-dev-env", "with": "application-test-env"},
        {"op": "replace", "find": "devDBA", "with": "testDBA", "key": "dba"},
        {"op": "replace", "find": "dev/", "with": "test/", "target": "paths"},
        {"op": "upper", "target": "keys", "path": "test/**"},  # sees the path after the rename
    ])
    assert by_path(p) == {
        "test/app": {"ENV": "application-test-env", "DBA": "testDBA", "PORT": 5432, "NOTE": "keep"},
        "shared/cfg": {"env": "application-test-env"},
    }
    assert (p.ignored_paths, p.ignored_keys, p.paths_changed, p.keys_changed, p.values_changed) == (1, 1, 1, 4, 3)
    assert d.secrets[0].data["env"] == "application-dev-env"  # the original is untouched


def test_prefix_suffix_lower_and_key_filter():
    p = prep(doc(("a", {"url": "Example.COM", "name": "svc"})), transforms=[
        {"op": "lower", "key": "url"}, {"op": "prefix", "with": "https://", "key": "url"},
        {"op": "suffix", "with": "-test", "key": "name"}])
    assert by_path(p) == {"a": {"url": "https://example.com", "name": "svc-test"}}


def test_collisions_and_empty_results_are_left_out_with_a_reason():
    d = doc(("dev/a", {"k": "1"}), ("test/a", {"k": "2"}), ("b", {"x": "1", "X": "2"}), ("c", {"only": "v"}))
    p = prep(d, ignore_keys=[{"key": "only"}], transforms=[
        {"op": "replace", "find": "dev/", "with": "test/", "target": "paths"},
        {"op": "upper", "target": "keys", "path": "b"}])
    assert set(by_path(p)) == set()  # both a's collide, b's keys collide, c lost its only key
    assert "2 secrets become 'test/a'" in p.problems["dev/a"] and "test/a" in p.problems
    assert p.problems["b"] == "two keys become 'X'"
    assert p.ignored_paths == 1  # c: every key ignored


def test_replace_needs_text_to_find():
    with pytest.raises(ValueError):
        ex.ImportRules.model_validate({"transforms": [{"op": "replace", "find": ""}]})


def test_published_schemas_match_the_code():
    assert json.loads((SCHEMAS / "lockstep-export-v1.json").read_text()) == ex.schema()
    assert json.loads((SCHEMAS / "lockstep-import-rules-v1.json").read_text()) == ex.rules_schema()


# --------------------------------------------------------------------------- API against the Vaults


@pytest.fixture
def env(client, vaults):
    from test_sync import Raw
    prefix = f"exptest-{uuid.uuid4().hex[:8]}"
    a, b = Raw(vaults[0], "root-a"), Raw(vaults[1], "root-b")

    def connect(preset, token):
        r = client.post("/api/connections", json={"preset_id": preset, "auth": {"method": "token", "token": token}})
        assert r.status_code == 201, r.text
        return r.json()["id"]

    class E:
        pass

    e = E()
    e.prefix, e.a, e.b, e.ca, e.cb = prefix, a, b, connect(0, "root-a"), connect(1, "root-b")
    e.side_a = {"conn_id": e.ca, "mount": "app-config", "prefix": prefix}
    e.side_b = {"conn_id": e.cb, "mount": "app-config", "prefix": prefix}

    def export(encrypt=False, rules=None, side=None):
        r = client.post("/api/exports", json={"side": side or e.side_a, "encrypt": encrypt, "rules": rules or {}})
        assert r.status_code == 200, r.text
        return r.json()

    e.export = export
    yield e
    a.purge(prefix)
    b.purge(prefix)


def test_export_plain_with_rules(env):
    env.a.put(f"{env.prefix}/db", {"user": "app", "password": "pw", "port": 5432})
    env.a.put(f"{env.prefix}/legacy/x", {"k": "v"})
    env.a.put(f"{env.prefix}/gone", {"k": "v"})
    env.a.c.delete(f"app-config/data/{env.prefix}/gone")  # latest version deleted
    out = env.export(rules={"ignore_paths": ["legacy/**"], "ignore_keys": [{"key": "password", "path": "**"}]})
    assert out["key"] is None and out["secrets"] == 1 and out["keys"] == 2
    f = out["file"]
    assert f["format"] == "lockstep.secret-export" and f["$schema"] == ex.SCHEMA_URL
    assert f["source"] | {} == {"vault": "Vault A", "url": None, "namespace": None, "mount": "app-config",
                                "prefix": env.prefix, "identity": "token"}
    assert f["secrets"] == [{"path": "db", "version": 1, "updated": f["secrets"][0]["updated"],
                             "data": {"user": "app", "port": 5432}}]
    assert f["skipped"]["ignored_paths"] == 1 and f["skipped"]["ignored_keys"] == 1
    assert f["skipped"]["deleted"] == ["gone"]
    assert out["filename"].startswith(f"lockstep-export-Vault_A-app-config-{env.prefix}-")


def test_export_encrypted_open_and_audit(env, client):
    env.a.put(f"{env.prefix}/db", {"password": "very-secret-pw"})
    records: list[str] = []

    class H(logging.Handler):
        def emit(self, rec):
            records.append(rec.getMessage())

    log = logging.getLogger("lockstep.audit")
    h = H()
    log.addHandler(h)
    try:
        out = env.export(encrypt=True)
    finally:
        log.removeHandler(h)
    assert out["file"]["format"] == "lockstep.secret-export.encrypted" and out["key"].startswith("lsk1.")
    assert "very-secret-pw" not in json.dumps(out["file"])
    assert out["filename"].endswith(".encrypted.json")
    entry = json.loads(records[0])
    assert entry["event"] == "export" and entry["encrypted"] is True and entry["secrets"] == 1
    assert "very-secret-pw" not in records[0] and out["key"] not in records[0]

    r = client.post("/api/exports/open", json={"file": out["file"], "key": out["key"]})
    assert r.status_code == 200 and r.json()["encrypted"] is True
    assert r.json()["export"]["secrets"][0]["data"] == {"password": "very-secret-pw"}
    r = client.post("/api/exports/open", json={"file": out["file"]})
    assert r.status_code == 400 and r.json()["detail"]["needs_key"] is True
    r = client.post("/api/exports/open", json={"file": out["file"], "key": ex.new_key()[1]})
    assert r.status_code == 400 and "Wrong key" in r.json()["detail"]["message"]


@pytest.mark.parametrize("mode, encrypt, status", [("off", True, 403), ("encrypted", False, 403),
                                                  ("encrypted", True, 200)])
def test_export_mode_setting(vaults, mode, encrypt, status):
    app = create_app()
    base = get_settings().model_dump()
    app.dependency_overrides[get_settings] = lambda: Settings(**(base | {"export_mode": mode}))
    with TestClient(app, headers={"X-Requested-With": "lockstep"}) as c:
        cid = c.post("/api/connections", json={"preset_id": 0, "auth": {"method": "token", "token": "root-a"}}).json()["id"]
        assert c.get("/api/config").json()["export_mode"] == mode
        r = c.post("/api/exports", json={"side": {"conn_id": cid, "mount": "app-config", "prefix": "payments"},
                                         "encrypt": encrypt})
        assert r.status_code == status, r.text


def test_compare_a_vault_with_an_export(env, client):
    env.a.put(f"{env.prefix}/db", {"password": "A", "user": "app"})
    env.a.put(f"{env.prefix}/only-in-file", {"k": "v"})
    env.b.put(f"{env.prefix}/db", {"password": "B", "user": "app"})
    env.b.put(f"{env.prefix}/only-in-b", {"k": "v"})
    f = env.export()["file"]
    r = client.post("/api/compare", json={"left": {"export": f, "name": "a.json"}, "right": env.side_b})
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["left"]["kind"] == "file" and out["right"]["kind"] == "vault"
    status = {s["path"]: s["status"] for s in out["secrets"]}
    assert status == {"db": "different", "only-in-file": "left_only", "only-in-b": "right_only"}


def test_copy_from_an_export_but_never_into_one(env, client):
    env.a.put(f"{env.prefix}/db", {"password": "from-file"})
    env.b.put(f"{env.prefix}/db", {"password": "B", "extra": "keep"})
    f = env.export()["file"]
    sides = {"left": {"export": f, "name": "a.json"}, "right": env.side_b}
    d = client.post("/api/compare", json=sides).json()["secrets"][0]
    to_vault = {"path": "db", "direction": "left_to_right", "keys": None,
                "expected_target_version": d["right"]["version"], "expected_source_version": d["left"]["version"]}
    r = client.post("/api/sync/apply", json=sides | {"changes": [to_vault], "confirm": True}).json()
    assert r["summary"]["applied"] == 1
    assert env.b.get(f"{env.prefix}/db")[0] == {"password": "from-file", "extra": "keep"}

    to_file = to_vault | {"direction": "right_to_left", "expected_target_version": d["left"]["version"]}
    p = client.post("/api/sync/preview", json=sides | {"changes": [to_file]}).json()[0]
    assert p["status"] == "denied"
    assert client.post("/api/plans", json=sides | {"changes": [to_vault]}).status_code == 400


def test_import_with_transforms_preview_apply_and_cas(env, client):
    env.a.put(f"{env.prefix}/dev/app", {"env": "application-dev-env", "dba": "devDBA", "port": 5432})
    env.a.put(f"{env.prefix}/dev/skip", {"k": "v"})
    env.b.put(f"{env.prefix}/test/app", {"env": "old", "only_b": "keep"})
    f = env.export()["file"]
    target = env.side_b
    rules = {"ignore_paths": ["dev/skip"], "transforms": [
        {"op": "replace", "find": "-dev-", "with": "-test-"},
        {"op": "replace", "find": "devDBA", "with": "testDBA"},
        {"op": "replace", "find": "dev/", "with": "test/", "target": "paths"}]}
    body = {"export": f, "name": "a.json", "rules": rules, "target": target}

    pv = client.post("/api/import/preview", json=body | {"reveal": True})
    assert pv.status_code == 200, pv.text
    out = pv.json()
    assert out["prepared"] | {"problems": []} == {"secrets": 1, "ignored_paths": 1, "ignored_keys": 0,
                                                  "paths_changed": 1, "keys_changed": 0, "values_changed": 2,
                                                  "problems": []}
    (plan,) = out["plans"]
    assert plan["status"] == "ready" and plan["target"]["path"] == f"{env.prefix}/test/app"
    keys = {k["key"]: (k["action"], k["source_value"]) for k in plan["keys"]}
    assert keys == {"env": ("update", "application-test-env"), "dba": ("add", "testDBA"), "port": ("add", 5432)}

    expected = {p["path"]: p["target"]["version"] for p in out["plans"] if p["status"] == "ready"}
    r = client.post("/api/import/apply", json=body | {"expected": expected, "confirm": True}).json()
    assert r["summary"]["applied"] == 1
    assert env.b.get(f"{env.prefix}/test/app")[0] == {"env": "application-test-env", "dba": "testDBA",
                                                     "port": 5432, "only_b": "keep"}
    again = client.post("/api/import/preview", json=body).json()["plans"][0]
    assert again["status"] == "noop"

    # Changed since the preview: check-and-set refuses
    env.b.put(f"{env.prefix}/test/app", {"env": "edited meanwhile"})
    r = client.post("/api/import/apply", json=body | {"expected": expected, "confirm": True}).json()
    assert r["results"][0]["status"] == "conflict"
    assert client.post("/api/import/apply", json=body | {"expected": {"nope": None}, "confirm": True}).status_code == 400
    assert client.post("/api/import/apply", json=body | {"expected": expected, "confirm": False}).status_code == 400


# --------------------------------------------------------------------------- CLI


@pytest.fixture
def cli_env(env, monkeypatch, tmp_path, vaults):
    for var in ("VAULT_ADDR", "VAULT_TOKEN", "LOCKSTEP_EXPORT_KEY", "LOCKSTEP_VAULT_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.chdir(tmp_path)
    env.dir = tmp_path
    env.addr_a, env.addr_b = vaults
    return env


def test_cli_export_encrypted_then_import_with_rules(cli_env, monkeypatch, capsys):
    from lockstep.cli import main
    e = cli_env
    e.a.put(f"{e.prefix}/dev/app", {"env": "application-dev-env", "token": "t", "port": 1})
    e.a.put(f"{e.prefix}/dev/skip", {"k": "v"})
    monkeypatch.setenv("VAULT_TOKEN", "root-a")
    rc = main(["export", "--vault-addr", e.addr_a, "--mount", "app-config", "--prefix", e.prefix,
               "-o", "x.json", "--key-file", "x.key", "--ignore-key", "token"])
    assert rc == 0, capsys.readouterr()
    out = capsys.readouterr().out
    assert "Exported 2 secrets (3 keys)" in out and "(encrypted)" in out and "Left out by the rules: 0 secret(s), 1 key(s)" in out
    assert oct((e.dir / "x.json").stat().st_mode & 0o777) == "0o600" and (e.dir / "x.key").read_text().startswith("lsk1.")
    assert json.loads((e.dir / "x.json").read_text())["format"] == ex.ENCRYPTED_FORMAT

    (e.dir / "rules.yaml").write_text("ignore_paths: [dev/skip]\ntransforms:\n"
                                      "  - {op: replace, target: paths, find: dev/, with: test/}\n")
    monkeypatch.setenv("VAULT_TOKEN", "root-b")
    args = ["import", "x.json", "--vault-addr", e.addr_b, "--mount", "app-config", "--prefix", e.prefix,
            "--key-file", "x.key", "--rules", "rules.yaml", "--replace=-dev-=-test-"]
    assert main(args + ["--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "new       test/app  env (add), port (add)" in out and "Dry run: nothing written." in out
    assert e.b.get(f"{e.prefix}/test/app")[0] is None

    assert main(args + ["--yes"]) == 0
    assert "Wrote 1 secret." in capsys.readouterr().out
    assert e.b.get(f"{e.prefix}/test/app")[0] == {"env": "application-test-env", "port": 1}
    assert main(args + ["--yes"]) == 0
    assert "0 to write, 1 already the same." in capsys.readouterr().out


def test_cli_import_needs_the_key_and_a_terminal(cli_env, monkeypatch, capsys):
    from lockstep.cli import main
    e = cli_env
    e.a.put(f"{e.prefix}/x", {"k": "v"})
    monkeypatch.setenv("VAULT_TOKEN", "root-a")
    assert main(["export", "--vault-addr", e.addr_a, "--mount", "app-config", "--prefix", e.prefix, "-o", "x.json",
                 "--key-file", "x.key"]) == 0
    capsys.readouterr()
    base = ["import", "x.json", "--vault-addr", e.addr_b, "--mount", "app-config", "--prefix", e.prefix]
    assert main(base) == 2
    assert "encrypted: enter its key" in capsys.readouterr().err
    monkeypatch.setenv("LOCKSTEP_EXPORT_KEY", (e.dir / "x.key").read_text())
    assert main(base) == 2  # stdin isn't a terminal under pytest
    assert "add --yes or --dry-run" in capsys.readouterr().err


def test_cli_export_plain_to_stdout_and_schemas(cli_env, monkeypatch, capsys):
    from lockstep.cli import main
    e = cli_env
    e.a.put(f"{e.prefix}/x", {"k": "v"})
    monkeypatch.setenv("VAULT_TOKEN", "root-a")
    assert main(["export", "--vault-addr", e.addr_a, "--mount", "app-config", "--prefix", e.prefix,
                 "--no-encrypt", "-o", "-"]) == 0
    cap = capsys.readouterr()
    assert json.loads(cap.out)["secrets"][0]["data"] == {"k": "v"} and "PLAIN TEXT" in cap.err
    for kind, fn in (("export", ex.schema), ("import-rules", ex.rules_schema)):
        assert main(["schema", kind]) == 0
        assert json.loads(capsys.readouterr().out) == fn()
