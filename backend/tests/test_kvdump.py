"""`vault kv get -format=json` output read as an export: one file, a folder, or a path: output map."""

import json

import pytest

from lockstep import exports as ex
from lockstep import kvdump
from test_exports import cli_env, env  # noqa: F401  (fixtures)


def kv2(data, version=3, deleted=False, destroyed=False):
    return {"request_id": "r", "lease_id": "", "lease_duration": 0, "renewable": False, "warnings": None, "mount_type": "kv",
            "data": {"data": None if deleted or destroyed else data,
                     "metadata": {"version": version, "created_time": "2026-11-01T10:00:00.5Z", "custom_metadata": None,
                                  "deletion_time": "2026-11-02T00:00:00Z" if deleted else "", "destroyed": destroyed}}}


def kv1(data):
    return {"request_id": "r", "lease_id": "", "lease_duration": 2764800, "renewable": False, "data": data, "warnings": None}


def test_one_file_a_folder_and_a_map():
    doc = kvdump.convert([("db.json", kv2({"user": "app", "port": 5432}))], "db.json")
    assert doc.source.vault == "db.json" and doc.source.mount == "vault kv get" and doc.tool.endswith("from vault kv get")
    assert [s.model_dump() for s in doc.secrets] == [{"path": "db", "version": 3, "updated": "2026-11-01T10:00:00.5Z",
                                                      "data": {"user": "app", "port": 5432}, "keep": False}]
    doc = kvdump.convert([("services/billing/db.json", kv2({"k": "1"})), ("services/web.JSON", kv1({"k": "2"})),
                          ("old.json", kv2({}, deleted=True)), ("gone.json", kv2({}, destroyed=True))], "dump")
    assert [(s.path, s.version) for s in doc.secrets] == [("services/billing/db", 3), ("services/web", None)]
    assert doc.skipped.deleted == ["gone", "old"]
    doc = kvdump.convert([("app.json", {"app/db": kv2({"k": "v"}), "/app/web/": kv1({"x": 1})})], "app.json")
    assert [s.path for s in doc.secrets] == ["app/db", "app/web"]
    # It's an ordinary export: it serialises, opens and prepares like one
    assert ex.load(doc.dump()) == doc and ex.prepare(doc, None).doc.secrets


@pytest.mark.parametrize("files, msg", [
    ([("x.json", {"user": "app"})], "isn't a Lockstep export or `vault kv get -format=json` output"),
    ([("a.json", kv1({"k": 1})), ("b/../a.json", kv1({"k": 2}))], "can't be a secret path"),
    ([("a.json", kv1({"k": 1})), ("m.json", {"a": kv1({"k": 2})})], "a appears twice"),
    ([("a.json", kv1(["not", "an", "object"]))], "isn't an object of keys and values"),
    ([], "No files"),
])
def test_refused(files, msg):
    with pytest.raises(ex.ExportError, match=msg):
        kvdump.convert(files, "x")


def test_api(client):
    r = client.post("/api/exports/from-kv-get", json={"name": "dump", "files": [
        {"name": "a/b.json", "content": kv2({"k": "v"})}, {"name": "c.json", "content": kv2({}, deleted=True)}]})
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["encrypted"] is False and out["export"]["secrets"][0]["path"] == "a/b"
    assert out["export"]["skipped"]["deleted"] == ["c"]
    r = client.post("/api/exports/from-kv-get", json={"files": [{"name": "x.json", "content": {"k": "v"}}]})
    assert r.status_code == 400 and "isn't a Lockstep export" in r.json()["detail"]["message"]


def test_cli_imports_a_folder_and_a_map(cli_env, monkeypatch, capsys):  # noqa: F811
    from lockstep.cli import main
    e = cli_env
    (e.dir / "dump" / "billing").mkdir(parents=True)
    (e.dir / "dump" / "billing" / "db.json").write_text(json.dumps(kv2({"user": "billing"})))
    (e.dir / "dump" / "web.json").write_text(json.dumps(kv1({"port": "80"})))
    (e.dir / "map.json").write_text(json.dumps({"api/key": kv2({"token": "t"})}))
    monkeypatch.setenv("VAULT_TOKEN", "root-b")
    base = ["--vault-addr", e.addr_b, "--mount", "app-config", "--prefix", e.prefix, "--yes"]
    assert main(["import", "dump"] + base) == 0
    assert "Wrote 2 secrets." in capsys.readouterr().out
    assert main(["import", "map.json"] + base) == 0
    assert e.b.get(f"{e.prefix}/billing/db")[0] == {"user": "billing"} and e.b.get(f"{e.prefix}/web")[0] == {"port": "80"}
    assert e.b.get(f"{e.prefix}/api/key")[0] == {"token": "t"}
    (e.dir / "bad.json").write_text(json.dumps({"user": "app"}))
    assert main(["import", "bad.json"] + base) == 2
    assert "isn't a Lockstep export or `vault kv get -format=json` output" in capsys.readouterr().err
