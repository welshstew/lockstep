"""The environment matrix: one baseline against several environments, odd one out first."""

import json
import uuid

import pytest
import yaml

from lockstep import matrix
from lockstep.diff import KeyDiff, SecretDiff, SideInfo
from test_sync import MOUNT, Raw

P = SideInfo(state="present")
A = SideInfo(state="absent")


def sd(path, status, keys=(), left=P, right=P):
    return SecretDiff(path=path, left_path=path, right_path=path, status=status, left=left, right=right,
                      keys=[KeyDiff(key=k, status=s, **({"ignored": True} if ign else {})) for k, s, ign in
                            ((*k, False) if len(k) == 2 else k for k in keys)])


def envs(*names):
    return [matrix.MatrixEnv(name=n, mount="m", prefix="") for n in names]


BASE = matrix.MatrixBaseline(name="prod", mount="m", prefix="")


def test_odd_one_out_first_and_cells():
    eq = [("user", "equal"), ("password", "different")]  # passwords differ everywhere: on purpose
    results = [
        [sd("db", "different", eq), sd("api", "equal", [("url", "equal")]), sd("cache", "left_only")],
        [sd("db", "different", [("user", "different"), ("password", "different")]),
         sd("api", "equal", [("url", "equal")]), sd("cache", "equal", [("ttl", "equal")])],
        [sd("db", "different", eq), sd("api", "different", [("url", "equal"), ("debug", "right_only")]),
         sd("cache", "equal", [("ttl", "equal")]), sd("extra", "right_only", right=P, left=A)],
    ]
    m = matrix.build(BASE, envs("staging", "dev", "test"), results)
    got = [(r.path, r.key, [c.status for c in r.cells]) for r in m.rows]
    # one environment out of three first, then all three; equal rows hidden
    assert got == [
        ("api", "debug", ["absent", "absent", "extra"]),
        ("cache", None, ["missing", "equal", "equal"]),
        ("db", "user", ["equal", "different", "equal"]),
        ("extra", None, ["absent", "absent", "extra"]),
        ("db", "password", ["different", "different", "different"]),
    ]
    assert m.summary == {"environments": 3, "failed": 0, "rows": 9, "odd_one_out": 4, "differing_rows": 5,
                         "unknown_rows": 0}
    assert m.environments[0].counts == {"equal": 4, "different": 1, "missing": 1, "extra": 0, "not_compared": 0}
    full = matrix.build(BASE, envs("staging", "dev", "test"), results, include_equal=True)
    assert len(full.rows) == 9 and full.rows[-1].odd == 0


def test_ignored_failed_and_unknown():
    results = [
        [sd("db", "equal", [("password", "different", True)])],
        None,  # the comparison failed
        [sd("db", "not_compared", [("password", "not_compared")]),
         sd("locked", "no_access", left=P, right=SideInfo(state="no_access"))],
    ]
    es = envs("a", "b", "c")
    es[1].error = "permission denied"
    m = matrix.build(BASE, es, results)
    by = {(r.path, r.key): r for r in m.rows}
    pw = by[("db", "password")]
    assert [c.status for c in pw.cells] == ["equal", "not_compared", "not_compared"]
    assert pw.cells[0].reason == "ignored by the profile" and pw.cells[1].reason == "the comparison failed"
    assert pw.odd == 0 and pw.unknown == 1  # a failed environment isn't counted as unknown per row
    assert by[("locked", None)].cells[2].reason == "this environment can't be read"
    assert m.summary["failed"] == 1 and m.summary["unknown_rows"] == 2 and m.summary["differing_rows"] == 0


# --------------------------------------------------------------------------- against the dev Vaults


@pytest.fixture
def three(vaults):
    """prod on Vault A; staging on Vault B, dev and test on Vault A under other prefixes."""
    a, b = Raw(vaults[0], "root-a"), Raw(vaults[1], "root-b")
    p = f"matrix-{uuid.uuid4().hex[:6]}"
    data = {"db": {"user": "svc", "password": "prod-pw", "host": "db.internal"}, "api": {"url": "https://api"},
            "flags": {"new_checkout": "off"}}
    for path, d in data.items():
        a.put(f"{p}/prod/{path}", d)
    b.put(f"{p}/staging/db", {**data["db"], "password": "stg-pw"})
    b.put(f"{p}/staging/api", data["api"])
    b.put(f"{p}/staging/flags", data["flags"])
    a.put(f"{p}/dev/db", {**data["db"], "password": "dev-pw"})
    a.put(f"{p}/dev/api", data["api"])
    a.put(f"{p}/dev/flags", {"new_checkout": "on"})  # the odd one out
    a.put(f"{p}/test/db", {**data["db"], "password": "test-pw", "host": "db-test.internal"})
    a.put(f"{p}/test/api", data["api"])
    a.put(f"{p}/test/flags", data["flags"])
    yield p
    a.purge(p)
    b.purge(p)


def _connect(client, preset, token):
    r = client.post("/api/connections", json={"preset_id": preset, "auth": {"method": "token", "token": token}})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def test_api_matrix(client, vaults, three, monkeypatch):
    from lockstep.vault import VaultClient, VaultError
    real = VaultClient.kv_tree

    async def kv_tree(self, mount, *a, **kw):
        if mount == "broken":
            raise VaultError(500, "Vault is having a bad day")
        return await real(self, mount, *a, **kw)
    monkeypatch.setattr(VaultClient, "kv_tree", kv_tree)
    ca, cb = _connect(client, 0, "root-a"), _connect(client, 1, "root-b")
    side = lambda c, e: {"conn_id": c, "mount": MOUNT, "prefix": f"{three}/{e}"}  # noqa: E731
    ignore_pw = {"ignore_keys": [{"key": "password", "path": "**"}]}
    body = {"baseline_name": "prod", "baseline": side(ca, "prod"),
            "environments": [{"name": "staging", "side": side(cb, "staging"), "rules": ignore_pw},
                             {"name": "dev", "side": side(ca, "dev"), "rules": ignore_pw},
                             {"name": "test", "side": side(ca, "test"), "rules": ignore_pw},
                             {"name": "nowhere", "side": {"conn_id": cb, "mount": "broken", "prefix": ""}}]}
    r = client.post("/api/matrix", json=body)
    assert r.status_code == 200, r.text
    m = r.json()
    assert [e["name"] for e in m["environments"]] == ["staging", "dev", "test", "nowhere"]
    assert m["environments"][3]["error"] == "Vault is having a bad day" and m["summary"]["failed"] == 1
    assert m["baseline"]["secret_count"] == 3
    rows = [(r["path"], r["key"], [c["status"] for c in r["cells"]]) for r in m["rows"]]
    assert rows[:2] == [("db", "host", ["equal", "equal", "different", "not_compared"]),
                        ("flags", "new_checkout", ["equal", "different", "equal", "not_compared"])]
    assert all(r["key"] != "password" for r in m["rows"])  # ignored by each pair's profile
    assert "prod-pw" not in r.text and "dev-pw" not in r.text  # never a value

    same = client.post("/api/matrix", json={**body, "baseline_name": "staging"})
    assert same.status_code == 400 and "different name" in same.json()["detail"]["message"]


def test_cli_matrix(vaults, three, tmp_path, monkeypatch, capsys):
    from lockstep.cli import main
    for var in ("VAULT_ADDR", "VAULT_TOKEN", "VAULT_NAMESPACE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("LOCKSTEP_PROD_TOKEN", "root-a")
    monkeypatch.setenv("LOCKSTEP_STAGING_TOKEN", "root-b")
    monkeypatch.setenv("LOCKSTEP_DEV_1_TOKEN", "root-a")
    monkeypatch.chdir(tmp_path)
    (tmp_path / "profiles").mkdir()
    (tmp_path / "profiles" / "ignore.yaml").write_text(yaml.safe_dump(
        {"name": "ignore passwords", "rules": {"ignore_keys": [{"key": "password", "path": "**"}]}}))
    spec = {"baseline": {"name": "prod", "addr": vaults[0], "mount": MOUNT, "prefix": f"{three}/prod"},
            "environments": [
                {"name": "staging", "addr": vaults[1], "prefix": f"{three}/staging", "profile": "profiles/ignore.yaml"},
                {"name": "dev-1", "prefix": f"{three}/dev", "profile": "profiles/ignore.yaml"},
                {"name": "test", "prefix": f"{three}/test"}]}  # same Vault as prod: shares its login
    (tmp_path / "m.yaml").write_text(yaml.safe_dump(spec))
    rc = main(["matrix", "m.yaml", "-o", "m.json", "-o", "m.md", "-o", "m.csv"])
    out = capsys.readouterr().out
    assert rc == 1, out
    lines = out.splitlines()
    grid = [ln.split() for ln in lines if ln.startswith("  db") or ln.startswith("  flags")]
    assert grid == [["db", "·", "host", "=", "=", "≠"], ["db", "·", "password", "=", "=", "≠"],
                    ["flags", "·", "new_checkout", "=", "≠", "="]]
    assert "in only one environment (listed first)" in out
    m = json.loads((tmp_path / "m.json").read_text())
    pw = next(r for r in m["rows"] if r["key"] == "password")
    assert [c["status"] for c in pw["cells"]] == ["equal", "equal", "different"]  # test has no profile
    assert "| `flags` | `new_checkout` | = | ≠ different | = |" in (tmp_path / "m.md").read_text()
    assert (tmp_path / "m.csv").read_text().splitlines()[0] == "secret,key,staging,dev-1,test"
    assert not any(v in (tmp_path / "m.json").read_text() for v in ("prod-pw", "test-pw", "db-test"))  # no values

    (tmp_path / "bad.yaml").write_text(yaml.safe_dump({"baseline": spec["baseline"],
                                                       "environments": [{"name": "prod"}]}))
    assert main(["matrix", "bad.yaml"]) == 2
    assert "different name" in capsys.readouterr().err
