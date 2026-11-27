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
                         "unknown_rows": 0, "known_rows": 0}
    assert m.environments[0].counts == {"equal": 4, "different": 1, "missing": 1, "extra": 0, "not_compared": 0,
                                        "known": 0}
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


def test_accepted_drift():
    """An environment's accepted drift (a drift baseline): listed with the same status, a cell is
    accepted. It's still shown, but doesn't count as odd; with another status it's new."""
    results = [
        [sd("db", "different", [("user", "equal"), ("password", "different")]), sd("cache", "left_only"),
         sd("api", "different", [("url", "different")])],
        [sd("db", "different", [("user", "equal"), ("password", "different")]), sd("cache", "equal", [("ttl", "equal")]),
         sd("api", "equal", [("url", "equal")])],
    ]
    accepted = [{("db", "password"): "different", ("cache", None): "left_only", ("api", "url"): "left_only",
                 ("gone", None): "right_only"}, None]
    es = envs("staging", "dev")
    m = matrix.build(BASE, es, results, accepted=accepted)
    by = {(r.path, r.key): r for r in m.rows}
    pw = by[("db", "password")]
    assert [c.accepted for c in pw.cells] == [True, False] and pw.odd == 1 and pw.known == 1
    cache = by[("cache", None)]
    assert cache.cells[0].status == "missing" and cache.cells[0].accepted and cache.odd == 0 and cache.known == 1
    url = by[("api", "url")]
    assert not url.cells[0].accepted and url.odd == 1  # accepted as left_only, now different: new
    assert m.rows[-1].path == "cache"  # only accepted drift: listed last
    assert m.summary["known_rows"] == 1 and m.summary["differing_rows"] == 2
    assert es[0].counts["known"] == 2 and es[0].counts["different"] == 1 and es[0].accepted_unused == 2
    assert es[1].accepted is None and es[1].accepted_unused == 0


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

    # dev's flag accepted as drift: shown, but not odd any more; for other locations it's refused
    drift = {"lockstep_baseline": 1, "left": {"mount": MOUNT, "prefix": f"{three}/prod"},
             "right": {"mount": MOUNT, "prefix": f"{three}/dev"},
             "drift": [{"path": "flags", "key": "new_checkout", "status": "different"}]}
    envs3 = [{**e} for e in body["environments"][:3]]
    envs3[1] |= {"accepted": drift, "accepted_name": "dev.base.json"}
    r = client.post("/api/matrix", json={**body, "environments": envs3})
    assert r.status_code == 200, r.text
    m = r.json()
    flag = next(r for r in m["rows"] if r["key"] == "new_checkout")
    assert flag["cells"][1] == {"status": "different", "reason": flag["cells"][1]["reason"], "accepted": True}
    assert flag["odd"] == 0 and flag["known"] == 1 and m["rows"][-1]["key"] == "new_checkout"
    assert m["environments"][1]["accepted"] == "dev.base.json" and m["environments"][1]["counts"]["known"] == 1
    envs3[2] |= {"accepted": drift}
    wrong = client.post("/api/matrix", json={**body, "environments": envs3})
    assert wrong.status_code == 400 and "written for test" in wrong.json()["detail"]["message"]

    # Signed with this server's plan key: checked, and the signer shown; edited: refused
    from lockstep import driftsign, plansign
    from lockstep.cli.drift import Baseline
    from lockstep.config import get_settings
    private, _public = plansign.generate()
    monkeypatch.setattr(get_settings(), "plan_signing_key", private)
    monkeypatch.setattr(get_settings(), "plan_issuer", "release-lockstep")
    issuer, sig = driftsign.sign("baseline", Baseline.model_validate(drift).body(), plansign.keys(get_settings()))
    signed = drift | {"issuer": issuer.model_dump(), "signature": sig}
    envs3[2] = {**body["environments"][2]}
    envs3[1] |= {"accepted": signed}
    r = client.post("/api/matrix", json={**body, "environments": envs3})
    assert r.status_code == 200, r.text
    assert r.json()["environments"][1]["accepted_signer"] == "release-lockstep"
    envs3[1] |= {"accepted": signed | {"drift": [*drift["drift"], {"path": "db", "key": "password", "status": "different"}]}}
    r = client.post("/api/matrix", json={**body, "environments": envs3})
    assert r.status_code == 400 and "was changed after release-lockstep signed it" in r.json()["detail"]["message"]


def test_api_matrix_from_an_export(client, vaults, three):
    """An export file as the baseline: compared like a Vault, with no Vault behind it."""
    ca, cb = _connect(client, 0, "root-a"), _connect(client, 1, "root-b")
    r = client.post("/api/exports", json={"side": {"conn_id": ca, "mount": MOUNT, "prefix": f"{three}/prod"}, "encrypt": False})
    assert r.status_code == 200, r.text
    f = r.json()["file"]
    body = {"baseline_name": "prod", "baseline": {"export": f, "name": "prod.json"},
            "environments": [{"name": "staging", "side": {"conn_id": cb, "mount": MOUNT, "prefix": f"{three}/staging"}},
                             {"name": "dev", "side": {"conn_id": ca, "mount": MOUNT, "prefix": f"{three}/dev"}}]}
    r = client.post("/api/matrix", json=body)
    assert r.status_code == 200, r.text
    m = r.json()
    assert m["baseline"]["kind"] == "file" and m["baseline"]["secret_count"] == 3
    rows = {(r["path"], r["key"]): [c["status"] for c in r["cells"]] for r in m["rows"]}
    assert rows[("flags", "new_checkout")] == ["equal", "different"]
    assert rows[("db", "password")] == ["different", "different"]
    assert "prod-pw" not in r.text
    # accepted drift works with a file baseline too: only the environment's side is checked
    drift = {"lockstep_baseline": 1, "left": {"mount": MOUNT, "prefix": f"{three}/prod"},
             "right": {"mount": MOUNT, "prefix": f"{three}/dev"},
             "drift": [{"path": "db", "key": "password", "status": "different"}]}
    body["environments"][1] |= {"accepted": drift}
    r = client.post("/api/matrix", json=body)
    assert r.status_code == 200, r.text
    pw = next(r for r in r.json()["rows"] if r["key"] == "password")
    assert [c["accepted"] for c in pw["cells"]] == [False, True] and pw["odd"] == 1


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

    # dev-1's flag is accepted drift: marked *, and without other drift the run would pass
    (tmp_path / "dev.base.json").write_text(json.dumps({
        "lockstep_baseline": 1, "left": {"mount": MOUNT, "prefix": f"{three}/prod"},
        "right": {"mount": MOUNT, "prefix": f"{three}/dev"},
        "drift": [{"path": "flags", "key": "new_checkout", "status": "different"}]}))
    spec2 = {**spec, "environments": [{**spec["environments"][1], "accepted": "dev.base.json"}]}
    (tmp_path / "m2.yaml").write_text(yaml.safe_dump(spec2))
    rc = main(["matrix", "m2.yaml", "-o", "m2.md"])
    out = capsys.readouterr().out
    assert rc == 0, out
    assert "≠*" in out and "*: accepted drift" in out and "apart from accepted drift (1 row)" in out
    assert "≠ different (accepted)" in (tmp_path / "m2.md").read_text()
    spec2["environments"][0]["prefix"] = f"{three}/test"
    (tmp_path / "m3.yaml").write_text(yaml.safe_dump(spec2))
    assert main(["matrix", "m3.yaml"]) == 2
    assert "is for dev-1" in capsys.readouterr().err

    (tmp_path / "bad.yaml").write_text(yaml.safe_dump({"baseline": spec["baseline"],
                                                       "environments": [{"name": "prod"}]}))
    assert main(["matrix", "bad.yaml"]) == 2
    assert "different name" in capsys.readouterr().err
