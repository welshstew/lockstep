"""The command-line interface: report building, editing mistakes, and compare/apply against
the compose Vaults. Each integration test works in its own random prefix."""

import asyncio
import io
import uuid

import pytest
import yaml

from lockstep.cli import main
from lockstep.cli import report as rpt
from lockstep.cli.connect import CliError

MOUNT = "app-config"


# --------------------------------------------------------------------------- pure


def test_ui_url_and_cli_command():
    assert rpt.ui_url("https://v.example:8200/", None, "app-config", "odd names/with space") == \
        "https://v.example:8200/ui/vault/secrets/app-config/kv/odd%20names%2Fwith%20space/details"
    assert rpt.ui_url("https://v", "team/a", "kv", "x").endswith("/kv/x/details?namespace=team%2Fa")
    assert rpt.cli_command("https://v", "ns1", "app config", "a b/c") == \
        "vault kv get -address=https://v -namespace=ns1 '-mount=app config' 'a b/c'"


def _report(**secret_overrides) -> dict:
    s = {
        "path": "svc/db", "status": "different", "action": "per-key",
        "left": {"path": "pre/svc/db", "state": "present", "version": 3},
        "right": {"path": "pre/svc/db", "state": "present", "version": 5},
        "keys": [{"key": "password", "status": "different", "action": "skip"},
                 {"key": "only_left", "status": "left_only", "action": "skip"},
                 {"key": "only_right", "status": "right_only", "action": "skip"}],
    }
    s.update(secret_overrides)
    return {"lockstep_report": 1, "created": "2026-11-09T00:00:00Z",
            "left": {"name": "a", "addr": "http://a", "mount": "m", "prefix": "pre"},
            "right": {"name": "b", "addr": "http://b", "mount": "m", "prefix": "pre"},
            "secrets": [s]}


def _plan(raw: dict):
    return rpt.plan(rpt.load(yaml.safe_dump(raw), "test.yaml"))


def test_plan_per_key_actions_group_by_direction():
    raw = _report()
    raw["secrets"][0]["keys"][0]["action"] = "copy-to-right"
    raw["secrets"][0]["keys"][1]["action"] = "copy-to-right"
    raw["secrets"][0]["keys"][2]["action"] = "copy-to-left"
    changes = {c.direction: c for _, c in _plan(raw)}
    lr, rl = changes["left_to_right"], changes["right_to_left"]
    assert lr.path == "svc/db" and lr.right_path is None  # relative to the prefix
    assert lr.keys == ["password", "only_left"]
    assert (lr.expected_source_version, lr.expected_target_version) == (3, 5)
    assert rl.keys == ["only_right"]
    assert (rl.expected_source_version, rl.expected_target_version) == (5, 3)


def test_plan_whole_secret_and_new_target():
    raw = _report(status="left_only", action="copy-to-right",
                  right={"path": "pre/svc/db", "state": "absent"},
                  keys=[{"key": "k", "status": "left_only"}])
    [(_, c)] = _plan(raw)
    assert c.keys is None and c.expected_target_version is None


def test_plan_nothing_set_is_empty():
    assert _plan(_report()) == []


@pytest.mark.parametrize("edit, message", [
    (lambda s: s["keys"][2].update(action="copy-to-right"), "only_right can't be copy-to-right"),
    (lambda s: s["keys"][1].update(action="copy-to-left"), "only_left can't be copy-to-left"),
    (lambda s: s.update(action="copy-to-left", right={"path": "pre/svc/db", "state": "absent"}),
     "needs the right side to have the secret"),
    (lambda s: (s.update(action="copy-to-right"), s["keys"][0].update(action="copy-to-left")), "not both"),
    (lambda s: (s.update(status="no_access"), s["keys"][0].update(action="copy-to-right")), "couldn't read both"),
    (lambda s: (s["left"].update(path="elsewhere/svc/db"), s["keys"][0].update(action="copy-to-right")),
     "isn't under the left prefix"),
])
def test_plan_rejects_impossible_actions(edit, message):
    raw = _report()
    edit(raw["secrets"][0])
    with pytest.raises(CliError, match=message):
        _plan(raw)


def test_load_names_typos_and_bad_values():
    raw = _report()
    raw["secrets"][0]["keys"][0]["acton"] = "copy-to-right"
    raw["secrets"][0]["keys"][1]["action"] = "copy-right"
    with pytest.raises(CliError) as e:
        _plan(raw)
    msg = str(e.value)
    assert "secrets[0].keys[0].acton" in msg and "key password" in msg
    assert "secrets[0].keys[1].action" in msg and "key only_left" in msg


def test_load_rejects_other_files():
    with pytest.raises(CliError, match="isn't a Lockstep report"):
        rpt.load("a: 1\n", "x.yaml")
    with pytest.raises(CliError, match="unsupported report format"):
        rpt.load(yaml.safe_dump({**_report(), "lockstep_report": 99}), "x.yaml")


def test_profile_from_web_export(tmp_path):
    import json

    from lockstep.cli import _load_profile

    f = tmp_path / "p.json"
    f.write_text(json.dumps({"lockstep_profiles": 1, "profiles": [
        {"name": "prod-vs-staging", "left_prefix": "services", "rules": {
            "mappings": [{"left": "*/prod/**", "right": "*/staging/**"}], "ignore_keys": [{"key": "host"}]}},
        {"name": "other", "rules": {}}]}))
    with pytest.raises(CliError, match="pick one with --profile-name"):
        _load_profile(str(f), None)
    prof, rules = _load_profile(str(f), None, "prod-vs-staging")
    assert prof.left_prefix == "services" and rules.to_right("billing/prod/db") == "billing/staging/db"
    f.write_text("ignore_keys:\n  - key: host\n")  # bare rules, in YAML
    prof, rules = _load_profile(str(f), None)
    assert prof is None and rules.key_ignored("host", "any/path")


# --------------------------------------------------------------------------- against Vault


@pytest.fixture
def env(vaults, monkeypatch, tmp_path):
    """Two Vaults, root tokens per side, a random prefix with known data, and cleanup."""
    from test_sync import Raw  # same helper as the sync tests

    prefix = f"clitest-{uuid.uuid4().hex[:8]}"
    a, b = Raw(vaults[0], "root-a"), Raw(vaults[1], "root-b")
    for var in ("VAULT_ADDR", "VAULT_TOKEN", "VAULT_NAMESPACE", "LOCKSTEP_LEFT_ADDR", "LOCKSTEP_RIGHT_ADDR"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("LOCKSTEP_LEFT_TOKEN", "root-a")
    monkeypatch.setenv("LOCKSTEP_RIGHT_TOKEN", "root-b")
    monkeypatch.chdir(tmp_path)
    a.put(f"{prefix}/db", {"host": "h", "password": "A", "port": 5432})
    b.put(f"{prefix}/db", {"host": "h", "password": "B", "port": "5432", "extra": "keep me"})
    a.put(f"{prefix}/new", {"k": "v"})
    b.put(f"{prefix}/eq/same", {"x": "1"})
    a.put(f"{prefix}/eq/same", {"x": "1"})

    class E:
        pass

    e = E()
    e.a, e.b, e.prefix, e.dir = a, b, prefix, tmp_path
    e.args = ["--left-addr", vaults[0], "--right-addr", vaults[1], "--mount", MOUNT, "--prefix", prefix,
              "--left-name", "A", "--right-name", "B"]
    yield e
    a.purge(prefix)
    b.purge(prefix)


def _compare(e, capsys, *extra) -> tuple[int, dict, str]:
    rc = main(["compare", *e.args, "-o", "report.yaml", *extra])
    out = capsys.readouterr().out
    return rc, yaml.safe_load((e.dir / "report.yaml").read_text()), out


def _set(report: dict, path: str, **actions) -> None:
    s = next(s for s in report["secrets"] if s["path"] == path)
    if "secret" in actions:
        s["action"] = actions.pop("secret")
    for k in s.get("keys", []):
        if k["key"] in actions:
            k["action"] = actions[k["key"]]


def test_compare_writes_report(env, capsys):
    rc, rep, out = _compare(env, capsys)
    assert rc == 1  # differences found
    assert "different   db" in out and "differs: password, port (type)" in out
    assert "left only   new" in out and "eq/same" not in out  # equal secrets aren't listed
    assert "3 secrets: 1 equal, 1 different, 1 left only." in out
    paths = {s["path"]: s for s in rep["secrets"]}
    assert set(paths) == {"db", "new"}  # equal secrets left out
    db = paths["db"]
    assert db["left"]["cli"] == f"vault kv get -address={env.args[1]} -mount={MOUNT} {env.prefix}/db"
    assert db["right"]["ui"].endswith(f"/ui/vault/secrets/{MOUNT}/kv/{env.prefix}%2Fdb/details")
    keys = {k["key"]: k for k in db["keys"]}
    assert set(keys) == {"password", "port", "extra"} and keys["port"]["type_differs"] is True
    assert db["equal_keys"] == 1
    assert all(k["action"] == "skip" for k in db["keys"])
    text = (env.dir / "report.yaml").read_text()
    assert "s3cret" not in text and '"A"' not in text and "keep me" not in text  # never values
    assert "action: skip  # skip | copy-to-right | copy-to-left" in text





def test_compare_in_sync_exits_zero(env, capsys):
    rc = main(["compare", *env.args, "--prefix", f"{env.prefix}/eq"])
    assert rc == 0
    assert "1 secrets: 1 equal." in capsys.readouterr().out


def test_compare_needs_a_token(env, monkeypatch, capsys):
    monkeypatch.delenv("LOCKSTEP_RIGHT_TOKEN")
    monkeypatch.setenv("HOME", str(env.dir))  # no ~/.vault-token
    assert main(["compare", *env.args]) == 2
    assert "No token for the right side" in capsys.readouterr().err


def test_apply_yes_writes_and_keeps_target_only_keys(env, capsys):
    _, rep, _ = _compare(env, capsys)
    _set(rep, "db", password="copy-to-right")
    _set(rep, "new", secret="copy-to-right")
    (env.dir / "report.yaml").write_text(yaml.safe_dump(rep))

    assert main(["apply", "report.yaml", "--yes"]) == 0
    out = capsys.readouterr().out
    assert "Wrote 2 keys to 2 secrets." in out
    assert env.b.get(f"{env.prefix}/db")[0] == {"host": "h", "password": "A", "port": "5432", "extra": "keep me"}
    assert env.b.get(f"{env.prefix}/new")[0] == {"k": "v"}


def test_apply_dry_run_writes_nothing(env, capsys):
    _, rep, _ = _compare(env, capsys)
    _set(rep, "db", password="copy-to-right", extra="copy-to-left")
    (env.dir / "report.yaml").write_text(yaml.safe_dump(rep))
    before_a, before_b = env.a.get(f"{env.prefix}/db"), env.b.get(f"{env.prefix}/db")
    assert main(["apply", "report.yaml", "--dry-run"]) == 0
    assert "Dry run: 2 secrets would be written." in capsys.readouterr().out
    assert (env.a.get(f"{env.prefix}/db"), env.b.get(f"{env.prefix}/db")) == (before_a, before_b)


def test_apply_skips_secrets_changed_since_the_report(env, capsys):
    _, rep, _ = _compare(env, capsys)
    _set(rep, "db", password="copy-to-right")
    _set(rep, "new", secret="copy-to-right")
    (env.dir / "report.yaml").write_text(yaml.safe_dump(rep))
    env.b.put(f"{env.prefix}/db", {"password": "changed meanwhile"})  # target moved on

    assert main(["apply", "report.yaml", "--yes"]) == 1
    out = capsys.readouterr().out
    assert "the target changed since the report was made (v1 → v2)" in out
    assert "1 skipped because they changed since the report" in out
    assert env.b.get(f"{env.prefix}/db")[0] == {"password": "changed meanwhile"}
    assert env.b.get(f"{env.prefix}/new")[0] == {"k": "v"}  # the rest still applied


def test_apply_skips_when_the_source_changed(env, capsys):
    _, rep, _ = _compare(env, capsys)
    _set(rep, "db", password="copy-to-right")
    (env.dir / "report.yaml").write_text(yaml.safe_dump(rep))
    env.a.put(f"{env.prefix}/db", {"host": "h", "password": "A2", "port": 5432})
    assert main(["apply", "report.yaml", "--yes"]) == 1
    assert "the source changed since the report was made" in capsys.readouterr().out
    assert env.b.get(f"{env.prefix}/db")[0]["password"] == "B"


async def test_apply_asks_per_key(env, capsys):
    from lockstep.cli import apply as ap
    from lockstep.cli.connect import cli_settings, connect_both, resolve_targets

    await asyncio.to_thread(main, ["compare", *env.args, "-o", "report.yaml"])
    raw = yaml.safe_load((env.dir / "report.yaml").read_text())
    _set(raw, "db", password="copy-to-right", port="copy-to-right")
    _set(raw, "new", secret="copy-to-right")
    rep = rpt.load(yaml.safe_dump(raw), "r")
    changes = rpt.plan(rep)

    class A:
        ca_cert = None
        tls_skip_verify = False

    for which, addr in (("left", env.args[1]), ("right", env.args[3])):
        for n in ("addr", "namespace", "auth", "user", "auth_mount", "token_file"):
            setattr(A, f"{which}_{n}", addr if n == "addr" else None)
    settings = cli_settings(A)
    lconn, rconn = await connect_both(resolve_targets(A), settings, {"left": "A", "right": "B"})
    answers = iter(["maybe", "n", "y", "q"])  # bad answer, then: password no, port yes, quit at `new`
    prompts: list[str] = []

    def read(p: str) -> str:
        prompts.append(p)
        return next(answers)

    out = io.StringIO()
    o = await ap.run(rep, changes, lconn, rconn, settings, yes=False, dry_run=False, show_values=True,
                     out=out, read=read)
    text = out.getvalue()
    assert [p.split("?")[0].strip() for p in prompts] == ["Write password", "Write password", "Write port", "Write k"]
    assert "Please answer y, n, a or q." in text
    assert "now: B" in text and "new: A" in text  # --show-values
    assert o.quit and o.declined == 1 and o.keys_written == 1
    assert env.b.get(f"{env.prefix}/db")[0] == {"host": "h", "password": "B", "port": 5432, "extra": "keep me"}
    assert env.b.get(f"{env.prefix}/new") == (None, None)


def test_apply_refuses_without_a_terminal(env, capsys, monkeypatch):
    _, rep, _ = _compare(env, capsys)
    _set(rep, "db", password="copy-to-right")
    (env.dir / "report.yaml").write_text(yaml.safe_dump(rep))
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    assert main(["apply", "report.yaml"]) == 2
    assert "add --yes or --dry-run" in capsys.readouterr().err


def test_same_vault_two_mounts_reuses_the_connection(env, capsys, monkeypatch):
    monkeypatch.delenv("LOCKSTEP_RIGHT_TOKEN")
    rc = main(["compare", "--left-addr", env.args[1], "--left-mount", MOUNT, "--right-mount", MOUNT,
               "--left-prefix", f"{env.prefix}/eq", "--right-prefix", f"{env.prefix}/eq", "-q"])
    assert rc == 0
