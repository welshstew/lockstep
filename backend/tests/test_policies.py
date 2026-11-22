"""Explaining policies on a mount, through the API, against the seeded dev Vault."""

import json
import uuid

import httpx
import pytest

pytestmark = pytest.mark.usefixtures("vaults")
MOUNT = "app-config"


@pytest.fixture
def connect(client):
    def go(**auth):
        auth.setdefault("method", "token")
        r = client.post("/api/connections", json={"preset_id": 0, "auth": auth})
        assert r.status_code == 201, r.text
        return r.json()["id"]
    return go


def explain(client, conn, **body):
    r = client.post("/api/policies/explain", json={"conn_id": conn, "mount": MOUNT} | body)
    assert r.status_code == 200, r.text
    out = r.json()
    out["by_path"] = {row["path"]: row["cells"] for row in out["rows"]}
    return out


def test_explain_a_policy_by_name(client, connect, vaults):
    root = connect(token="root-a")
    out = explain(client, root, names=["lockstep-limited"])
    assert out["mode"] == "policies" and out["complete"]
    assert out["policies"] == [{"name": "lockstep-limited", "origin": "vault", "rules": 7, "error": None}]
    db, api = out["by_path"]["payments/db"], out["by_path"]["payments/api"]
    assert [db[c]["ok"] for c in ("names", "read", "write", "delete", "destroy", "history")] == [
        True, True, True, False, False, True]
    assert not api["read"]["ok"] and api["read"]["deny"]
    rule = out["rules"][api["read"]["rule"]]
    assert rule["sources"][0]["path"] == "app-config/data/payments/api" and rule["sources"][0]["line"]
    restricted = out["by_path"]["restricted/root-creds"]  # root can list it; the policy can't
    assert not restricted["names"]["ok"] and not restricted["read"]["ok"]


def test_the_matrix_agrees_with_vault_for_a_real_token(client, connect, vaults):
    """Every cell for lockstep-limited equals what Vault says for a token holding it."""
    root = connect(token="root-a")
    out = explain(client, root, names=["lockstep-limited"])
    v = httpx.Client(base_url=f"{vaults[0]}/v1/", headers={"X-Vault-Token": "root-a"}, timeout=10)
    token = v.post("auth/token/create", json={"policies": ["lockstep-limited"], "no_default_policy": True,
                                              "ttl": "5m"}).json()["auth"]["client_token"]
    from lockstep.policy.explain import COLUMNS, request_path
    paths = sorted({request_path(MOUNT, p, w) for p in out["by_path"] for _, _, w, _ in COLUMNS})
    caps = v.post("sys/capabilities", json={"token": token, "paths": paths}).json()
    for p, cells in out["by_path"].items():
        for col, _, where, need in COLUMNS:
            got = caps[request_path(MOUNT, p, where)]
            assert cells[col]["ok"] == any(c in got for c in need), (p, col, got)


def test_own_token_without_rights_to_read_policies_asks_vault(client, connect):
    carol = connect(method="userpass", username="carol", password="password")
    out = explain(client, carol, token="self")
    assert out["mode"] == "vault" and out["complete"]
    assert {p["name"] for p in out["policies"]} == {"default", "lockstep-limited"}
    assert all(p["error"] and "needs read" in p["error"] for p in out["policies"])
    assert "read on sys/policies/acl/lockstep-limited" in out["missing"]
    assert "restricted/" in out["denied"]  # carol can't even list it
    assert not out["by_path"]["payments/api"]["read"]["ok"]
    db = out["by_path"]["payments/db"]
    assert db["write"]["ok"] and db["write"]["rule"] is None  # from Vault: no deciding rule to show
    assert out["rules"] == []


def test_root_token_and_pasted_policies(client, connect):
    root = connect(token="root-a")
    out = explain(client, root, token="self")
    assert out["root"] and all(c["ok"] for c in out["by_path"]["payments/db"].values())

    out = explain(client, root, pasted=[
        {"name": "mine", "text": 'path "app-config/payments/*" { capabilities = ["read"] }\n'
                                 'path "app-config/data/*" { capabilities = ["read", "list"] }'},
        {"name": "broken", "text": 'path "x" {'},
    ])
    srcs = {p["name"]: p for p in out["policies"]}
    assert srcs["mine"]["rules"] == 2 and "can't be parsed" in srcs["broken"]["error"]
    msgs = [f["message"] for f in out["findings"]]
    assert any("Did you mean app-config/data/payments/*" in m for m in msgs)
    assert any("list does nothing on data/" in m for m in msgs)
    assert out["by_path"]["payments/db"]["read"]["ok"] and not out["by_path"]["payments/db"]["names"]["ok"]


def test_list_and_read_policies(client, connect):
    root = connect(token="root-a")
    names = client.get("/api/policies", params={"conn_id": root}).json()["names"]
    assert {"lockstep-admin", "lockstep-limited", "lockstep-readonly"} <= set(names)
    text = client.get("/api/policies/lockstep-readonly", params={"conn_id": root}).json()["text"]
    assert '"+/data/*"' in text
    bob = connect(method="userpass", username="bob", password="password")
    r = client.get("/api/policies", params={"conn_id": bob})
    assert r.status_code == 403 and "Type policy names instead" in r.text


def test_explain_needs_something_and_a_kv2_mount(client, connect):
    root = connect(token="root-a")
    assert client.post("/api/policies/explain", json={"conn_id": root, "mount": MOUNT}).status_code == 400
    r = client.post("/api/policies/explain", json={"conn_id": root, "mount": "sys", "token": "self"})
    assert r.status_code in (400, 404)


# --------------------------------------------------------------------------- CLI


@pytest.fixture
def cli(vaults, monkeypatch, tmp_path):
    for var in ("VAULT_ADDR", "VAULT_TOKEN", "VAULT_NAMESPACE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("VAULT_TOKEN", "root-a")
    monkeypatch.chdir(tmp_path)
    from lockstep.cli import main
    return lambda *a: main(["policy", "explain", "--vault-addr", vaults[0], "--mount", MOUNT, *a])


def test_cli_explain_table_why_and_json(cli, capsys, tmp_path):
    assert cli("lockstep-limited", "--prefix", "payments") == 0
    out = capsys.readouterr().out
    assert "lockstep-limited (vault): 7 rules" in out
    assert "secret" in out and "See names" in out and "payments/api" in out

    assert cli("lockstep-limited", "--why", "payments/api") == 0
    out = capsys.readouterr().out
    assert 'path "app-config/data/payments/api"' in out and "Read" in out

    assert cli("lockstep-limited", "--json", "--prefix", "payments") == 0
    data = json.loads(capsys.readouterr().out)
    assert {r["path"] for r in data["rows"]} == {"payments/api", "payments/db"}


def test_cli_file_with_an_error_exits_one(cli, capsys, tmp_path):
    (tmp_path / "bad.hcl").write_text('path "app-config/data/+*" { capabilities = ["read"] }\n')
    assert cli("--file", "bad.hcl", "--prefix", "payments") == 1
    assert "Vault refuses '+*'" in capsys.readouterr().out


# --------------------------------------------------------------------------- compare


def test_pair_names_with_mappings_and_ignore():
    from lockstep.policy.compare import PolicyProfile, pair_names
    prof = PolicyProfile(name="p", mappings=[{"left": "*-dev", "right": "*-prod"}, {"left": "ci-*-x", "right": "ci-*-y"}],
                         ignore=["root", "tmp-*"])
    pairs = pair_names(["a-dev", "b-dev", "same", "ci-q-x", "only-left", "tmp-1", "root"],
                       ["a-prod", "same", "ci-q-y", "only-right", "b-dev"], prof)
    got = {(l, r): (m, n) for l, r, m, n in pairs}
    assert got[("a-dev", "a-prod")] == (True, "")
    assert got[("ci-q-x", "ci-q-y")] == (True, "")
    assert got[("b-dev", None)] == (True, "expected b-prod on the right")  # mapped, but the target is missing
    assert got[("same", "same")] == (False, "")
    assert ("only-left", None) in got and (None, "only-right") in got and (None, "b-dev") in got
    assert not any("tmp-1" in (l, r) or "root" in (l, r) for l, r, _, _ in pairs)
    with pytest.raises(ValueError):
        PolicyProfile(name="bad", mappings=[{"left": "*-dev", "right": "prod"}])


def test_compare_texts_by_meaning():
    from lockstep.policy.compare import Rewrite, compare_texts
    a = '# dev\npath "kv/data/dev/*" { capabilities = ["read", "list"] }\npath "kv/data/dev/*" { capabilities = ["update"] }'
    b = 'path "kv/data/prod/*" {\n  capabilities = ["update", "list", "read"]\n}'
    res = compare_texts(a, b, [Rewrite(find="/dev/", replace="/prod/")])
    assert res["status"] == "equal" and res["formatting"]
    res = compare_texts(a, b)
    assert res["status"] == "different"
    assert {r["path"]: r["change"] for r in res["rules"]} == {"kv/data/dev/*": "left_only", "kv/data/prod/*": "right_only"}
    res = compare_texts('path "x" { capabilities = ["read"] }', 'path "x" { capabilities = ["read", "deny"] }')
    assert res["rules"][0] == {"path": "x", "left": ["read"], "right": ["deny"], "left_extra": None,
                               "right_extra": None, "change": "changed"}
    assert compare_texts("broken {", "broken {")["status"] == "equal"
    assert compare_texts("broken {", "other {")["status"] == "error"


@pytest.fixture
def two_vaults(vaults):
    tag = uuid.uuid4().hex[:6]
    a = httpx.Client(base_url=f"{vaults[0]}/v1/", headers={"X-Vault-Token": "root-a"}, timeout=10)
    b = httpx.Client(base_url=f"{vaults[1]}/v1/", headers={"X-Vault-Token": "root-b"}, timeout=10)
    made = []

    def put(v, name, text):
        v.put(f"sys/policies/acl/{name}", json={"policy": text}).raise_for_status()
        made.append((v, name))

    yield tag, a, b, put
    for v, n in made:
        v.delete(f"sys/policies/acl/{n}")


def test_compare_policies_across_vaults(client, two_vaults):
    tag, a, b, put = two_vaults
    put(a, f"t{tag}-app-dev", 'path "app-config/data/dev/*" { capabilities = ["read"] }')
    put(b, f"t{tag}-app-prod", '# formatted differently\npath "app-config/data/prod/*" {\n  capabilities = ["read"]\n}')
    put(a, f"t{tag}-same", 'path "x/*" { capabilities = ["read", "list"] }')
    put(b, f"t{tag}-same", 'path "x/*" { capabilities = ["read"] }')
    put(a, f"t{tag}-left", 'path "y" { capabilities = ["read"] }')
    ca = client.post("/api/connections", json={"preset_id": 0, "auth": {"method": "token", "token": "root-a"}}).json()["id"]
    cb = client.post("/api/connections", json={"preset_id": 1, "auth": {"method": "token", "token": "root-b"}}).json()["id"]
    profile = {"name": "dev-prod", "mappings": [{"left": f"t{tag}-*-dev", "right": f"t{tag}-*-prod"}],
               "rewrites": [{"find": "/dev/", "replace": "/prod/"}]}
    r = client.post("/api/policies/compare", json={"left": ca, "right": cb, "profile": profile})
    assert r.status_code == 200, r.text
    pairs = {(p["left"], p["right"]): p for p in r.json()["pairs"] if (p["left"] or p["right"]).startswith(f"t{tag}")}
    mapped = pairs[(f"t{tag}-app-dev", f"t{tag}-app-prod")]
    assert mapped["status"] == "equal" and mapped["mapped"] and mapped["formatting"]
    same = pairs[(f"t{tag}-same", f"t{tag}-same")]
    assert same["status"] == "different" and same["rules"][0]["left"] == ["list", "read"]
    assert pairs[(f"t{tag}-left", None)]["status"] == "left_only"
    seeded = {(p["left"], p["right"]): p["status"] for p in r.json()["pairs"]}
    assert seeded[("lockstep-limited", "lockstep-limited")] == "equal"  # seeded the same on both
    assert ("root", "root") not in seeded  # ignored by default

    # Effective access: the same two policies on each Vault's app-config
    r = client.post("/api/policies/compare-access", json={
        "left": {"conn_id": ca, "mount": "app-config", "name": "lockstep-limited"},
        "right": {"conn_id": cb, "mount": "app-config", "name": "lockstep-readonly"}})
    assert r.status_code == 200, r.text
    rows = {x["path"]: x for x in r.json()["rows"]}
    db = rows["payments/db"]
    assert db["left"]["write"]["ok"] and not db["right"]["write"]["ok"] and db["differs"]


def test_compare_needs_rights_to_list(client):
    bob = client.post("/api/connections", json={"preset_id": 0, "auth": {"method": "userpass", "username": "bob",
                                                                          "password": "password"}}).json()["id"]
    root = client.post("/api/connections", json={"preset_id": 1, "auth": {"method": "token", "token": "root-b"}}).json()["id"]
    out = client.post("/api/policies/compare", json={"left": bob, "right": root}).json()
    assert "needs list" in out["left"]["error"] and "left: list on sys/policies/acl" in out["missing"]
    assert all(p["status"] == "right_only" for p in out["pairs"])


def test_cli_policy_compare(two_vaults, vaults, monkeypatch, tmp_path, capsys):
    tag, a, b, put = two_vaults
    put(a, f"t{tag}-app-dev", 'path "app-config/data/dev/*" { capabilities = ["read"] }')
    put(b, f"t{tag}-app-prod", 'path "app-config/data/prod/*" { capabilities = ["read", "update"] }')
    for var in ("VAULT_ADDR", "VAULT_TOKEN", "VAULT_NAMESPACE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("LOCKSTEP_LEFT_TOKEN", "root-a")
    monkeypatch.setenv("LOCKSTEP_RIGHT_TOKEN", "root-b")
    monkeypatch.chdir(tmp_path)
    (tmp_path / "prof.yaml").write_text(f"mappings: [{{left: 't{tag}-*-dev', right: 't{tag}-*-prod'}}]\n"
                                        "rewrites: [{find: /dev/, replace: /prod/}]\nignore: [root, 'lockstep-*', default]\n")
    from lockstep.cli import main
    base = ["policy", "compare", "--left-addr", vaults[0], "--right-addr", vaults[1], "--profile", "prof.yaml"]
    assert main(base) == 1
    out = capsys.readouterr().out
    assert f"different   t{tag}-app-dev ⇄ t{tag}-app-prod" in out
    assert 'path "app-config/data/prod/*"  [read] → [read, update]' in out
    assert main([*base, "--json"]) == 1
    data = json.loads(capsys.readouterr().out)
    assert any(p["left"] == f"t{tag}-app-dev" and p["mapped"] for p in data["pairs"])
    assert main(["schema", "policy-profile"]) == 0
    assert '"mappings"' in capsys.readouterr().out


def test_the_builtin_default_policy_raises_no_admin_warnings(client, connect):
    root = connect(token="root-a")
    out = explain(client, root, names=["default"])
    assert not [f for f in out["findings"] if f["policy"] == "default" and f["level"] != "error"]


def test_explain_reports_the_vault_version(client, connect):
    root = connect(token="root-a")
    out = explain(client, root, names=["lockstep-limited"])
    assert out["vault_version"].startswith("1.21") and out["evaluation"] == "Vault 2.2.1 or earlier"
