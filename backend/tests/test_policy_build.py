"""Building policies from plain rules, suggesting them from a layout, and the admin bundle."""

import io
import zipfile

import httpx
import pytest

from lockstep.policy.acl import ACL
from lockstep.policy.build import Rule, build_hcl
from lockstep.policy.explain import explain
from lockstep.policy.hcl import parse_policy
from lockstep.policy.suggest import SuggestPattern, apply_pattern, compare_profile, detect

SECRETS = ["payments/dev/db", "payments/test/db", "payments/prod/db", "orders/dev/q", "orders/prod/q", "shared/ca"]


def cells(hcl, secrets):
    out = explain([parse_policy(hcl, "p")], "kv", secrets)
    return {r["path"]: {c: v["ok"] for c, v in r["cells"].items()} for r in out["rows"]}


def test_plain_rules_map_to_the_right_kv2_paths():
    hcl = build_hcl("kv", [Rule(where="payments/dev/", can=["names", "read", "write", "delete", "history"]),
                           Rule(where="payments/test/**", can=["names", "read"]),
                           Rule(where="payments/prod/db", can=["destroy"])], name="t")
    got = cells(hcl, ["payments/dev/db", "payments/test/db", "payments/prod/db", "orders/dev/q"])
    assert got["payments/dev/db"] == {"names": True, "read": True, "write": True, "delete": True, "destroy": False, "history": True}
    assert got["payments/test/db"] == {"names": True, "read": True, "write": False, "delete": False, "destroy": False, "history": False}
    assert got["payments/prod/db"] == {"names": False, "read": False, "write": False, "delete": False, "destroy": True, "history": False}
    assert not any(got["orders/dev/q"].values())
    acl = ACL([parse_policy(hcl)])
    assert acl.decide("kv/metadata/payments/dev/").allows("list")  # the folder itself can be listed
    assert acl.decide("kv/delete/payments/dev/db").allows("update") and acl.decide("kv/undelete/payments/dev/db").allows("update")
    assert "# payments/dev/**: names, read, write, delete, history" in hcl


def test_wildcards_and_whole_mount():
    hcl = build_hcl("kv", [Rule(where="*/dev/**", can=["read"]), Rule(where="**", can=["names"])])
    assert 'path "kv/data/+/dev/*"' in hcl and 'path "kv/metadata/*"' in hcl and 'path "kv/metadata"' in hcl
    got = cells(hcl, ["a/dev/x", "a/prod/x"])
    assert got["a/dev/x"]["read"] and not got["a/prod/x"]["read"] and got["a/prod/x"]["names"]


@pytest.mark.parametrize("bad", ["a/**/b", "a//b", "ab*/c", "a/+/b"])
def test_bad_where(bad):
    with pytest.raises(ValueError):
        Rule(where=bad, can=["read"])


def test_detect_app_env_layout_and_suggest():
    pattern, why = detect(SECRETS)
    assert pattern.layout == "{app}/{env}/**" and pattern.values["env"] == ["dev", "test", "prod"]
    assert any("environment names" in w for w in why)
    out, notes = apply_pattern(pattern, SECRETS, "app-config")
    names = [s.name for s in out]
    assert {"payments-developer", "orders-developer", "payments-dev-app", "payments-prod-app", "orders-dev-app",
            "app-config-read", "app-config-admin"} <= set(names)
    assert "orders-test-app" not in names  # orders has no test folder
    dev = next(s for s in out if s.name == "payments-developer")
    got = cells(dev.hcl.replace("app-config/", "kv/"), SECRETS)
    assert got["payments/dev/db"]["write"] and got["payments/test/db"]["read"] and not got["payments/test/db"]["write"]
    assert got["payments/prod/db"]["names"] and not got["payments/prod/db"]["read"]
    assert not any(got["orders/dev/q"].values())
    prof = compare_profile(pattern)
    assert prof.name == "dev vs prod"
    assert {(m.left, m.right) for m in prof.mappings} == {("*-dev-app", "*-prod-app")}
    assert prof.rewrites[0].find == "/dev/"


def test_detect_with_a_fixed_top_folder_and_one_env_per_app():
    pattern, _ = detect(["services/billing/prod/db", "services/billing/staging/db", "services/search/prod/c"])
    assert pattern.layout == "services/{app}/{env}/**"
    pattern, why = detect(["a/x", "b/y"])
    assert pattern.layout == "{app}/**" and "top-level folders" in why[0]
    assert detect(["x", "y"])[0].layout == "**"


def test_a_users_pattern_with_values_and_a_prefix():
    pattern = SuggestPattern.model_validate({
        "name": "teams", "layout": "{team}/{env}/**", "values": {"env": ["prod", "dev"]},
        "policies": [{"name": "{team}-{env}", "rules": [{"where": "{team}/{env}/**", "can": ["read"]}]},
                     {"name": "{team}-all", "rules": [{"where": "{team}/{env}/**", "can": ["names"]}]},
                     {"name": "{nope}-x", "rules": [{"where": "**", "can": ["read"]}]}],
        "compare": {"pair": {"env": ["dev", "prod"]}}})
    out, notes = apply_pattern(pattern, SECRETS, "kv", prefix="base")
    names = [s.name for s in out]
    assert "payments-test" not in names  # values limited to prod and dev
    assert "payments-prod" in names and "payments-dev" in names
    allrule = next(s for s in out if s.name == "payments-all")
    assert {r.where for r in allrule.rules} == {"base/payments/prod/**", "base/payments/dev/**"}
    assert any("{nope}" in n for n in notes)
    assert compare_profile(pattern).mappings[0].left == "*-dev"


# --------------------------------------------------------------------------- API


@pytest.fixture
def root(client, vaults):
    r = client.post("/api/connections", json={"preset_id": 0, "auth": {"method": "token", "token": "root-a"}})
    return r.json()["id"]


def test_build_and_suggest_api(client, root):
    r = client.post("/api/policies/build", json={"mount": "app-config", "name": "x",
                                                 "rules": [{"where": "payments/**", "can": ["read"]}]})
    assert r.status_code == 200, r.text
    assert 'path "app-config/data/payments/*"' in r.json()["hcl"]
    assert client.post("/api/policies/build", json={"mount": "m", "rules": [{"where": "a/**/b", "can": ["read"]}]}).status_code == 422

    r = client.post("/api/policies/suggest", json={"conn_id": root, "mount": "app-config", "prefix": "services"})
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["layout"] == "{app}/{env}/**"
    assert any(s["name"] == "billing-prod-app" for s in out["suggestions"])
    assert any(s["name"] == "app-config-services-read" for s in out["suggestions"])
    dev = next(s for s in out["suggestions"] if s["name"] == "billing-developer")
    assert dev["description"] == "Developers of an app: see names in prod"
    assert all(r2["where"].startswith("services/") or r2["where"] == "**" or r2["where"].startswith("services")
               for s in out["suggestions"] for r2 in s["rules"])
    assert "name: detected" in out["pattern_yaml"]

    r = client.post("/api/policies/suggest", json={"conn_id": root, "mount": "app-config", "prefix": "services",
                                                   "pattern": "layout: '{app}/**'\npolicies:\n  - name: '{app}-ro'\n    rules: [{where: '{app}/**', can: [read]}]\n"})
    assert r.status_code == 200, r.text
    assert {s["name"] for s in r.json()["suggestions"]} == {"billing-ro", "search-ro"}
    bad = client.post("/api/policies/suggest", json={"conn_id": root, "mount": "app-config", "pattern": "layout: [1"})
    assert bad.status_code == 400


def test_bundle_with_script_and_terraform(client, root, vaults):
    pol = [{"name": "lockstep-limited", "text": 'path "app-config/data/*" { capabilities = ["read"] }'},
           {"name": "brand-new", "text": 'path "x/${y}" { capabilities = ["read"] }'}]
    r = client.post("/api/policies/bundle", json={"policies": pol, "conn_id": root,
                                                  "terraform": {"tool": "opentofu", "provider": "~> 5.0", "layout": "single", "imports": True}})
    assert r.status_code == 200, r.text
    assert r.headers["content-type"] == "application/zip"
    z = zipfile.ZipFile(io.BytesIO(r.content))
    names = set(z.namelist())
    assert {"README.md", "apply.sh", "policies/lockstep-limited.hcl", "policies/brand-new.hcl",
            "opentofu/versions.tf", "opentofu/policies.tf", "opentofu/imports.tf"} <= names
    assert z.getinfo("apply.sh").external_attr >> 16 & 0o111
    script = z.read("apply.sh").decode()
    assert "--dry-run" in script and "vault policy write" in script
    tf = z.read("opentofu/policies.tf").decode()
    assert 'resource "vault_policy" "brand_new"' in tf and "$${y}" in tf  # ${ escaped in the heredoc
    assert 'version = "~> 5.0"' in z.read("opentofu/versions.tf").decode()
    imports = z.read("opentofu/imports.tf").decode()
    assert 'id = "lockstep-limited"' in imports and "brand-new" not in imports  # only what exists already

    bad = client.post("/api/policies/bundle", json={"policies": [{"name": "../evil", "text": 'path "x" { capabilities = ["read"] }'}]})
    assert bad.status_code == 422
    broken = client.post("/api/policies/bundle", json={"policies": [{"name": "ok", "text": 'path "x" {'}]})
    assert broken.status_code == 400 and "can't be parsed" in broken.text


VAULT_SHIM = """#!{python}
# A stand-in for the vault CLI: just `vault policy read|write`, over the HTTP API
import json, os, sys, urllib.request, urllib.error
hdr = {{"X-Vault-Token": os.environ["VAULT_TOKEN"]}}
base = os.environ["VAULT_ADDR"] + "/v1/"
if sys.argv[1] in ("read", "write"):  # vault read PATH / vault write PATH @file.json
    url = base + sys.argv[2]
    try:
        if sys.argv[1] == "read":
            urllib.request.urlopen(urllib.request.Request(url, headers=hdr))
        else:
            body = open(sys.argv[3][1:]).read().encode()
            urllib.request.urlopen(urllib.request.Request(url, data=body, headers=hdr, method="POST"))
    except urllib.error.HTTPError:
        sys.exit(2)
    sys.exit(0)
_, group, cmd, name, *rest = sys.argv
assert group == "policy"
url = base + "sys/policies/acl/" + name
if cmd == "read":
    try:
        print(json.load(urllib.request.urlopen(urllib.request.Request(url, headers=hdr)))["data"]["policy"])
    except urllib.error.HTTPError:
        sys.exit(2)
else:
    body = json.dumps({{"policy": open(rest[0]).read()}}).encode()
    urllib.request.urlopen(urllib.request.Request(url, data=body, headers=hdr, method="PUT"))
"""


DIFF_SHIM = """#!{python}
# A stand-in for diff(1), for images without diffutils: -q, -u and --label
import difflib, sys
args, labels, files, quiet = sys.argv[1:], [], [], False
while args:
    a = args.pop(0)
    if a == "--label":
        labels.append(args.pop(0))
    elif a == "-q":
        quiet = True
    elif not a.startswith("-"):
        files.append(a)
x, y = (open(f).read().splitlines(True) for f in files)
if x == y:
    sys.exit(0)
if not quiet:
    sys.stdout.writelines(difflib.unified_diff(x, y, *(labels or files)))
sys.exit(1)
"""


def test_apply_script_runs_against_vault(client, vaults, tmp_path):
    """The generated apply.sh against a real Vault (through a minimal vault CLI stand-in)."""
    import os
    import shutil
    import subprocess
    import sys
    if not shutil.which("bash"):
        pytest.skip("needs bash")
    shim = tmp_path / "bin" / "vault"
    shim.parent.mkdir()
    shim.write_text(VAULT_SHIM.format(python=sys.executable))
    shim.chmod(0o755)
    if not shutil.which("diff"):
        (shim.parent / "diff").write_text(DIFF_SHIM.format(python=sys.executable))
        (shim.parent / "diff").chmod(0o755)
    v = httpx.Client(base_url=f"{vaults[0]}/v1/", headers={"X-Vault-Token": "root-a"})
    v.put("sys/policies/acl/lockstep-bundle-same", json={"policy": 'path "same" { capabilities = ["read"] }\n'})
    try:
        r = client.post("/api/policies/bundle", json={"policies": [
            {"name": "lockstep-bundle-new", "text": 'path "x" { capabilities = ["read"] }'},
            {"name": "lockstep-bundle-same", "text": 'path "same" { capabilities = ["read"] }'}]})
        zipfile.ZipFile(io.BytesIO(r.content)).extractall(tmp_path / "b")
        env = {**os.environ, "VAULT_ADDR": vaults[0], "VAULT_TOKEN": "root-a", "PATH": f"{shim.parent}:{os.environ['PATH']}"}
        dry = subprocess.run(["bash", str(tmp_path / "b" / "apply.sh"), "--dry-run"], env=env, capture_output=True, text=True)
        assert dry.returncode == 0, dry.stderr
        assert "new      lockstep-bundle-new" in dry.stdout and "same     lockstep-bundle-same" in dry.stdout
        assert "Dry run: 1 policy would be written" in dry.stdout
        assert v.get("sys/policies/acl/lockstep-bundle-new").status_code == 404
        subprocess.run(["bash", str(tmp_path / "b" / "apply.sh")], env=env, check=True, capture_output=True)
        assert 'path "x"' in v.get("sys/policies/acl/lockstep-bundle-new").json()["data"]["policy"]
    finally:
        for n in ("lockstep-bundle-new", "lockstep-bundle-same"):
            v.delete(f"sys/policies/acl/{n}")


def test_cli_suggest_and_export(vaults, monkeypatch, tmp_path, capsys):
    import json as _json
    for var in ("VAULT_ADDR", "VAULT_TOKEN", "VAULT_NAMESPACE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("VAULT_TOKEN", "root-a")
    monkeypatch.chdir(tmp_path)
    from lockstep.cli import main
    rc = main(["policy", "suggest", "--vault-addr", vaults[0], "--mount", "app-config", "--prefix", "services",
               "--only", "billing-prod-app", "--bundle", "s.zip", "--terraform"])
    out = capsys.readouterr().out
    assert rc == 0 and "Layout: {app}/{env}/**" in out and "--- billing-prod-app" in out
    assert 'path "app-config/data/services/billing/prod/*"' in out
    z = zipfile.ZipFile(tmp_path / "s.zip")
    assert {"policies/billing-prod-app.hcl", "terraform/versions.tf", "apply.sh"} <= set(z.namelist())

    (tmp_path / "team-a.hcl").write_text('path "kv/data/a/*" { capabilities = ["read"] }\n')
    assert main(["policy", "export", "team-a.hcl", "--bundle", "e.zip", "--opentofu", "--tf-files"]) == 0
    assert "opentofu/policy_team_a.tf" in zipfile.ZipFile(tmp_path / "e.zip").namelist()
    (tmp_path / "bad.hcl").write_text('path "x" {')
    assert main(["policy", "export", "bad.hcl", "--bundle", "x.zip"]) == 2
    capsys.readouterr()
    assert main(["schema", "suggest-pattern"]) == 0
    assert "layout" in _json.loads(capsys.readouterr().out)["properties"]


def test_shared_patterns(client, monkeypatch):
    from lockstep.config import get_settings
    from lockstep.policy.suggest import SuggestPattern
    p = SuggestPattern.model_validate({"name": "teams", "layout": "{team}/**",
                                       "policies": [{"name": "{team}-ro", "rules": [{"where": "{team}/**", "can": ["read"]}]}]})
    monkeypatch.setattr(get_settings(), "policy_patterns", [p])
    out = client.get("/api/policies/patterns").json()
    assert out[0]["name"] == "teams" and "layout: '{team}/**'" in out[0]["yaml"]
