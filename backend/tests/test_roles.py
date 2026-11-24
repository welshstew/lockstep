"""Kubernetes and JWT/OIDC auth roles: reading, checking, explaining, comparing, bundling."""

import io
import json
import uuid
import zipfile

import httpx
import pytest

from conftest import ca_pem
from lockstep.policy.roles import compare_roles, lint, normalise, policies_of, seconds

pytestmark = pytest.mark.usefixtures("vaults")

CA = ca_pem()


def test_normalise_defaults_durations_and_lists():
    raw = {"bound_service_account_names": ["b", "a"], "bound_service_account_namespaces": ["ns"],
           "token_ttl": "1h", "token_max_ttl": 0, "token_type": "default", "alias_name_source": "serviceaccount_uid",
           "token_policies": ["p2", "p1"], "audience": ""}
    assert normalise("kubernetes", raw) == {"bound_service_account_names": ["a", "b"],
                                            "bound_service_account_namespaces": ["ns"], "token_ttl": 3600,
                                            "token_policies": ["p1", "p2"]}
    assert seconds("1h30m") == 5400 and seconds("90") == 90 and seconds(15) == 15
    assert normalise("jwt", {"policies": ["legacy"], "role_type": "oidc"}) == {"token_policies": ["legacy"]}
    assert policies_of({"token_policies": ["a"]}) == ["a", "default"]
    assert policies_of({"token_policies": ["a"], "token_no_default_policy": True}) == ["a"]


@pytest.mark.parametrize("kind,role,expect", [
    ("kubernetes", {"bound_service_account_names": ["*"], "bound_service_account_namespaces": ["*"], "token_policies": ["p"]},
     "Any service account in any namespace"),
    ("kubernetes", {"bound_service_account_names": ["a"], "token_policies": ["p"]}, "No namespaces"),
    ("jwt", {"role_type": "jwt", "user_claim": "sub", "token_policies": ["p"]}, "anyone with any token from this issuer"),
    ("jwt", {"role_type": "jwt", "user_claim": "sub", "bound_audiences": ["x"], "token_policies": ["p"]}, "Only the audience"),
    ("jwt", {"role_type": "oidc", "user_claim": "email", "allowed_redirect_uris": ["http://vault.example.com/cb"], "token_policies": ["p"]}, "plain HTTP"),
    ("jwt", {"role_type": "jwt", "user_claim": "sub", "bound_claims_type": "glob", "bound_claims": {"ref": "*"}, "token_policies": ["p"]}, "matches anything"),
    ("kubernetes", {"bound_service_account_names": ["a"], "bound_service_account_namespaces": ["n"], "token_policies": ["nope"]}, "No such policy"),
    ("kubernetes", {"bound_service_account_names": ["a"], "bound_service_account_namespaces": ["n"], "token_ttl": 172800, "token_policies": ["p"]}, "48 hours"),
])
def test_lint(kind, role, expect):
    msgs = [f.message for f in lint(kind, normalise(kind, role), existing={"p"})]
    assert any(expect in m for m in msgs), msgs


def test_compare_with_mappings_and_rewrites():
    from lockstep.policy.compare import PolicyProfile
    left = {"app-dev": {"bound_service_account_namespaces": ["app-dev"], "token_policies": ["app-dev-app"]},
            "same": {"token_ttl": 60}, "only-left": {}}
    right = {"app-prod": {"bound_service_account_namespaces": ["app-prod"], "token_policies": ["app-prod-app"], "token_ttl": 60},
             "same": {"token_ttl": 60}, "only-right": {}}
    prof = PolicyProfile(name="p", mappings=[{"left": "*-dev", "right": "*-prod"}], rewrites=[{"find": "-dev", "replace": "-prod"}])
    pairs = {(p["left"], p["right"]): p for p in compare_roles(left, right, prof)}
    mapped = pairs[("app-dev", "app-prod")]
    assert mapped["status"] == "different" and [f["field"] for f in mapped["fields"]] == ["token_ttl"]
    assert pairs[("same", "same")]["status"] == "equal"
    assert pairs[("only-left", None)]["status"] == "left_only" and pairs[(None, "only-right")]["status"] == "right_only"


@pytest.fixture
def k8s(client, vaults):
    """A throwaway Kubernetes auth mount on each Vault (no cluster needed to read and write roles)."""
    mount = f"k8s-test-{uuid.uuid4().hex[:6]}"
    vs = [httpx.Client(base_url=f"{a}/v1/", headers={"X-Vault-Token": t}, timeout=10)
          for a, t in ((vaults[0], "root-a"), (vaults[1], "root-b"))]
    try:
        yield from _k8s_mounts(client, mount, vs)
    finally:
        for v in vs:
            v.delete(f"sys/auth/{mount}")


def _k8s_mounts(client, mount, vs):
    for v in vs:
        v.post(f"sys/auth/{mount}", json={"type": "kubernetes"}).raise_for_status()
        v.post(f"auth/{mount}/config", json={"kubernetes_host": "https://kubernetes.example:443", "kubernetes_ca_cert": CA,
                                             "disable_local_ca_jwt": True}).raise_for_status()  # OpenBao requires the CA
    a, b = vs
    a.post(f"auth/{mount}/role/payments-dev", json={"bound_service_account_names": ["payments"],
                                                     "bound_service_account_namespaces": ["payments-dev"],
                                                     "token_policies": ["lockstep-limited"], "token_ttl": "1h"}).raise_for_status()
    a.post(f"auth/{mount}/role/wide", json={"bound_service_account_names": ["*"], "bound_service_account_namespaces": ["*"],
                                             "token_policies": ["no-such-policy"]}).raise_for_status()
    b.post(f"auth/{mount}/role/payments-prod", json={"bound_service_account_names": ["payments"],
                                                      "bound_service_account_namespaces": ["payments-prod"],
                                                      "token_policies": ["lockstep-limited"], "token_ttl": 3600,
                                                      "audience": "vault"}).raise_for_status()
    ids = [client.post("/api/connections", json={"preset_id": i, "auth": {"method": "token", "token": t}}).json()["id"]
           for i, t in ((0, "root-a"), (1, "root-b"))]
    yield mount, ids, vs


def test_mounts_list_and_findings(client, k8s):
    mount, (ca, _), _ = k8s
    ms = client.get("/api/roles/mounts", params={"conn_id": ca}).json()
    assert {"path": mount, "type": "kubernetes", "kind": "kubernetes", "description": ""} in ms
    assert any(m["kind"] == "jwt" and m["path"] == "jwt" for m in ms) and any(m["path"] == "oidc" for m in ms)
    out = client.get("/api/roles", params={"conn_id": ca, "mount": mount}).json()
    roles = {r["name"]: r for r in out["roles"]}
    assert roles["payments-dev"]["role"]["token_ttl"] == 3600
    assert roles["payments-dev"]["policies"] == ["lockstep-limited", "default"]
    wide = [f["message"] for f in roles["wide"]["findings"]]
    assert any("Any service account in any namespace" in m for m in wide) and any("no-such-policy" in m for m in wide)
    jwt = client.get("/api/roles", params={"conn_id": ca, "mount": "jwt"}).json()
    assert jwt["kind"] == "jwt" and jwt["roles"][0]["name"] == "default"
    assert client.get("/api/roles", params={"conn_id": ca, "mount": "userpass"}).status_code == 404


def test_explain_compare_and_granting(client, k8s):
    mount, (ca, cb), _ = k8s
    r = client.post("/api/roles/explain", json={"conn_id": ca, "mount": mount, "role": "payments-dev",
                                                "kv_mount": "app-config", "prefix": "payments"})
    assert r.status_code == 200, r.text
    ex = r.json()
    assert {p["name"] for p in ex["policies"]} == {"lockstep-limited", "default"}
    rows = {x["path"]: x["cells"] for x in ex["rows"]}
    assert rows["payments/db"]["read"]["ok"] and not rows["payments/api"]["read"]["ok"]

    r = client.post("/api/roles/compare", json={"left": {"conn_id": ca, "mount": mount}, "right": {"conn_id": cb, "mount": mount},
                                                "profile": {"name": "p", "mappings": [{"left": "*-dev", "right": "*-prod"}],
                                                            "rewrites": [{"find": "-dev", "replace": "-prod"}]}})
    assert r.status_code == 200, r.text
    pairs = {(p["left"], p["right"]): p for p in r.json()["pairs"]}
    diff = pairs[("payments-dev", "payments-prod")]
    assert diff["status"] == "different" and [f["field"] for f in diff["fields"]] == ["audience"]
    assert pairs[("wide", None)]["status"] == "left_only"
    bad = client.post("/api/roles/compare", json={"left": {"conn_id": ca, "mount": mount}, "right": {"conn_id": cb, "mount": "jwt"}})
    assert bad.status_code == 400

    g = client.get("/api/roles/granting", params={"conn_id": ca, "policy": "lockstep-readonly"}).json()
    assert {"mount": "jwt", "kind": "jwt", "role": "default"} in g["roles"]
    g = client.get("/api/roles/granting", params={"conn_id": ca, "policy": "lockstep-limited"}).json()
    assert {"mount": mount, "kind": "kubernetes", "role": "payments-dev"} in g["roles"]


def test_check_and_templates(client, k8s):
    _, (ca, _), _ = k8s
    t = {x["id"]: x for x in client.get("/api/roles/templates").json()}
    assert {"kubernetes", "gitlab-ci", "github-actions", "k8s-issuer", "oidc-group"} <= set(t)
    body = t["gitlab-ci"]["body"] | {"token_policies": ["lockstep-limited", "missing-one"], "token_ttl": "15m"}
    out = client.post("/api/roles/check", json={"kind": "jwt", "body": body, "conn_id": ca}).json()
    assert out["role"]["token_ttl"] == 900 and out["role"]["bound_claims"]["project_path"] == "mygroup/my-app"
    assert any("missing-one" in f["message"] for f in out["findings"])
    assert not any(f["level"] == "error" for f in out["findings"])


def test_bundle_with_roles(client, k8s, tmp_path):
    mount, (ca, _), _ = k8s
    roles = [{"kind": "kubernetes", "mount": mount, "name": "payments-dev",
              "body": {"bound_service_account_names": ["payments"], "bound_service_account_namespaces": ["payments-dev"],
                       "token_policies": ["lockstep-limited"], "token_ttl": "2h"}},
             {"kind": "jwt", "mount": "jwt", "name": "ci-deploy",
              "body": {"role_type": "jwt", "user_claim": "user_email", "bound_claims": {"project_path": "g/app"},
                       "token_policies": ["lockstep-limited"]}}]
    r = client.post("/api/policies/bundle", json={"roles": roles, "conn_id": ca,
                                                  "terraform": {"tool": "terraform", "provider": "~> 5.0", "layout": "single", "imports": True}})
    assert r.status_code == 200, r.text
    z = zipfile.ZipFile(io.BytesIO(r.content))
    assert json.loads(z.read(f"roles/{mount}/payments-dev.json"))["token_ttl"] == 7200
    assert "vault write \"auth/$mount/role/$name\"" in z.read("apply.sh").decode()
    tf = z.read("terraform/roles.tf").decode()
    assert 'resource "vault_kubernetes_auth_backend_role"' in tf and 'resource "vault_jwt_auth_backend_role"' in tf
    assert '"project_path" = "g/app"' in tf
    imports = z.read("terraform/imports.tf").decode()
    assert f'id = "auth/{mount}/role/payments-dev"' in imports and "ci-deploy" not in imports
    assert f"auth/{mount}/role/payments-dev` (kubernetes) (exists already)" in z.read("README.md").decode()
    assert client.post("/api/policies/bundle", json={}).status_code == 400


def test_apply_script_writes_roles(client, k8s, vaults, tmp_path):
    import os
    import shutil
    import subprocess
    import sys
    from test_policy_build import DIFF_SHIM, VAULT_SHIM
    if not shutil.which("bash"):
        pytest.skip("needs bash")
    mount, _, (a, _) = k8s
    bindir = tmp_path / "bin"
    bindir.mkdir()
    (bindir / "vault").write_text(VAULT_SHIM.format(python=sys.executable))
    (bindir / "diff").write_text(DIFF_SHIM.format(python=sys.executable))
    for f in bindir.iterdir():
        f.chmod(0o755)
    r = client.post("/api/policies/bundle", json={"roles": [{"kind": "kubernetes", "mount": mount, "name": "from-bundle",
        "body": {"bound_service_account_names": ["x"], "bound_service_account_namespaces": ["y"], "token_policies": ["p"], "token_ttl": "30m"}}]})
    zipfile.ZipFile(io.BytesIO(r.content)).extractall(tmp_path / "b")
    env = {**os.environ, "VAULT_ADDR": vaults[0], "VAULT_TOKEN": "root-a", "PATH": f"{bindir}:{os.environ['PATH']}"}
    dry = subprocess.run(["bash", str(tmp_path / "b" / "apply.sh"), "--dry-run"], env=env, capture_output=True, text=True)
    assert dry.returncode == 0, dry.stderr
    assert f"new      auth/{mount}/role/from-bundle" in dry.stdout
    assert a.get(f"auth/{mount}/role/from-bundle").status_code == 404
    subprocess.run(["bash", str(tmp_path / "b" / "apply.sh")], env=env, check=True, capture_output=True)
    role = a.get(f"auth/{mount}/role/from-bundle").json()["data"]
    assert role["token_ttl"] == 1800 and role["bound_service_account_names"] == ["x"]


@pytest.fixture
def approle(client, vaults):
    mount = f"approle-test-{uuid.uuid4().hex[:6]}"
    v = httpx.Client(base_url=f"{vaults[0]}/v1/", headers={"X-Vault-Token": "root-a"}, timeout=10)
    try:
        v.post(f"sys/auth/{mount}", json={"type": "approle"}).raise_for_status()
        v.post(f"auth/{mount}/role/ci", json={"token_policies": ["lockstep-readonly"], "token_ttl": "15m"}).raise_for_status()
        v.post(f"auth/{mount}/role/open", json={"bind_secret_id": False, "secret_id_bound_cidrs": [], "token_bound_cidrs": ["10.0.0.0/8"],
                                                 "token_policies": ["lockstep-readonly"]}).raise_for_status()
        conn = client.post("/api/connections", json={"preset_id": 0, "auth": {"method": "token", "token": "root-a"}}).json()["id"]
        yield mount, conn, v
    finally:
        v.delete(f"sys/auth/{mount}")


def test_approle_roles_findings_and_secret_id(client, approle, vaults, caplog):
    import logging
    mount, conn, v = approle
    out = client.get("/api/roles", params={"conn_id": conn, "mount": mount}).json()
    assert out["kind"] == "approle"
    roles = {r["name"]: r for r in out["roles"]}
    assert any("never expire" in f["message"] for f in roles["ci"]["findings"])
    assert any("No secret ID" in f["message"] for f in roles["open"]["findings"])

    with caplog.at_level(logging.INFO, logger="lockstep.audit"):
        r = client.post("/api/roles/secret-id", json={"conn_id": conn, "mount": mount, "role": "ci", "ttl": "5m"})
    assert r.status_code == 200, r.text
    got = r.json()
    assert got["role_id"] and got["wrapping_token"] and got["ttl"] == 300
    assert not any(got["wrapping_token"] in m for m in caplog.messages)
    # The wrapped secret ID logs in with the role ID
    secret_id = httpx.post(f"{vaults[0]}/v1/sys/wrapping/unwrap", headers={"X-Vault-Token": got["wrapping_token"]}).json()["data"]["secret_id"]
    login = httpx.post(f"{vaults[0]}/v1/auth/{mount}/login", json={"role_id": got["role_id"], "secret_id": secret_id}).json()
    assert "lockstep-readonly" in login["auth"]["policies"]
    assert client.post("/api/roles/secret-id", json={"conn_id": conn, "mount": "jwt", "role": "default"}).status_code == 400


def test_approle_in_bundle_and_write(client, approle):
    import io
    mount, conn, v = approle
    spec = {"kind": "approle", "mount": mount, "name": "built", "body": {"secret_id_ttl": "1h", "token_policies": ["lockstep-readonly"]}}
    z = zipfile.ZipFile(io.BytesIO(client.post("/api/policies/bundle", json={"roles": [spec], "terraform": {"tool": "terraform", "provider": "~> 5.0", "layout": "single", "imports": False}}).content))
    assert 'resource "vault_approle_auth_backend_role"' in z.read("terraform/roles.tf").decode()
    pre = client.post("/api/access/preview", json={"conn_id": conn, "roles": [spec]}).json()[0]
    assert pre["action"] == "new" and pre["status"] == "ready"
    out = client.post("/api/access/apply", json={"conn_id": conn, "roles": [spec], "expected": {pre["id"]: None}, "confirm": True}).json()[0]
    assert out["status"] == "applied"
    assert v.get(f"auth/{mount}/role/built").json()["data"]["secret_id_ttl"] == 3600
