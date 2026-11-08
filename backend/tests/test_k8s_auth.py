"""Kubernetes auth: policy checks (always) and real logins against the k3s dev cluster
(when the service account token is mounted, i.e. `podman compose --profile k8s`)."""

import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from lockstep.config import Settings, get_settings
from lockstep.main import create_app

TOKEN = "/var/run/secrets/kubernetes.io/serviceaccount/token"
H = {"X-Requested-With": "lockstep"}


def make_client(**overrides) -> TestClient:
    app = create_app()
    base = get_settings().model_dump()
    app.dependency_overrides[get_settings] = lambda: Settings(**(base | overrides))
    return TestClient(app, headers=H)


def login(c, role="lockstep-admin", preset=0):
    return c.post("/api/connections", json={"preset_id": preset, "auth": {"method": "kubernetes", "role": role}})


# --------------------------------------------------------------------------- policy


def test_disabled_by_default_and_hidden(tmp_path):
    tok = tmp_path / "token"
    tok.write_text("x.eyJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6bnM6c2EifQ.y")
    with make_client(k8s_auth_enabled=False, k8s_token_path=str(tok)) as c:
        assert c.get("/api/config").json()["k8s_auth"]["available"] is False
        r = login(c)
        assert r.status_code == 403 and "disabled" in r.json()["detail"]["message"]


def test_enabled_but_no_token_file(tmp_path):
    with make_client(k8s_auth_enabled=True, k8s_token_path=str(tmp_path / "missing")) as c:
        assert c.get("/api/config").json()["k8s_auth"]["available"] is False
        assert login(c).status_code == 400


def test_role_allowlist(tmp_path):
    tok = tmp_path / "token"
    tok.write_text("x.eyJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6bnM6c2EifQ.y")
    with make_client(k8s_auth_enabled=True, k8s_token_path=str(tok), k8s_auth_roles=["reader"]) as c:
        cfg = c.get("/api/config").json()["k8s_auth"]
        assert cfg["available"] and cfg["roles"] == ["reader"] and cfg["service_account"] == "ns/sa"
        r = login(c, role="admin")
        assert r.status_code == 403 and "isn't allowed" in r.json()["detail"]["message"]


def test_roles_setting_accepts_comma_list(monkeypatch):
    monkeypatch.setenv("LOCKSTEP_K8S_AUTH_ROLES", "a, b")
    assert Settings().k8s_auth_roles == ["a", "b"]
    monkeypatch.setenv("LOCKSTEP_K8S_AUTH_ROLES", '["c"]')
    assert Settings().k8s_auth_roles == ["c"]


# --------------------------------------------------------------------------- real cluster

needs_k3s = pytest.mark.skipif(not (Path(TOKEN).is_file() and os.environ.get("LOCKSTEP_K8S_AUTH_ENABLED") == "true"),
                               reason="no service account token mounted (run with --profile k8s)")


@needs_k3s
@pytest.mark.usefixtures("vaults")
def test_login_as_service_account(client, vaults):
    import httpx
    assert client.get("/api/config").json()["k8s_auth"]["service_account"] == "lockstep/lockstep"
    r = login(client)
    assert r.status_code == 201, r.text
    c = r.json()
    assert c["auth_method"] == "kubernetes" and "lockstep-admin" in c["policies"]
    assert "lockstep" in c["display_name"]
    assert client.get(f"/api/connections/{c['id']}/mounts").status_code == 200

    from lockstep.session import COOKIE_NAME, decode
    token = decode(client.cookies.get(COOKIE_NAME), get_settings()).connections[0].token
    assert client.delete(f"/api/connections/{c['id']}").status_code == 204
    assert httpx.get(f"{vaults[0]}/v1/auth/token/lookup-self", headers={"X-Vault-Token": token}).status_code == 403


@needs_k3s
@pytest.mark.usefixtures("vaults")
def test_reader_role_on_vault_b(client):
    r = login(client, role="lockstep-reader", preset=1)
    assert r.status_code == 201 and "lockstep-readonly" in r.json()["policies"]


@needs_k3s
@pytest.mark.usefixtures("vaults")
def test_role_bound_to_another_service_account_is_refused(client):
    r = login(client, role="other-app")
    assert r.status_code == 401 and "not authorized" in r.json()["detail"]["message"]


@needs_k3s
@pytest.mark.usefixtures("vaults")
def test_allowlist_blocks_a_role_vault_would_accept():
    with make_client(k8s_auth_roles=["lockstep-reader"]) as c:
        assert login(c, role="lockstep-admin").status_code == 403
        assert login(c, role="lockstep-reader").status_code == 201
