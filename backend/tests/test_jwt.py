"""Vault's JWT auth method: real logins with ID tokens from the dev Dex (password grant).

The seed configures `auth/jwt` on both Vaults to trust Dex. Its default role gives
read-only access; alice@example.com gets admin through her identity entity.
"""

import os

import httpx
import pytest

from lockstep.cli import main

DEX = os.environ.get("DEX_URL", "http://dex.localhost:5556/dex")
pytestmark = pytest.mark.usefixtures("vaults")


def id_token(user: str) -> str:
    try:
        r = httpx.post(f"{DEX}/token", auth=("vault", "vault-dev-secret"), timeout=5, data={
            "grant_type": "password", "username": f"{user}@example.com", "password": "password",
            "scope": "openid email profile"})
    except httpx.HTTPError:
        pytest.skip(f"Dex not reachable at {DEX}")
    r.raise_for_status()
    return r.json()["id_token"]


def login(client, jwt: str, **extra):
    return client.post("/api/connections", json={"preset_id": 0, "auth": {"method": "jwt", "jwt": jwt, **extra}})


def test_jwt_login_uses_the_default_role_and_identity_policies(client):
    r = login(client, id_token("alice"))
    assert r.status_code == 201, r.text
    c = r.json()
    assert c["auth_method"] == "jwt"
    assert "lockstep-admin" in c["policies"]  # from alice's entity
    assert c["expires_at"] is not None

    bob = login(client, id_token("bob"), role="default").json()
    assert "lockstep-readonly" in bob["policies"] and "lockstep-admin" not in bob["policies"]


def test_jwt_login_token_works_and_is_revoked_on_sign_out(client):
    conn = login(client, id_token("alice")).json()
    assert client.get(f"/api/connections/{conn['id']}/mounts").status_code == 200
    assert client.delete(f"/api/connections/{conn['id']}").status_code == 204


@pytest.mark.parametrize("jwt, extra", [
    ("not-a-jwt", {}),
    (None, {"role": "no-such-role"}),
    (None, {"mount": "oidc"}),  # an OIDC-only role can't take a JWT
])
def test_jwt_login_rejected(client, jwt, extra):
    r = login(client, jwt or id_token("alice"), **extra)
    assert r.status_code == 401, r.text
    assert r.json()["detail"]["message"].startswith("Vault rejected the credentials")


def test_jwt_must_not_be_empty(client):
    assert login(client, "").status_code == 422


def test_cli_jwt_login_from_env_and_file(vaults, monkeypatch, tmp_path, capsys):
    for var in ("VAULT_ADDR", "VAULT_TOKEN", "LOCKSTEP_LEFT_TOKEN", "LOCKSTEP_RIGHT_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))  # no ~/.vault-token to fall back on
    jwt_file = tmp_path / "token.jwt"
    jwt_file.write_text(id_token("alice") + "\n")
    monkeypatch.setenv("LOCKSTEP_LEFT_JWT", id_token("bob"))
    rc = main(["compare", "--left-addr", vaults[0], "--right-addr", vaults[1], "--mount", "app-config",
               "--prefix", "payments", "--left-auth", "jwt", "--right-auth", "jwt",
               "--right-jwt-file", str(jwt_file), "-q"])
    assert rc == 1, capsys.readouterr()  # payments/db differs between the Vaults


def test_cli_jwt_login_needs_a_jwt(vaults, monkeypatch, capsys):
    monkeypatch.delenv("LOCKSTEP_LEFT_JWT", raising=False)
    rc = main(["compare", "--left-addr", vaults[0], "--mount", "app-config", "--left-auth", "jwt"])
    assert rc == 2
    assert "No JWT for the left side" in capsys.readouterr().err


def test_cli_jwt_login_failure_is_one_line(vaults, monkeypatch, capsys):
    monkeypatch.setenv("LOCKSTEP_LEFT_JWT", "not-a-jwt")
    rc = main(["compare", "--left-addr", vaults[0], "--mount", "app-config", "--left-auth", "jwt"])
    assert rc == 2
    assert "jwt login to" in capsys.readouterr().err
