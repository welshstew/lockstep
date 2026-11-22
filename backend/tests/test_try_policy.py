"""Trying a draft policy for real, against the seeded dev Vault."""

import httpx
import pytest

pytestmark = pytest.mark.usefixtures("vaults")
DRAFT = """
path "app-config/metadata/*" { capabilities = ["list"] }
path "app-config/data/payments/*" { capabilities = ["read"] }
"""


def connect(client, **auth):
    auth.setdefault("method", "token")
    r = client.post("/api/connections", json={"preset_id": 0, "auth": auth})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def temp_policies(vaults):
    r = httpx.request("LIST", f"{vaults[0]}/v1/sys/policies/acl", headers={"X-Vault-Token": "root-a"})
    return [k for k in r.json()["data"]["keys"] if k.startswith("lockstep-try-")]


def test_try_a_draft_and_clean_up(client, vaults):
    before = temp_policies(vaults)
    conn = connect(client, token="root-a")
    r = client.post("/api/policies/try", json={"conn_id": conn, "mount": "app-config", "text": DRAFT})
    assert r.status_code == 200, r.text
    out = r.json()
    by_path = {row["path"]: row["cells"] for row in out["rows"]}
    assert by_path["payments/db"]["read"]["ok"] and not by_path["payments/db"]["write"]["ok"]
    assert out["mode"] == "vault" and out["temporary_policy"].startswith("lockstep-try-")
    assert out["disagreements"] == []  # the matcher agrees with Vault
    assert temp_policies(vaults) == before  # removed again


def test_try_needs_sudo(client):
    conn = connect(client, method="userpass", username="bob", password="password")
    r = client.post("/api/policies/try", json={"conn_id": conn, "mount": "app-config", "text": DRAFT})
    assert r.status_code == 403
    assert "sys/policies/acl" in r.json()["detail"]["message"]


def test_try_bad_hcl(client):
    conn = connect(client, token="root-a")
    r = client.post("/api/policies/try", json={"conn_id": conn, "mount": "app-config", "text": "path {"})
    assert r.status_code == 400
