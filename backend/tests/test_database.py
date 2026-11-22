"""Database credentials (seeded database/ on Vault A against the dev Postgres)."""

import json
import logging

import httpx
import pytest

from lockstep.api.database import redact_url

pytestmark = pytest.mark.usefixtures("vaults")


@pytest.fixture
def root(client):
    return client.post("/api/connections", json={"preset_id": 0, "auth": {"method": "token", "token": "root-a"}}).json()["id"]


def test_redact_url():
    assert redact_url("postgresql://{{username}}:{{password}}@db:5432/x") == "postgresql://{{username}}:{{password}}@db:5432/x"
    assert redact_url("postgresql://app:hunter2@db:5432/x") == "postgresql://app:…@db:5432/x"


def test_overview(client, root):
    assert {"path": "database", "description": "Dev Postgres credentials"} in client.get("/api/database/mounts", params={"conn_id": root}).json()
    out = client.get("/api/database/overview", params={"conn_id": root, "mount": "database"}).json()
    c = out["connections"][0]
    assert c["name"] == "orders" and c["plugin_name"] == "postgresql-database-plugin" and c["username"] == "postgres"
    assert "dev-postgres" not in json.dumps(out)
    roles = {r["name"]: r for r in out["roles"]}
    assert roles["orders-readonly"]["db_name"] == "orders" and roles["orders-readonly"]["default_ttl"] == 3600
    assert any("pg_read_all_data" in s for s in roles["orders-readonly"]["creation_statements"])


def test_generate_credentials(client, root, vaults, caplog):
    with caplog.at_level(logging.INFO, logger="lockstep.audit"):
        r = client.post("/api/database/creds", json={"conn_id": root, "mount": "database", "role": "orders-readonly"})
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["data"]["username"].startswith("v-") and out["data"]["password"]
    assert out["lease_id"].startswith("database/creds/orders-readonly/") and out["ttl"] == 3600
    line = next(json.loads(m) for m in caplog.messages if '"database.creds"' in m)
    assert line["lease_id"] == out["lease_id"] and out["data"]["password"] not in json.dumps(line)
    httpx.put(f"{vaults[0]}/v1/sys/leases/revoke", headers={"X-Vault-Token": "root-a"}, json={"lease_id": out["lease_id"]})
    assert client.post("/api/database/creds", json={"conn_id": root, "mount": "database", "role": "nope"}).status_code >= 400
