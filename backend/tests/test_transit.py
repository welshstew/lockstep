"""The Transit playground (seeded transit/ with app-key and signing-key)."""

import pytest

pytestmark = pytest.mark.usefixtures("vaults")


@pytest.fixture
def conn(client):
    return client.post("/api/connections", json={"preset_id": 0, "auth": {"method": "token", "token": "root-a"}}).json()["id"]


def run(client, conn, **body):
    r = client.post("/api/transit/run", json={"conn_id": conn, "mount": "transit"} | body)
    assert r.status_code == 200, r.text
    return r.json()


def test_keys(client, conn):
    assert {"path": "transit", "description": "Encryption as a service"} in client.get("/api/transit/mounts", params={"conn_id": conn}).json()
    keys = {k["name"]: k for k in client.get("/api/transit/keys", params={"conn_id": conn, "mount": "transit"}).json()["keys"]}
    assert keys["app-key"]["type"] == "aes256-gcm96" and keys["app-key"]["supports_encryption"]
    assert keys["signing-key"]["supports_signing"]


def test_encrypt_decrypt_rewrap(client, conn):
    ct = run(client, conn, key="app-key", op="encrypt", text="héllo wörld")
    assert ct["result"].startswith("vault:v1:") and ct["key_version"] == 1
    assert run(client, conn, key="app-key", op="decrypt", text=ct["result"])["result"] == "héllo wörld"
    assert run(client, conn, key="app-key", op="rewrap", text=ct["result"])["result"].startswith("vault:v")
    bad = client.post("/api/transit/run", json={"conn_id": conn, "mount": "transit", "key": "app-key", "op": "decrypt", "text": "nonsense"})
    assert bad.status_code == 400


def test_sign_verify_hmac(client, conn):
    sig = run(client, conn, key="signing-key", op="sign", text="release 1.2.3")["result"]
    assert run(client, conn, key="signing-key", op="verify", text="release 1.2.3", signature=sig)["valid"] is True
    assert run(client, conn, key="signing-key", op="verify", text="release 1.2.4", signature=sig)["valid"] is False
    assert run(client, conn, key="app-key", op="hmac", text="x")["result"].startswith("vault:v1:")
