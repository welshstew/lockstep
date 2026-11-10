"""Keystore password finder: ranking (unit) and the API against the seeded tree.

Seed (certs mount, both Vaults): some-secrets/files/certs.p12 is opened by the value in
some-secrets/strings/KEYSTORE_PASSWORD; CERT_PASSWORD and DB_PASSWORD are decoys.
"""

import base64
import datetime as dt
import uuid

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

from lockstep.analyze import passwords


def p12(password: str) -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "finder.example.com")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now).not_valid_after(now + dt.timedelta(days=30))
            .sign(key, hashes.SHA256()))
    raw = pkcs12.serialize_key_and_certificates(b"x", key, cert, None,
                                                serialization.BestAvailableEncryption(password.encode()))
    return base64.b64encode(raw).decode()


# --------------------------------------------------------------------------- unit


def test_tokens():
    assert passwords.tokens("CERT_PASSWORD") == {"cert", "password"}
    assert passwords.tokens("certs.p12") == {"cert", "p12"}
    assert passwords.tokens("keyStorePassword") == {"key", "store", "password"}
    assert passwords.tokens("tls.crt") == {"tls", "crt"}


TREE = {
    "some-secrets/files/certs.p12": {"certs.p12": "<keystore>"},
    "some-secrets/passwords/CERT_PASSWORD": {"value": "a"},
    "some-secrets/strings/KEYSTORE_PASSWORD": {"value": "b"},
    "some-secrets/passwords/DB_PASSWORD": {"value": "c"},
    "some-secrets/strings/API_URL": {"value": "https://x"},  # no password-like name: never a candidate
    "some-secrets/strings/LONG_SECRET": {"value": "x" * 300},  # too long for a password
    "some-secrets/strings/PEM_SECRET": {"value": "line1\nline2"},  # multi-line: not a password
}


def test_rank_prefers_shared_names_and_skips_non_passwords():
    ranked = passwords.rank("some-secrets/files/certs.p12", "certs.p12", TREE)
    labels = [c.label for c in ranked]
    assert labels == ["some-secrets/passwords/CERT_PASSWORD · value",
                      "some-secrets/strings/KEYSTORE_PASSWORD · value",
                      "some-secrets/passwords/DB_PASSWORD · value"]
    assert "shares cert, some" in ranked[0].reasons


def test_rank_same_secret_first_and_closer_folders_higher():
    tree = TREE | {
        "some-secrets/files/certs.p12": {"certs.p12": "<keystore>", "keystore.password": "s"},
        "some-secrets/files/other/PIN": {"value": "p"},
        "elsewhere/deep/x/STORE_PASSWORD": {"value": "e"},
    }
    ranked = passwords.rank("some-secrets/files/certs.p12", "certs.p12", tree)
    assert ranked[0].key == "keystore.password" and ranked[0].reasons[0] == "same secret"
    pos = {c.path: i for i, c in enumerate(ranked)}
    assert pos["some-secrets/files/other/PIN"] < pos["some-secrets/passwords/DB_PASSWORD"]
    assert pos["elsewhere/deep/x/STORE_PASSWORD"] > pos["some-secrets/passwords/DB_PASSWORD"]


def test_search_root():
    assert passwords.search_root("some-secrets/files/certs.p12") == "some-secrets/"
    assert passwords.search_root("certs.p12") == ""


def test_opens_and_needs_password():
    from lockstep.analyze.detect import analyze
    v = p12("right-one")
    assert passwords.needs_password(analyze(v).root)
    assert passwords.opens(v, "right-one") and not passwords.opens(v, "wrong")
    assert not passwords.opens("plain text", "x")


# --------------------------------------------------------------------------- API (seeded Vaults)


@pytest.fixture
def conn(client, vaults):
    r = client.post("/api/connections", json={"preset_id": 0, "auth": {"method": "token", "token": "root-a"}})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def find(client, conn, mount, path, key):
    r = client.post("/api/analyze/passwords", json={"conn_id": conn, "mount": mount, "path": path, "key": key})
    assert r.status_code == 200, r.text
    return r


def test_finder_finds_the_password_elsewhere_and_returns_no_values(client, conn):
    r = find(client, conn, "certs", "some-secrets/files/certs.p12", "certs.p12")
    out = r.json()
    assert out["needs_password"] and out["searched"] == "some-secrets/" and out["secrets"] == 5
    first = out["candidates"][0]
    assert (first["path"], first["key"], first["opens"]) == ("some-secrets/strings/KEYSTORE_PASSWORD", "value", True)
    assert [c["opens"] for c in out["candidates"]] == [True, False, False]  # the decoys are tried too
    assert "not-the-store-password" not in r.text and "db-password" not in r.text
    assert out["default"] is None

    # Use it: the inspector opens the keystore with the password from the other secret
    a = client.post("/api/analyze", json={"conn_id": conn, "mount": "certs", "path": "some-secrets/files/certs.p12",
                                          "key": "certs.p12",
                                          "password_ref": {"path": first["path"], "key": first["key"]}})
    assert a.status_code == 200, a.text
    assert a.json()["password_used"] is True


def test_finder_on_a_value_that_needs_no_password(client, conn):
    out = find(client, conn, "certs", "keystores/selfsigned-nopass", "keystore.p12").json()
    assert out["needs_password"] is False and out["candidates"] == []


def test_finder_tries_the_java_default(client, conn, vaults):
    from test_sync import Raw
    raw = Raw(vaults[0], "root-a")
    prefix = f"finder-{uuid.uuid4().hex[:8]}"
    raw.put(f"{prefix}/app/store", {"keystore.p12": p12("changeit")})
    try:
        out = find(client, conn, "app-config", f"{prefix}/app/store", "keystore.p12").json()
        assert out["candidates"] == [] and out["default"] == "changeit"
        assert out["default_label"] == "Java's default keystore password"
    finally:
        raw.purge(prefix)


def test_password_ref_must_be_text(client, conn):
    r = client.post("/api/analyze", json={"conn_id": conn, "mount": "certs", "path": "some-secrets/files/certs.p12",
                                          "key": "certs.p12", "password_ref": {"path": "some-secrets/files/certs.p12",
                                                                               "key": "missing"}})
    assert r.status_code == 400


def test_expiry_scan_opens_keystores_with_a_password_from_elsewhere(client, conn):
    r = client.post("/api/expiry", json={"sides": [{"side": "left", "conn_id": conn, "mount": "certs"}]})
    rows = [x for x in r.json()["certificates"] if x["path"] == "some-secrets/files/certs.p12"]
    assert rows and {x["opened_with"] for x in rows} == {"some-secrets/strings/KEYSTORE_PASSWORD · value"}
    assert not [x for x in r.json()["locked"] if x["path"] == "some-secrets/files/certs.p12"]
