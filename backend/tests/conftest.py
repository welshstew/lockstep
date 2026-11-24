import json
import os

import pytest

VAULT_A = os.environ.get("VAULT_A_ADDR", "http://localhost:8200")
VAULT_B = os.environ.get("VAULT_B_ADDR", "http://localhost:8201")

os.environ.setdefault("LOCKSTEP_SESSION_KEY", "test-session-key-0123456789abcdef0123456789")
os.environ.setdefault("LOCKSTEP_COOKIE_SECURE", "false")
os.environ.setdefault("LOCKSTEP_USER_WRITE", "on")
os.environ.setdefault("LOCKSTEP_PRESET_CONNECTIONS", json.dumps([
    {"name": "Vault A", "url": VAULT_A, "browser_url": "http://localhost:8200"},
    {"name": "Vault B", "url": VAULT_B, "browser_url": "http://localhost:8201"},
]))


def _vault_up(addr: str) -> bool:
    import httpx
    try:
        return httpx.get(f"{addr}/v1/sys/health", timeout=2).status_code == 200
    except httpx.HTTPError:
        return False


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from lockstep.main import create_app
    with TestClient(create_app(), headers={"X-Requested-With": "lockstep"}) as c:
        yield c


def has_plugin_b(kind: str, name: str) -> bool:
    """Whether Vault B has a built-in plugin: OpenBao, run as side B, ships without LDAP, AWS,
    Azure and GCP (VAULT_B_ADDR=http://bao:8200)."""
    import httpx
    r = httpx.get(f"{VAULT_B}/v1/sys/plugins/catalog", headers={"X-Vault-Token": "root-b"}, timeout=5)
    return r.status_code == 200 and name in (r.json()["data"].get(kind) or [])


def has_namespaces_b() -> bool:
    """Whether Vault B has namespaces (OpenBao 2.3+, Vault Enterprise); Vault Community answers
    "enterprise-only feature"."""
    import httpx
    r = httpx.get(f"{VAULT_B}/v1/sys/namespaces/lockstep-no-such-namespace", headers={"X-Vault-Token": "root-b"}, timeout=5)
    return r.status_code in (200, 404) and "enterprise-only" not in r.text


def is_openbao_b() -> bool:
    """Whether Vault B is OpenBao: its built-in plugins report versions ending in .bao."""
    import httpx
    r = httpx.get(f"{VAULT_B}/v1/sys/mounts", headers={"X-Vault-Token": "root-b"}, timeout=5)
    return r.status_code == 200 and any(".bao" in str(m.get("running_plugin_version")) for m in r.json()["data"].values())


def ca_pem() -> str:
    """A throwaway self-signed CA certificate, for configs that need one (Kubernetes auth)."""
    import datetime as dt

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "kubernetes.example")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now).not_valid_after(now + dt.timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM).decode()


@pytest.fixture(scope="session")
def vaults():
    if not (_vault_up(VAULT_A) and _vault_up(VAULT_B)):
        pytest.skip("compose Vaults not reachable (run `podman compose up -d`)")
    return VAULT_A, VAULT_B
