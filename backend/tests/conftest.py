import json
import os

import pytest

VAULT_A = os.environ.get("VAULT_A_ADDR", "http://localhost:8200")
VAULT_B = os.environ.get("VAULT_B_ADDR", "http://localhost:8201")

os.environ.setdefault("LOCKSTEP_SESSION_KEY", "test-session-key-0123456789abcdef0123456789")
os.environ.setdefault("LOCKSTEP_COOKIE_SECURE", "false")
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


@pytest.fixture(scope="session")
def vaults():
    if not (_vault_up(VAULT_A) and _vault_up(VAULT_B)):
        pytest.skip("compose Vaults not reachable (run `podman compose up -d`)")
    return VAULT_A, VAULT_B
