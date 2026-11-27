"""Custom Vault addresses: normalised before the patterns, private addresses refused, and only the
checked address connected to."""

import asyncio

import httpcore
import httpx
import pytest

import lockstep.vault as vault
from lockstep.addresses import AddressError, check_origin, normalise, resolve
from lockstep.config import Settings
from lockstep.vault import VaultClient, VaultError, _Pinned


def settings(**kw) -> Settings:
    return Settings(session_key="k" * 32, **kw)


@pytest.mark.parametrize("url,origin", [
    ("https://Vault.Example.com", "https://vault.example.com"),
    ("https://vault.example.com:443/", "https://vault.example.com"),
    ("http://vault.example.com:8200", "http://vault.example.com:8200"),
    ("https://vault.example.com.", "https://vault.example.com"),
    ("http://[2001:db8::1]:8200", "http://[2001:db8::1]:8200"),
])
def test_normalised_origins(url, origin):
    assert normalise(url)[0] == origin


@pytest.mark.parametrize("url,why", [
    ("https://vault.example.com@evil.example", "user name"),
    ("https://user:pw@vault.example.com", "user name"),
    ("https://vault.example.com/v1/sys", "without a path"),
    ("https://vault.example.com/?x=1", "without a path"),
    ("https://vault.example.com#frag", "without a path"),
    ("https://vault.example.com?", "without a path"),
    ("ftp://vault.example.com", "http(s)"),
    ("vault.example.com", "http(s)"),
    ("http://vault.example.com:99999", "Not a valid"),
])
def test_refused_addresses(url, why):
    with pytest.raises(AddressError, match=why.replace("(", r"\(").replace(")", r"\)")):
        normalise(url)


def test_patterns_match_the_origin_not_the_raw_text():
    loose = settings(allow_custom_connections=True, custom_url_patterns=[r"https://vault\.example\.com.*"])
    assert check_origin("https://vault.example.com/", loose) == "https://vault.example.com"
    with pytest.raises(AddressError):  # the old string match let this through to evil.example
        check_origin("https://vault.example.com@evil.example", loose)
    strict = settings(allow_custom_connections=True, custom_url_patterns=[r"https://vault\.[a-z]+\.example\.com(:8200)?"])
    assert check_origin("HTTPS://vault.prod.example.com:8200", strict) == "https://vault.prod.example.com:8200"
    with pytest.raises(AddressError, match="allowed list"):
        check_origin("https://vault.prod.example.com:8201", strict)


def test_custom_addresses_are_off_by_default():
    with pytest.raises(AddressError, match="turned off"):
        check_origin("https://vault.example.com", settings())


@pytest.mark.parametrize("host", ["127.0.0.1", "169.254.169.254", "10.1.2.3", "192.168.0.10", "172.16.0.1",
                                  "100.64.0.1", "::1", "fd00::1", "fe80::1", "::ffff:127.0.0.1", "0.0.0.0",
                                  "2130706433", "localhost"])
def test_private_and_local_addresses_are_refused(host):
    with pytest.raises(AddressError, match="private or local"):
        asyncio.run(resolve(host, 8200, settings()))


def test_private_addresses_allowed_when_asked():
    assert asyncio.run(resolve("10.1.2.3", 8200, settings(custom_allow_private=True))) == "10.1.2.3"
    with pytest.raises(AddressError):  # never multicast or unspecified
        asyncio.run(resolve("0.0.0.0", 8200, settings(custom_allow_private=True)))


def test_every_resolved_address_is_checked(monkeypatch):
    async def two(host, port, **kw):  # a name with a public and a private answer
        return [(2, 1, 6, "", ("93.184.216.34", port)), (2, 1, 6, "", ("10.0.0.5", port))]

    monkeypatch.setattr("lockstep.addresses._getaddrinfo", two)
    with pytest.raises(AddressError, match="10.0.0.5"):
        asyncio.run(resolve("mixed.example", 443, settings()))


def test_pinned_backend_connects_to_the_checked_address_only():
    seen = []

    class Inner(httpcore.AsyncNetworkBackend):
        async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
            seen.append((host, port))
            raise httpcore.ConnectError("stop here")

        async def sleep(self, seconds):
            pass

    b = _Pinned(Inner(), {"vault.example.com": "93.184.216.34"})
    with pytest.raises(httpcore.ConnectError):
        asyncio.run(b.connect_tcp("vault.example.com", 8200))
    assert seen == [("93.184.216.34", 8200)]
    with pytest.raises(httpcore.ConnectError, match="wasn't checked"):
        asyncio.run(b.connect_tcp("other.example.com", 8200))
    assert len(seen) == 1


def test_custom_client_wraps_the_pool_and_checks_before_the_first_request(monkeypatch):
    v = VaultClient("http://10.9.9.9:8200", settings(allow_custom_connections=True), custom=True)
    assert isinstance(v._http._transport._pool._network_backend, _Pinned)  # guards the httpx internals used
    with pytest.raises(VaultError) as e:
        asyncio.run(v.request("GET", "sys/health"))
    assert e.value.status == 0 and "private or local" in e.value.message
    preset = VaultClient("http://10.9.9.9:8200", settings())
    assert not isinstance(preset._http._transport._pool._network_backend, _Pinned)


def test_custom_redirects_pass_the_same_checks(monkeypatch):
    monkeypatch.setattr(vault, "BACKOFF", (0, 0))
    s = settings(allow_custom_connections=True, custom_url_patterns=[r"https://vault[0-9]\.example\.com"])

    async def fake_resolve(host, port, settings):
        return "93.184.216.34"

    monkeypatch.setattr("lockstep.addresses.resolve", fake_resolve)

    def handler(req):
        if req.url.host == "vault1.example.com":
            return httpx.Response(307, headers={"location": "https://vault2.example.com/v1/sys/health"})
        if req.url.host == "vault2.example.com":
            return httpx.Response(307, headers={"location": "https://evil.example/v1/sys/health"})
        return httpx.Response(200, json={})

    v = VaultClient("https://vault1.example.com", s, custom=True)
    v._http = httpx.AsyncClient(base_url="https://vault1.example.com/v1/", transport=httpx.MockTransport(handler))
    with pytest.raises(VaultError, match="redirected to evil.example"):
        asyncio.run(v.request("GET", "sys/health"))
    assert set(v._pins) == {"vault1.example.com", "vault2.example.com"}  # the allowed hop was checked and pinned


def test_api_refuses_custom_addresses_by_default(client):
    r = client.post("/api/connections", json={"url": "https://vault.example.com", "auth": {"method": "token", "token": "x"}})
    assert r.status_code == 403 and "turned off" in r.json()["detail"]["message"]


@pytest.fixture
def custom_app(monkeypatch):
    from fastapi.testclient import TestClient

    from lockstep.config import get_settings
    from lockstep.main import create_app

    def make(**env):
        for k, v in env.items():
            monkeypatch.setenv(f"LOCKSTEP_{k.upper()}", v)
        get_settings.cache_clear()
        return TestClient(create_app(), headers={"X-Requested-With": "lockstep"})

    yield make
    get_settings.cache_clear()


@pytest.mark.usefixtures("vaults")
def test_custom_address_to_a_real_vault(custom_app, vaults):
    """Through the API, against Vault A (a private address in the compose network): refused until
    private addresses are allowed, then signed in over the pinned connection."""
    body = {"url": vaults[0] + "/", "auth": {"method": "token", "token": "root-a"}}
    c = custom_app(allow_custom_connections="true")
    r = c.post("/api/connections", json=body)
    assert r.status_code >= 400 and "private or local" in r.text, r.text
    c = custom_app(allow_custom_connections="true", custom_allow_private="true")
    r = c.post("/api/connections", json=body)
    assert r.status_code == 201, r.text
    conn = r.json()["id"]
    assert c.get(f"/api/connections/{conn}/mounts").status_code == 200  # later requests check again
