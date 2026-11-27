"""The Vault client's HTTP behaviour, with a mock transport: redirects from HA standbys, proxies that
refuse the LIST verb, retries for reads (never writes), and the timeout settings."""

import asyncio

import httpx
import pytest

import lockstep.vault as vault
from lockstep.config import PresetConnection, Settings
from lockstep.vault import VaultClient, VaultError


@pytest.fixture(autouse=True)
def no_backoff(monkeypatch):
    monkeypatch.setattr(vault, "BACKOFF", (0, 0))


def settings(**kw) -> Settings:
    return Settings(session_key="k" * 32, **kw)


def client(handler, url="http://vault-a:8200", **kw) -> tuple[VaultClient, list[httpx.Request]]:
    seen: list[httpx.Request] = []

    def record(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        return handler(req)

    v = VaultClient(url, settings(**kw), token="t-1")
    timeout = v._http.timeout
    v._http = httpx.AsyncClient(base_url=url + "/v1/", headers=v._http.headers, timeout=timeout,
                                transport=httpx.MockTransport(record))
    return v, seen


def run(coro):
    return asyncio.run(coro)


def test_standby_redirect_to_a_preset_vault_is_followed():
    presets = [PresetConnection(name="A", url="http://vault-a:8200"), PresetConnection(name="A2", url="http://vault-a2:8200")]

    def handler(req):
        if req.url.host == "vault-a":
            return httpx.Response(307, headers={"location": "http://vault-a2:8200/v1/sys/mounts?x=1"})
        return httpx.Response(200, json={"data": {"ok": True}})

    v, seen = client(handler, preset_connections=presets)
    assert run(v.request("GET", "sys/mounts")) == {"data": {"ok": True}}
    assert [r.url.host for r in seen] == ["vault-a", "vault-a2"] and seen[1].url.params["x"] == "1"
    assert seen[1].headers["x-vault-token"] == "t-1"


def test_redirect_elsewhere_is_refused_with_a_clear_message():
    v, seen = client(lambda req: httpx.Response(307, headers={"location": "http://evil.example:8200/v1/sys/mounts"}))
    with pytest.raises(VaultError) as e:
        run(v.request("GET", "sys/mounts"))
    assert e.value.status == 307 and "redirected to evil.example" in e.value.message and "active node" in e.value.message
    assert len(seen) == 1  # the token never went to the other host


def test_redirect_loop_stops():
    v, seen = client(lambda req: httpx.Response(307, headers={"location": "/v1/sys/mounts"}))
    with pytest.raises(VaultError, match="too many"):
        run(v.request("GET", "sys/mounts"))
    assert len(seen) == 1 + vault.MAX_REDIRECTS


def test_other_3xx_is_an_error_not_an_empty_answer():
    v, _ = client(lambda req: httpx.Response(304))
    with pytest.raises(VaultError) as e:
        run(v.request("GET", "sys/mounts"))
    assert e.value.status == 304


@pytest.mark.parametrize("refusal", [httpx.Response(405), httpx.Response(403, text="<html>Forbidden</html>")])
def test_list_falls_back_to_get_when_a_proxy_refuses_it(refusal):
    def handler(req):
        if req.method == "LIST":
            return refusal
        assert req.method == "GET" and req.url.params["list"] == "true"
        return httpx.Response(200, json={"data": {"keys": ["a", "b/"]}})

    v, seen = client(handler)
    assert run(v.request("LIST", "kv/metadata/"))["data"]["keys"] == ["a", "b/"]
    run(v.request("LIST", "kv/metadata/b/"))  # remembered: straight to GET
    assert [r.method for r in seen] == ["LIST", "GET", "GET"]


def test_vaults_own_permission_denied_on_list_is_not_retried_as_get():
    v, seen = client(lambda req: httpx.Response(403, json={"errors": ["permission denied"]}))
    with pytest.raises(VaultError) as e:
        run(v.request("LIST", "kv/metadata/"))
    assert e.value.denied and [r.method for r in seen] == ["LIST"]


def test_reads_are_retried_on_503_then_succeed():
    answers = iter([httpx.Response(503), httpx.Response(502), httpx.Response(200, json={"ok": 1})])
    v, seen = client(lambda req: next(answers))
    assert run(v.request("GET", "sys/health")) == {"ok": 1} and len(seen) == 3


def test_reads_give_up_after_two_retries():
    v, seen = client(lambda req: httpx.Response(503, json={"errors": ["Vault is sealed"]}))
    with pytest.raises(VaultError) as e:
        run(v.request("GET", "sys/health"))
    assert e.value.status == 503 and "sealed" in e.value.message and len(seen) == 3


def test_reads_are_retried_when_the_connection_fails():
    calls = {"n": 0}

    def handler(req):
        calls["n"] += 1
        if calls["n"] == 1:
            raise httpx.ConnectError("refused")
        return httpx.Response(200, json={"ok": 1})

    v, _ = client(handler)
    assert run(v.request("GET", "sys/health")) == {"ok": 1} and calls["n"] == 2


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "PATCH"])
def test_writes_are_never_retried(method):
    v, seen = client(lambda req: httpx.Response(503))
    with pytest.raises(VaultError):
        run(v.request(method, "kv/data/x", json={"data": {}}))
    assert len(seen) == 1


def test_a_long_retry_after_is_not_waited_for():
    v, seen = client(lambda req: httpx.Response(429, headers={"retry-after": "30"}))
    with pytest.raises(VaultError) as e:
        run(v.request("GET", "sys/health"))
    assert e.value.status == 429 and len(seen) == 1


def test_timeouts_from_settings_and_presets():
    s = settings(vault_timeout_seconds=40, preset_connections=[PresetConnection(name="Slow", url="http://slow:8200/", timeout_seconds=90)])
    assert VaultClient("http://other:8200", s)._http.timeout.read == 40
    assert VaultClient("http://slow:8200", s)._http.timeout.read == 90
    assert VaultClient("http://slow:8200", s, timeout=5)._http.timeout.read == 5
    assert VaultClient("http://other:8200", settings())._http.timeout.read == 15
