"""Browser security headers sent by the app itself, and the switch for the API documentation."""

import pytest
from fastapi.testclient import TestClient

from lockstep.config import get_settings


@pytest.fixture
def app_with(monkeypatch):
    def make(**env):
        for k, v in env.items():
            monkeypatch.setenv(f"LOCKSTEP_{k.upper()}", v)
        get_settings.cache_clear()
        from lockstep.main import create_app
        return TestClient(create_app(), headers={"X-Requested-With": "lockstep"})

    yield make
    get_settings.cache_clear()


@pytest.mark.parametrize("path", ["/api/config", "/healthz", "/api/no-such-thing"])
def test_security_headers_everywhere(app_with, path):
    r = app_with().get(path)
    h = r.headers
    assert h["x-content-type-options"] == "nosniff" and h["referrer-policy"] == "no-referrer"
    assert h["x-frame-options"] == "DENY" and "camera=()" in h["permissions-policy"]
    csp = h["content-security-policy"]
    assert "script-src 'self';" in csp and "frame-ancestors 'none'" in csp and "unsafe-eval" not in csp
    assert "strict-transport-security" not in h  # the default public URL is http


def test_refused_requests_carry_them_too(app_with):
    r = app_with().post("/api/connections", json={}, headers={"X-Requested-With": ""})
    assert r.status_code == 403 and r.headers["x-frame-options"] == "DENY"


def test_hsts_only_over_https(app_with):
    assert app_with(public_url="https://lockstep.example.com").get("/healthz").headers[
        "strict-transport-security"] == "max-age=31536000"


def test_api_docs_get_a_policy_that_lets_swagger_load(app_with):
    r = app_with().get("/api/docs")
    assert r.status_code == 200 and "cdn.jsdelivr.net" in r.text
    assert "https://cdn.jsdelivr.net" in r.headers["content-security-policy"]
    assert app_with().get("/api/openapi.json").status_code == 200


def test_api_docs_can_be_turned_off(app_with):
    c = app_with(api_docs="off")
    assert c.get("/api/docs").status_code == 404 and c.get("/api/openapi.json").status_code == 404
    assert c.get("/api/config").status_code == 200


def test_no_redoc(app_with):
    assert app_with().get("/redoc").status_code == 404
