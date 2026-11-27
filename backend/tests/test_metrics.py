"""Prometheus metrics at /metrics (LOCKSTEP_METRICS=on)."""

import re
import uuid

import httpx
import pytest
from fastapi.testclient import TestClient

from lockstep import metrics
from lockstep.config import get_settings


@pytest.fixture
def app_with(monkeypatch):
    def make(**env):
        for k, v in env.items():
            monkeypatch.setenv(f"LOCKSTEP_{k.upper()}", v)
        get_settings.cache_clear()
        metrics.reset()
        from lockstep.main import create_app
        return TestClient(create_app(), headers={"X-Requested-With": "lockstep"})

    yield make
    get_settings.cache_clear()
    metrics.enabled = False


def sample(text: str, name: str, **labels) -> float | None:
    for line in text.splitlines():
        m = re.fullmatch(rf"{name}\{{(.*)\}} (\S+)", line)
        if m and all(f'{k}="{v}"' in m.group(1) for k, v in labels.items()):
            return float(m.group(2))
    return None


def test_off_by_default(app_with):
    c = app_with()
    assert c.get("/metrics").status_code in (404, 405) or "lockstep_http" not in c.get("/metrics").text


def test_requests_vault_calls_and_sign_ins(app_with, vaults):
    c = app_with(metrics="on")
    name = f"metrics-{uuid.uuid4().hex[:8]}"
    v = httpx.Client(base_url=f"{vaults[0]}/v1/", headers={"X-Vault-Token": "root-a"})
    v.post(f"auth/userpass/users/{name}", json={"password": "right-pw"}).raise_for_status()
    try:
        bad = c.post("/api/connections", json={"preset_id": 0, "auth": {"method": "userpass", "username": name,
                                                                        "password": "wrong-pw"}})
        assert bad.status_code == 401
        ok = c.post("/api/connections", json={"preset_id": 0, "auth": {"method": "userpass", "username": name,
                                                                       "password": "right-pw"}})
        assert ok.status_code == 201
        conn = ok.json()["id"]
        assert c.get(f"/api/connections/{conn}/mounts").status_code in (200, 404)
    finally:
        v.delete(f"auth/userpass/users/{name}")
    r = c.get("/metrics")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/plain; version=0.0.4")
    text = r.text
    assert sample(text, "lockstep_http_requests_total", route="/api/connections", method="POST", status="401") == 1
    assert sample(text, "lockstep_http_requests_total", route="/api/connections", method="POST", status="201") == 1
    assert sample(text, "lockstep_signins_total", method="userpass", outcome="failure") == 1
    assert sample(text, "lockstep_signins_total", method="userpass", outcome="success") == 1
    host = httpx.URL(vaults[0]).netloc.decode()  # host:port
    assert (sample(text, "lockstep_vault_requests_total", vault=host, status="200") or 0) >= 1
    assert sample(text, "lockstep_vault_request_duration_seconds_count", vault=host) >= 1
    assert 'le="+Inf"' in text
    assert conn not in text and name not in text and "wrong-pw" not in text  # no ids, users or paths
    assert sample(text, "lockstep_http_requests_total", route="/api/connections/{conn_id}/mounts", method="GET")  # templates


def test_rate_limit_refusals(app_with):
    c = app_with(metrics="on", rate_limit_per_minute="1", rate_limit_burst="1")
    codes = [c.get("/api/config").status_code for _ in range(3)]
    assert 429 in codes
    assert sample(c.get("/metrics").text, "lockstep_rate_limited_total", limit="api") >= 1


def test_token(app_with):
    c = app_with(metrics="on", metrics_token="scrape-me")
    assert c.get("/metrics").status_code == 401
    assert c.get("/metrics", headers={"Authorization": "Bearer nope"}).status_code == 401
    assert c.get("/metrics", headers={"Authorization": "Bearer scrape-me"}).status_code == 200


def test_text_format():
    h = metrics.Histogram("x_seconds", "help", ("a",), buckets=(0.1, 1.0))
    h.observe(0.05, 'q"x')
    h.observe(0.5, 'q"x')
    out = "\n".join(h.render())
    assert 'x_seconds_bucket{a="q\\"x",le="0.1"} 1' in out and 'x_seconds_bucket{a="q\\"x",le="1"} 2' in out
    assert 'x_seconds_bucket{a="q\\"x",le="+Inf"} 2' in out and 'x_seconds_count{a="q\\"x"} 2' in out
