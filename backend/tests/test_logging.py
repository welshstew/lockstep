import json
import logging

import pytest
from fastapi.testclient import TestClient

from lockstep import logs
from lockstep.config import get_settings


def _record(msg="hello", name="lockstep.test", level=logging.INFO, **extra):
    r = logging.LogRecord(name, level, __file__, 1, msg, None, None)
    r.request_id = "ab12cd34"
    for k, v in extra.items():
        setattr(r, k, v)
    return r


def test_text_lines_have_a_utc_timestamp_level_and_request_id():
    line = logs.TextFormatter().format(_record())
    ts, level, name, rid, msg = line.split(None, 4)
    assert ts.endswith("Z") and "T" in ts and len(ts) == len("2026-11-25T10:04:31.207Z")
    assert (level, name, rid, msg) == ("INFO", "lockstep.test", "[ab12cd34]", "hello")


def test_json_lines_carry_extra_fields():
    out = json.loads(logs.JsonFormatter().format(_record(fields={"status": 200, "ms": 4})))
    assert out["level"] == "info" and out["request_id"] == "ab12cd34" and out["msg"] == "hello"
    assert out["status"] == 200 and out["ms"] == 4 and out["ts"].endswith("Z")


@pytest.fixture
def app_with(monkeypatch):
    clients = []

    def make(**env):
        for k, v in env.items():
            monkeypatch.setenv(f"LOCKSTEP_{k.upper()}", v)
        get_settings.cache_clear()
        from lockstep.main import create_app
        app = create_app()
        c = TestClient(app, headers={"X-Requested-With": "lockstep"}, raise_server_exceptions=False)
        clients.append(c)
        return app, c

    yield make
    get_settings.cache_clear()
    logs.setup()  # back to the defaults for the tests that follow


def test_one_line_per_api_request_with_request_id(app_with, caplog):
    _, c = app_with()
    with caplog.at_level(logging.INFO):
        r = c.get("/api/config", headers={"X-Request-ID": "from-proxy-1"})
        c.get("/healthz")  # probes stay quiet below debug
    assert r.headers["X-Request-ID"] == "from-proxy-1"
    lines = [x for x in caplog.records if x.name == "lockstep.http"]
    assert len(lines) == 1
    assert lines[0].getMessage().startswith("GET /api/config 200 ")
    assert lines[0].request_id == "from-proxy-1" and lines[0].fields["status"] == 200


def test_a_bad_request_id_is_replaced(app_with):
    _, c = app_with()
    rid = c.get("/api/config", headers={"X-Request-ID": "no spaces\nor newlines"}).headers["X-Request-ID"]
    assert len(rid) == 8 and rid.isalnum()


def test_startup_summary_names_presets_and_settings(app_with, caplog):
    with caplog.at_level(logging.INFO):
        app_with(rate_limit_per_minute="120")
    text = "\n".join(r.getMessage() for r in caplog.records if r.name == "lockstep")
    assert "starting; log level info, format text" in text
    assert "preset Vault 0: Vault A at " in text and "rate limit 120/min" in text


def test_crash_is_logged_with_request_id_and_answered_500(app_with, caplog):
    app, c = app_with()

    @app.get("/api/boom")
    def boom():
        raise RuntimeError("kaboom")

    with caplog.at_level(logging.INFO):
        r = c.get("/api/boom")
    assert r.status_code == 500
    rid = r.headers["X-Request-ID"]
    assert rid in r.json()["detail"]["message"]
    crash = [x for x in caplog.records if x.name == "lockstep.http" and x.exc_info]
    assert crash and "kaboom" in str(crash[0].exc_info[1]) and crash[0].request_id == rid


def test_debug_level_logs_vault_calls_and_never_the_token(app_with, caplog, vaults):
    _, c = app_with(log_level="debug")
    with caplog.at_level(logging.DEBUG):
        r = c.post("/api/connections", json={"preset_id": 0, "auth": {"method": "token", "token": "root-a"}})
    assert r.status_code == 201
    text = "\n".join(x.getMessage() for x in caplog.records)
    assert "GET auth/token/lookup-self -> 200" in text
    assert "signed in to Vault A as token (token)" in text
    assert "root-a" not in text


def test_failed_sign_in_is_logged(app_with, caplog, vaults):
    _, c = app_with()
    with caplog.at_level(logging.INFO):
        r = c.post("/api/connections", json={"preset_id": 0, "auth": {
            "method": "userpass", "username": "nobody", "password": "wrong-pass-123"}})
    assert r.status_code == 401
    text = "\n".join(x.getMessage() for x in caplog.records if x.name == "lockstep.auth")
    assert "sign-in to Vault A as nobody (userpass) failed: Vault said" in text
    assert "wrong-pass-123" not in "\n".join(x.getMessage() for x in caplog.records)
