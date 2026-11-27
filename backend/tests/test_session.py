import time

from lockstep.config import get_settings
from lockstep.session import Connection, SessionData, decode, encode


def _conn(**kw):
    return Connection(name="x", url="http://v:8200", token="hvs.secret", auth_method="token", **kw)


def test_roundtrip_and_token_not_visible():
    s = get_settings()
    raw = encode(SessionData(connections=[_conn()]), s)
    assert "hvs.secret" not in raw
    assert decode(raw, s).connections[0].token == "hvs.secret"


def test_tampered_cookie_is_discarded():
    s = get_settings()
    raw = encode(SessionData(connections=[_conn()]), s)
    tampered = raw[:-4] + ("AAAA" if raw[-4:] != "AAAA" else "BBBB")
    assert decode(tampered, s).connections == []


def test_expired_connections_dropped():
    s = get_settings()
    raw = encode(SessionData(connections=[_conn(expires_at=time.time() - 1), _conn()]), s)
    assert len(decode(raw, s).connections) == 1


def test_garbage_cookie():
    assert decode("not-a-cookie", get_settings()).connections == []


# ---- per-client API rate limit

def test_rate_limiter_bucket():
    from lockstep.ratelimit import RateLimiter, retry_after
    now = [0.0]
    rl = RateLimiter(per_minute=60, burst=3, max_clients=2, clock=lambda: now[0])
    assert [rl.check("a") for _ in range(3)] == [0, 0, 0]
    wait = rl.check("a")
    assert 0 < wait <= 1 and retry_after(wait) == 1
    assert rl.check("b") == 0  # another client has its own bucket
    now[0] += 1.0  # one token back (60 a minute)
    assert rl.check("a") == 0 and rl.check("a") > 0
    rl.check("c")  # third client: the least recently seen ("b") is forgotten
    assert "b" not in rl._buckets and len(rl._buckets) == 2


def test_api_answers_429_over_the_limit(monkeypatch):
    from fastapi.testclient import TestClient

    from lockstep.config import get_settings
    from lockstep.main import create_app
    monkeypatch.setenv("LOCKSTEP_RATE_LIMIT_PER_MINUTE", "60")
    monkeypatch.setenv("LOCKSTEP_RATE_LIMIT_BURST", "3")
    get_settings.cache_clear()
    try:
        with TestClient(create_app(), headers={"X-Requested-With": "lockstep"}) as c:
            assert [c.get("/api/config").status_code for _ in range(3)] == [200, 200, 200]
            r = c.get("/api/config")
            assert r.status_code == 429 and r.headers["Retry-After"] == "1"
            assert "Too many requests" in r.json()["detail"]["message"]
            assert c.get("/healthz").status_code == 200  # only /api is limited
    finally:
        get_settings.cache_clear()


def test_rate_limit_off_by_default(client):
    assert all(client.get("/api/config").status_code == 200 for _ in range(50))
