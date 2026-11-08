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
