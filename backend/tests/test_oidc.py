"""OIDC redirect login, end to end through the dev Dex."""

import re
from urllib.parse import parse_qs, urljoin, urlparse

import httpx
import pytest

pytestmark = pytest.mark.usefixtures("vaults")
CALLBACK = "/api/auth/oidc/callback"


def dex_login(auth_url: str, email: str, password: str = "password") -> str:
    """Sign in on Dex's form; return the URL Dex redirects back to (our callback)."""
    with httpx.Client(timeout=15) as idp:
        r = idp.get(auth_url, follow_redirects=True)
        action = re.search(r'<form[^>]*action="([^"]+)"', r.text)
        form_url = urljoin(str(r.url), action.group(1).replace("&amp;", "&")) if action else str(r.url)
        r = idp.post(form_url, data={"login": email, "password": password})
        for _ in range(5):  # Dex may hop through an approval step before the callback
            loc = r.headers.get("location", "")
            if CALLBACK in loc:
                return loc
            assert r.is_redirect, f"Dex login didn't redirect (status {r.status_code})"
            r = idp.get(urljoin(str(r.url), loc))
    raise AssertionError("never redirected to the callback")


def start(client, **body):
    r = client.post("/api/auth/oidc/start", json={"preset_id": 0, **body})
    assert r.status_code == 200, r.text
    return r.json()["auth_url"]


def finish(client, callback_url: str):
    u = urlparse(callback_url)
    return client.get(f"{u.path}?{u.query}", follow_redirects=False)


def test_login_methods_are_discoverable(client):
    methods = client.post("/api/auth/methods", json={"preset_id": 0}).json()["methods"]
    assert {(m["path"], m["type"]) for m in methods} >= {("oidc", "oidc"), ("userpass", "userpass")}


def test_full_oidc_login_as_admin(client):
    auth_url = start(client, side="right")
    assert "dex" in auth_url and "redirect_uri=" in auth_url
    r = finish(client, dex_login(auth_url, "alice@example.com"))
    assert r.status_code == 303
    back = parse_qs(urlparse(r.headers["location"]).query)
    assert back["oidc"] == ["ok"] and back["side"] == ["right"]

    conns = client.get("/api/connections").json()
    assert len(conns) == 1
    c = conns[0]
    assert c["id"] == back["conn"][0] and c["auth_method"] == "oidc" and c["status"] == "ok"
    assert "lockstep-admin" in c["policies"]  # alice's identity entity grants admin
    # the minted token works for real calls
    assert client.get(f"/api/connections/{c['id']}/mounts").status_code == 200


def test_oidc_user_without_entity_gets_role_policy(client):
    finish(client, dex_login(start(client), "bob@example.com"))
    c = client.get("/api/connections").json()[0]
    assert "lockstep-readonly" in c["policies"] and "lockstep-admin" not in c["policies"]


def test_state_mismatch_is_rejected(client):
    cb = dex_login(start(client), "alice@example.com")
    forged = re.sub(r"state=[^&]+", "state=forged", cb)
    r = finish(client, forged)
    assert "oidc_error" in r.headers["location"] and "mismatch" in r.headers["location"]
    assert client.get("/api/connections").json() == []


def test_callback_without_pending_login_or_replayed(client):
    cb = dex_login(start(client), "alice@example.com")
    assert "oidc=ok" in finish(client, cb).headers["location"]
    replay = finish(client, cb)  # the pending login is single use
    assert "oidc_error" in replay.headers["location"]
    assert len(client.get("/api/connections").json()) == 1


def test_idp_error_is_reported(client):
    start(client)
    r = client.get(f"{CALLBACK}?error=access_denied&error_description=User+said+no", follow_redirects=False)
    assert "oidc_error" in r.headers["location"] and "User+said+no" in r.headers["location"]


def test_unknown_mount_gives_clear_error(client):
    r = client.post("/api/auth/oidc/start", json={"preset_id": 0, "mount": "nope"})
    assert r.status_code in (400, 403, 404, 502)
