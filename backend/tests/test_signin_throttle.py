"""Sign-in throttling: failed sign-ins per client address and per user on a Vault."""

import logging

import pytest
from fastapi.testclient import TestClient

from lockstep.config import get_settings
from lockstep.ratelimit import FailureThrottle


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def test_failures_in_the_window_lock_the_key_until_the_oldest_expires():
    clock = Clock()
    th = FailureThrottle(3, 300, clock=clock)
    for _ in range(2):
        th.failed("client a")
        clock.t += 10
    assert th.wait("client a") == 0
    th.failed("client a")
    assert th.wait("client a") == pytest.approx(280)  # the first failure was 20 s ago
    assert th.wait("client b") == 0 and th.wait("client b", "client a") == pytest.approx(280)
    clock.t += 281
    assert th.wait("client a") == 0  # the oldest left the window


def test_success_clears_only_that_key_and_zero_turns_it_off():
    th = FailureThrottle(2, 300, clock=Clock())
    th.failed("client a", "user alice")
    th.failed("client a", "user alice")
    th.succeeded("user alice")
    assert th.wait("user alice") == 0 and th.wait("client a") > 0
    off = FailureThrottle(0, 300)
    for _ in range(50):
        off.failed("client a")
    assert off.wait("client a") == 0


def test_keys_are_bounded():
    th = FailureThrottle(1, 300, max_keys=3, clock=Clock())
    for i in range(10):
        th.failed(f"client {i}")
    assert len(th._fails) == 3 and th.wait("client 9") > 0 and th.wait("client 0") == 0


@pytest.fixture
def app_with(monkeypatch):
    def make(client=("testclient", 50000), **env):
        for k, v in env.items():
            monkeypatch.setenv(f"LOCKSTEP_{k.upper()}", v)
        get_settings.cache_clear()
        from lockstep.main import create_app
        return TestClient(create_app(), headers={"X-Requested-With": "lockstep"}, client=client)

    yield make
    get_settings.cache_clear()


def sign_in(c, user, password):
    return c.post("/api/connections", json={"preset_id": 0, "auth": {"method": "userpass", "username": user,
                                                                     "password": password}})


@pytest.fixture
def users(vaults):
    """Throwaway userpass users on Vault A, so Vault's own lockout (5 failures) never locks the
    seeded ones. Each test stays under Vault's limit for any one user."""
    import uuid

    import httpx
    v = httpx.Client(base_url=f"{vaults[0]}/v1/", headers={"X-Vault-Token": "root-a"})
    made = []

    def make() -> str:
        name = f"throttle-{uuid.uuid4().hex[:8]}"
        v.post(f"auth/userpass/users/{name}", json={"password": "right-pw"}).raise_for_status()
        made.append(name)
        return name

    yield make
    for n in made:
        v.delete(f"auth/userpass/users/{n}")


def test_too_many_wrong_passwords_answer_429(app_with, users, caplog):
    u, other = users(), users()
    c = app_with(signin_max_failures="3")
    for _ in range(3):
        assert sign_in(c, u, "wrong-pw").status_code == 401
    with caplog.at_level(logging.WARNING, logger="lockstep.auth"):
        r = sign_in(c, u, "right-pw")  # even the right password waits
    assert r.status_code == 429 and int(r.headers["retry-after"]) > 0 and "Too many failed sign-ins" in r.text
    assert any("sign-in refused" in m and "client testclient" in m for m in caplog.messages)
    assert "wrong-pw" not in caplog.text  # passwords never logged
    assert sign_in(c, other, "right-pw").status_code == 429  # the same address, another user
    assert c.post("/api/auth/oidc/start", json={"preset_id": 0, "mount": "oidc"}).status_code == 429


def test_a_user_is_throttled_from_any_address(app_with, users):
    u, other = users(), users()
    a = app_with(client=("10.0.0.1", 1), signin_max_failures="3")
    for _ in range(3):
        assert sign_in(a, u.upper(), "wrong-pw").status_code == 401
    b = app_with(client=("10.0.0.2", 1), signin_max_failures="3")
    assert sign_in(b, u, "right-pw").status_code == 429  # the user, case-insensitive
    assert sign_in(b, other, "right-pw").status_code == 201  # that address hasn't failed


def test_success_resets_the_user(app_with, users):
    u = users()
    c = app_with(signin_max_failures="3")
    for _ in range(2):
        assert sign_in(c, u, "wrong-pw").status_code == 401
    assert sign_in(c, u, "right-pw").status_code == 201
    other = app_with(client=("10.0.0.9", 1), signin_max_failures="3")
    assert sign_in(other, u, "wrong-pw").status_code == 401
    # 3 failures for the user in all, but the success cleared the first 2
    assert sign_in(other, u, "right-pw").status_code == 201
