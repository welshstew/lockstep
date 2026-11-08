"""Browser end-to-end tests: Playwright (Chromium) against the running compose stack.

The browser reaches the app as http://localhost:8080 and Dex as http://dex.localhost:5556,
the same URLs a user gets locally, via Chromium host mapping. So the OIDC redirect
round trip works unchanged inside the compose network (and in CI).
"""

from __future__ import annotations

import os
import re
import uuid
from pathlib import Path

import httpx
import pytest
from playwright.sync_api import Page, expect, sync_playwright

BASE = os.environ.get("APP_URL", "http://localhost:8080")
HOST_RULES = os.environ.get("HOST_RULES", "MAP dex.localhost dex, MAP localhost lockstep")
VAULT_A = os.environ.get("VAULT_A_ADDR", "http://vault-a:8200")
VAULT_B = os.environ.get("VAULT_B_ADDR", "http://vault-b:8200")
REPORTS = Path(os.environ.get("REPORTS_DIR", "/reports"))

expect.set_options(timeout=15_000)


@pytest.fixture(scope="session")
def browser():
    with sync_playwright() as pw:
        b = pw.chromium.launch(args=[f"--host-resolver-rules={HOST_RULES}"])
        yield b
        b.close()


@pytest.fixture
def page(browser, request):
    """A fresh browser context per test: its own cookies (session) and local storage."""
    ctx = browser.new_context(viewport={"width": 1440, "height": 900})
    pg = ctx.new_page()
    pg.set_default_timeout(15_000)
    pg.goto(BASE)
    yield pg
    if getattr(request.node, "rep_call", None) is not None and request.node.rep_call.failed:
        (REPORTS / "failures").mkdir(parents=True, exist_ok=True)
        name = re.sub(r"[^A-Za-z0-9_.-]+", "_", request.node.nodeid.split("::")[-1])
        pg.screenshot(path=str(REPORTS / "failures" / f"{name}.png"), full_page=True)
    ctx.close()


@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    rep = outcome.get_result()
    setattr(item, f"rep_{rep.when}", rep)


class RawVault:
    """Root access to a dev Vault for setting up and checking data (never through the UI)."""

    def __init__(self, addr: str, token: str):
        self.c = httpx.Client(base_url=f"{addr}/v1/", headers={"X-Vault-Token": token}, timeout=10)

    def put(self, mount: str, path: str, data: dict) -> int:
        r = self.c.post(f"{mount}/data/{path}", json={"data": data})
        r.raise_for_status()
        return r.json()["data"]["version"]

    def get(self, mount: str, path: str) -> dict | None:
        r = self.c.get(f"{mount}/data/{path}")
        return None if r.status_code == 404 else r.json()["data"]["data"]

    def purge(self, mount: str, prefix: str) -> None:
        r = self.c.request("LIST", f"{mount}/metadata/{prefix}/")
        if r.status_code == 404:
            return
        for k in r.json()["data"]["keys"]:
            if k.endswith("/"):
                self.purge(mount, f"{prefix}/{k.rstrip('/')}")
            else:
                self.c.delete(f"{mount}/metadata/{prefix}/{k}")


@pytest.fixture(scope="session")
def vault_a():
    return RawVault(VAULT_A, "root-a")


@pytest.fixture(scope="session")
def vault_b():
    return RawVault(VAULT_B, "root-b")


@pytest.fixture
def sandbox(vault_a, vault_b):
    """A random prefix in app-config on both Vaults, removed afterwards."""
    prefix = f"e2e-{uuid.uuid4().hex[:8]}"
    yield prefix
    vault_a.purge("app-config", prefix)
    vault_b.purge("app-config", prefix)


# --------------------------------------------------------------------------- UI helpers


def side(page: Page, which: str):
    return page.locator(f"section.side-card.{which}")


def field(card, label: str):
    """A form field by its exact label text (option texts inside other fields don't count)."""
    return card.locator("label.field").filter(
        has=card.page.locator("> span", has_text=re.compile(rf"^{re.escape(label)}"))).first


def sign_in_userpass(page: Page, which: str, username: str, vault: str | None = None) -> None:
    """Sign in through the connect form, as a user would."""
    card = side(page, which)
    if card.get_by_role("combobox").first.input_value() != "__new__" and card.locator(".conn-chip").count():
        card.get_by_role("combobox").first.select_option("__new__")
    if vault:
        sel = field(card, "Vault").locator("select")
        sel.select_option(value=sel.locator("option", has_text=vault).first.get_attribute("value"))
    card.get_by_role("button", name="Username", exact=True).click()
    card.get_by_label("Username").fill(username)
    card.get_by_label("Password").fill("password")
    card.get_by_role("button", name="Connect", exact=True).click()
    expect(card.locator(".conn-chip")).to_contain_text(f"userpass-{username}")


def choose_mount(page: Page, which: str, mount: str, prefix: str = "") -> None:
    card = side(page, which)
    sel = field(card, "KV v2 secret engine").locator("select")
    expect(sel.locator(f"option[value='{mount}']")).to_have_count(1)  # mounts load asynchronously
    sel.select_option(value=mount)
    if prefix:
        card.get_by_placeholder("e.g. payments/").fill(prefix)


def compare(page: Page) -> None:
    page.get_by_role("button", name=re.compile(r"^\s*Compare( again)?$")).click()
    expect(page.locator(".cols-head")).to_be_visible()


def show_everything(page: Page) -> None:
    page.locator(".chip", has_text="Everything").click()


def row(page: Page, path: str):
    return page.locator(".secret").filter(has=page.locator(".secret-path", has_text=re.compile(rf"^{re.escape(path)}$")))


def expand(page: Page, path: str):
    r = row(page, path)
    r.locator(".secret-head").click()
    expect(r.locator(".keys")).to_be_visible()
    return r


def key_row(secret_row, key: str):
    return secret_row.locator(".key-row").filter(has=secret_row.page.locator(".key-name", has_text=re.compile(rf"^{re.escape(key)}")))


def set_reveal(page: Page, on: bool) -> None:
    t = page.locator(".toggle input")
    if t.is_checked() != on:
        page.locator(".toggle").click()
    expect(t).to_be_checked(checked=on)
