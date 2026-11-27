"""KV v1 in the browser: offered in the side picker, compared, copied from into KV v2, never written."""

import uuid

import httpx
import pytest
from playwright.sync_api import expect

from conftest import VAULT_A, choose_mount, compare, expand, side, sign_in_userpass


@pytest.fixture
def kv1_mount(sandbox):
    name = f"kv1-e2e-{uuid.uuid4().hex[:6]}"
    root = httpx.Client(base_url=f"{VAULT_A}/v1/", headers={"X-Vault-Token": "root-a"}, timeout=10)
    root.post(f"sys/mounts/{name}", json={"type": "kv", "options": {"version": "1"}}).raise_for_status()
    root.post(f"{name}/{sandbox}/db", json={"user": "svc", "password": "p1"}).raise_for_status()
    root.post(f"{name}/{sandbox}/only-v1", json={"k": "v"}).raise_for_status()
    yield name
    root.delete(f"sys/mounts/{name}")


def test_kv1_is_compared_and_copied_from_but_never_to(page, sandbox, kv1_mount, vault_b):
    vault_b.put("app-config", f"{sandbox}/db", {"user": "svc", "password": "p2"})
    page.get_by_role("tab", name="Compare", exact=True).click()
    sign_in_userpass(page, "left", "alice", vault="Vault A")
    sign_in_userpass(page, "right", "alice", vault="Vault B")
    sel = side(page, "left").locator("label.field", has=page.locator("> span", has_text="KV secret engine")).locator("select")
    expect(sel.locator(f"option[value='{kv1_mount}']")).to_contain_text("KV v1, read-only")
    choose_mount(page, "left", kv1_mount, sandbox)
    expect(side(page, "left")).to_contain_text("Lockstep never writes it")
    choose_mount(page, "right", "app-config", sandbox)
    compare(page)

    r = expand(page, "db")
    expect(r.get_by_role("button", name="Copy password from left to right")).to_be_visible()
    expect(r.get_by_role("button", name="Copy password from right to left")).to_have_count(0)  # never into KV v1

    # Other tabs leave the KV v1 side out and say why
    page.get_by_role("tab", name="Browse", exact=True).click()
    expect(page.locator(".kv1-note")).to_contain_text("this tab needs a KV v2 mount")
