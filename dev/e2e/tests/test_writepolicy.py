"""A preset that's read-only on this Lockstep server: compared and browsed, never written."""

import re

from playwright.sync_api import expect

from conftest import choose_mount, compare, expand, sign_in_userpass


def test_read_only_preset_hides_writes(page, sandbox, vault_a, vault_b):
    vault_a.put("app-config", f"{sandbox}/db", {"user": "svc", "password": "a"})
    vault_b.put("app-config", f"{sandbox}/db", {"user": "svc", "password": "b"})
    page.get_by_role("tab", name="Compare", exact=True).click()
    sign_in_userpass(page, "left", "alice", vault="Vault A")
    sign_in_userpass(page, "right", "alice", vault="Vault B (read-only)")
    choose_mount(page, "left", "app-config", sandbox)
    choose_mount(page, "right", "app-config", sandbox)
    compare(page)
    r = expand(page, "db")
    expect(r.get_by_role("button", name="Copy password from right to left")).to_be_visible()
    expect(r.get_by_role("button", name="Copy password from left to right")).to_have_count(0)  # never into it

    page.get_by_role("tab", name="Browse", exact=True).click()
    page.get_by_role("group", name="Which side to browse").get_by_role("button", name=re.compile("read-only")).click()
    expect(page.locator(".badge", has_text="read-only here")).to_be_visible()
