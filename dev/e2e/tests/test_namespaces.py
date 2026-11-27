"""Namespaces in the browser: each side signs in to a namespace of Vault B and they're compared.
Needs a Vault B with namespaces: OpenBao (make test-openbao) or Vault Enterprise."""

import re

import httpx
import pytest
from playwright.sync_api import expect

from conftest import VAULT_B, choose_mount, side, sign_in_userpass


def _has_namespaces() -> bool:
    r = httpx.get(f"{VAULT_B}/v1/sys/namespaces/lockstep-no-such-namespace", headers={"X-Vault-Token": "root-b"}, timeout=5)
    return r.status_code in (200, 404) and "enterprise-only" not in r.text


pytestmark = pytest.mark.skipif(not _has_namespaces(), reason="Vault B has no namespaces (run make test-openbao)")


def test_compare_two_namespaces(page):
    page.get_by_role("tab", name="Compare", exact=True).click()
    sign_in_userpass(page, "left", "alice", vault="Vault B", namespace="team-a")
    sign_in_userpass(page, "right", "alice", vault="Vault B", namespace="team-c")
    choose_mount(page, "left", "app-config")
    choose_mount(page, "right", "app-config")
    page.get_by_role("button", name="Collapse the left side").click()
    expect(side(page, "left").locator(".side-summary")).to_contain_text("namespace team-a")
    page.get_by_role("button", name=re.compile(r"^\s*Compare$")).click()
    expect(page.locator(".secret-path", has_text="payments/db")).to_have_count(1)
    expect(page.locator(".secret-path", has_text="service/config")).to_have_count(1)


def test_namespace_picker_moves_a_side_without_signing_in_again(page):
    page.get_by_role("tab", name="Compare", exact=True).click()
    card = side(page, "left")
    if card.get_by_role("combobox").first.input_value() != "__new__" and card.locator(".conn-chip").count():
        card.get_by_role("combobox").first.select_option("__new__")
    sel = card.locator("label.field", has=page.locator("> span", has_text="Vault")).first.locator("select")
    sel.select_option(value=sel.locator("option", has_text="Vault B").first.get_attribute("value"))
    card.get_by_role("button", name="Token", exact=True).click()
    card.get_by_label("Token", exact=True).fill("root-b")
    card.get_by_role("button", name="Connect", exact=True).click()
    picker = card.locator("label.field", has=page.locator("> span", has_text=re.compile("^Namespace$"))).locator("select")
    expect(picker.locator("option", has_text="team-a/")).to_have_count(1)
    picker.select_option(label="↳ team-a/")
    expect(picker.locator("option").first).to_have_text("team-a/")
    expect(card.get_by_role("button", name="Close", exact=True)).to_be_visible()  # same token: closing keeps the sign-in
    choose_mount(page, "left", "app-config")
    expect(picker.locator("option", has_text="team-a/apps/")).to_have_count(1)
    picker.select_option(value=picker.locator("option[value^='up:']").get_attribute("value"))
    expect(picker.locator("option").first).to_have_text("root namespace")
