"""Comparison profiles through the UI: a shared profile with mappings and ignored keys,
a copy that follows the mapping, and creating a personal profile in the editor."""

import re

from playwright.sync_api import expect

from conftest import compare, expand, key_row, row, side, sign_in_userpass

SHARED = "Prod ↔ staging services"


def connect_both(page):
    sign_in_userpass(page, "left", "alice", vault="Vault A")
    sign_in_userpass(page, "right", "alice", vault="Vault B")


def mapped_row(page, left_path):
    return page.locator(".secret").filter(has=page.locator(".map-l", has_text=re.compile(rf"^{re.escape(left_path)}$")))


def test_shared_profile_maps_ignores_and_copies(page, vault_b):
    connect_both(page)
    bar = page.locator("section.profile-bar")
    bar.get_by_role("combobox").select_option(label=SHARED)
    expect(bar).to_contain_text("1 mapping")
    # the profile's mounts were applied to both sides
    for which in ("left", "right"):
        expect(side(page, which).locator("label.field", has=page.locator("> span", has_text="KV v2 secret engine"))
               .locator("select")).to_have_value("app-config")
    compare(page)
    expect(page.locator(".profile-effect")).to_contain_text(re.compile(r"\d+ pairs? matched by a mapping"))

    page.locator(".chip", has_text="Everything").click()
    db = mapped_row(page, "services/billing/prod/db")
    expect(db.locator(".map-r")).to_have_text("services/billing/staging/db")
    expect(db.locator(".badge").last).to_have_text("Equal")  # host differs, but it's ignored
    expect(db.locator(".secret-head .badge.ignored")).to_have_text("1 ignored")
    expect(row(page, "legacy/old-service")).to_have_count(0)  # ignored path

    search = mapped_row(page, "services/search/prod/config")
    expect(search.locator(".badge").last).to_have_text("Left only")
    search.locator(".secret-head").click()
    search.get_by_role("button", name="all keys to right →").click()
    page.get_by_role("button", name="Review & apply…").click()
    dialog = page.locator("dialog.review")
    expect(dialog.locator(".plan-head")).to_contain_text("Vault B · app-config/services/search/staging/config")
    dialog.locator(".confirm input").check()
    dialog.get_by_role("button", name="Apply").click()
    expect(dialog.get_by_role("heading", name="Changes applied")).to_be_visible()
    expect(dialog.locator(".plan .badge", has_text=re.compile(r"^Written$"))).to_have_count(1)
    try:
        assert vault_b.get("app-config", "services/search/staging/config") == {"replicas": "3", "index": "products"}
        assert vault_b.get("app-config", "services/search/prod/config") is None
    finally:
        vault_b.c.delete("app-config/metadata/services/search/staging/config")


def test_create_personal_profile_in_editor(page):
    connect_both(page)
    for which in ("left", "right"):
        sel = side(page, which).locator("label.field", has=page.locator("> span", has_text="KV v2 secret engine")).locator("select")
        expect(sel.locator("option[value='app-config']")).to_have_count(1)
        sel.select_option("app-config")
    bar = page.locator("section.profile-bar")
    bar.get_by_role("button", name="＋ New").click()
    ed = page.locator("dialog.profile-editor")
    ed.get_by_label("Name").fill("Billing only")
    ed.get_by_role("button", name="＋ Add mapping").click()
    ed.get_by_label("Mapping 1 left pattern").fill("services/billing/prod/*")
    ed.get_by_label("Mapping 1 right pattern").fill("services/billing/staging/**")  # wrong wildcard
    ed.get_by_role("button", name="Save profile").click()
    expect(ed.locator(".notice.error")).to_contain_text("same wildcards")
    ed.get_by_label("Mapping 1 right pattern").fill("services/billing/staging/*")
    ed.get_by_role("button", name="＋ Add ignored key").click()
    ed.get_by_label("Ignored key 1", exact=True).fill("host")
    ed.get_by_role("button", name="Save profile").click()
    expect(ed).to_be_hidden()

    expect(bar.get_by_role("combobox")).to_have_value("personal:Billing only")
    compare(page)
    page.locator(".chip", has_text="Everything").click()
    expect(mapped_row(page, "services/billing/prod/db").locator(".badge").last).to_have_text("Equal")
    # search isn't covered by this profile's mapping: its paths stay apart
    expect(row(page, "services/search/prod/config").locator(".badge").last).to_have_text("Left only")

    bar.get_by_role("button", name="Delete").click()
    expect(bar.get_by_role("combobox")).to_have_value("")


def test_cancelled_review_does_not_come_back(page):
    """Regression: cancelling a review, then immediately changing the profile, used to leave
    the app in 'reviewing' state, so the next comparison re-opened an empty review."""
    connect_both(page)
    for which in ("left", "right"):
        sel = side(page, which).locator("label.field", has=page.locator("> span", has_text="KV v2 secret engine")).locator("select")
        expect(sel.locator("option[value='app-config']")).to_have_count(1)
        sel.select_option("app-config")
    compare(page)
    r = expand(page, "payments/db")
    key_row(r, "password").get_by_role("button", name="Copy password from left to right").click()
    page.get_by_role("button", name="Review & apply…").click()
    page.locator("dialog.review .plan").first.wait_for()
    page.locator("dialog.review").get_by_role("button", name="Cancel").click()
    page.locator("section.profile-bar").get_by_role("combobox").select_option(label=SHARED)  # no pause
    compare(page)
    page.wait_for_timeout(500)
    expect(page.locator("dialog.review")).to_have_count(0)
