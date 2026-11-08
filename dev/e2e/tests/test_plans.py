"""Saved sync plans: a read-only user saves a plan, someone with write access applies it."""

import re

import pytest
from playwright.sync_api import expect

from conftest import BASE, choose_mount, compare, expand, key_row, sign_in_userpass


def connect_both(page, user, prefix):
    sign_in_userpass(page, "left", user, vault="Vault A")
    sign_in_userpass(page, "right", user, vault="Vault B")
    choose_mount(page, "left", "app-config", prefix)
    choose_mount(page, "right", "app-config", prefix)


def save_plan_as_bob(page, sandbox, tmp_path):
    """bob (read-only) stages two copies and saves them as a plan file."""
    connect_both(page, "bob", sandbox)
    compare(page)
    for path in ("one", "two"):
        key_row(expand(page, path), "k").get_by_role("button", name="Copy k from left to right").click()
    page.get_by_role("button", name="Review & apply…").click()
    dialog = page.locator("dialog.review")
    expect(dialog.locator(".plan .badge", has_text="No permission")).to_have_count(2)
    expect(dialog.get_by_role("button", name="Apply")).to_be_disabled()

    dialog.get_by_label("Plan note").fill("Promote k to Vault B")
    with page.expect_download() as dl:
        dialog.get_by_role("button", name="Save as plan").click()
    path = tmp_path / dl.value.suggested_filename
    dl.value.save_as(path)
    assert re.fullmatch(r"lockstep-plan-\d{4}-\d{2}-\d{2}-[0-9a-f]{8}\.json", path.name)
    expect(dialog.get_by_role("status")).to_contain_text("Plan saved as")
    assert "from-A" not in path.read_text()  # no values in the file
    return path


def open_plan_as_alice(browser, plan_file, sandbox):
    """A different person, in their own browser session, opens the plan."""
    ctx = browser.new_context(viewport={"width": 1440, "height": 900})
    page = ctx.new_page()
    page.set_default_timeout(15_000)
    page.goto(BASE)
    connect_both(page, "alice", sandbox)
    page.get_by_role("tab", name="Sync plans").click()
    page.get_by_label("Plan file").set_input_files(plan_file)
    expect(page.locator(".plan-note")).to_have_text("Promote k to Vault B")
    expect(page.locator(".plan-side.left")).to_contain_text("Planned by userpass-bob")
    expect(page.locator(".plan-table tbody tr")).to_have_count(2)
    return ctx, page


@pytest.fixture
def data(sandbox, vault_a, vault_b):
    vault_a.put("app-config", f"{sandbox}/one", {"k": "from-A", "same": "x"})
    vault_b.put("app-config", f"{sandbox}/one", {"k": "from-B", "same": "x", "only_b": "keep"})
    vault_a.put("app-config", f"{sandbox}/two", {"k": "A2"})
    return sandbox


def test_plan_saved_by_reader_applied_by_writer(page, browser, data, vault_b, tmp_path):
    plan_file = save_plan_as_bob(page, data, tmp_path)
    ctx, alice = open_plan_as_alice(browser, plan_file, data)
    try:
        alice.get_by_role("button", name="Check plan").click()
        expect(alice.get_by_role("status")).to_contain_text("exactly as they were")
        apply = alice.get_by_role("button", name="Apply plan")
        expect(apply).to_be_disabled()  # confirmation required
        alice.locator(".plan-actions .confirm input").check()
        apply.click()
        expect(alice.get_by_role("status")).to_contain_text("2 of 2 secret(s) written")
        expect(alice.locator(".plan-table .badge", has_text=re.compile(r"^Written v\d+$"))).to_have_count(2)
    finally:
        ctx.close()
    assert vault_b.get("app-config", f"{data}/one") == {"k": "from-A", "same": "x", "only_b": "keep"}
    assert vault_b.get("app-config", f"{data}/two") == {"k": "A2"}


def test_changed_target_means_plan_must_be_made_again(page, browser, data, vault_b, tmp_path):
    plan_file = save_plan_as_bob(page, data, tmp_path)
    vault_b.put("app-config", f"{data}/one", {"k": "edited meanwhile"})
    ctx, alice = open_plan_as_alice(browser, plan_file, data)
    try:
        alice.get_by_role("button", name="Check plan").click()
        expect(alice.get_by_role("status")).to_contain_text("This plan can't be applied")
        expect(alice.get_by_role("status")).to_contain_text("created again")
        expect(alice.locator(".plan-table .badge", has_text="Changed since the plan")).to_have_count(1)
        expect(alice.get_by_role("button", name="Apply plan")).to_be_disabled()
    finally:
        ctx.close()
    assert vault_b.get("app-config", f"{data}/two") is None  # nothing written, not even the unchanged one
