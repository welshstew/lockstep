"""Four-eyes: on a Vault whose secrets change only through approved plans, alice saves a plan,
bob approves it, and alice applies it."""

import re

from playwright.sync_api import expect

from conftest import BASE, choose_mount, compare, expand, key_row, sign_in_userpass

TARGET = "Vault B (with approval)"


def connect(page, user, prefix):
    sign_in_userpass(page, "left", user, vault="Vault A")
    sign_in_userpass(page, "right", user, vault=TARGET)
    choose_mount(page, "left", "app-config", prefix)
    choose_mount(page, "right", "app-config", prefix)


def open_plan(browser, user, path, prefix):
    ctx = browser.new_context(viewport={"width": 1440, "height": 900})
    page = ctx.new_page()
    page.set_default_timeout(15_000)
    page.goto(BASE)
    connect(page, user, prefix)
    page.get_by_role("tab", name="Sync plans").click()
    page.get_by_label("Plan file").set_input_files(path)
    return ctx, page


def test_plan_needs_someone_elses_approval(page, browser, sandbox, vault_a, vault_b, tmp_path):
    vault_a.put("app-config", f"{sandbox}/db", {"k": "new"})
    vault_b.put("app-config", f"{sandbox}/db", {"k": "old"})
    connect(page, "alice", sandbox)
    page.get_by_role("tab", name="Compare", exact=True).click()
    compare(page)
    key_row(expand(page, "db"), "k").get_by_role("button", name="Copy k from left to right").click()
    page.get_by_role("button", name="Review & apply…").click()
    dialog = page.locator("dialog.review")
    expect(dialog).to_contain_text("only through approved plans")
    expect(dialog.get_by_role("button", name="Apply")).to_be_disabled()
    with page.expect_download() as dl:
        dialog.get_by_role("button", name="Save as plan").click()
    plan_file = tmp_path / dl.value.suggested_filename
    dl.value.save_as(plan_file)

    # bob checks and approves (he can't write it himself; he doesn't need to)
    ctx, bob = open_plan(browser, "bob", plan_file, sandbox)
    try:
        bob.get_by_role("button", name="Check plan").click()
        expect(bob.locator(".plan-approvals")).to_contain_text("Not approved yet")
        with bob.expect_download() as dl:
            bob.get_by_role("button", name="Approve").click()
        approved = tmp_path / dl.value.suggested_filename
        dl.value.save_as(approved)
        assert approved.name.endswith("-approved.json")
        expect(bob.locator(".plan-approvals")).to_contain_text("Approved by userpass-bob")
    finally:
        ctx.close()

    # alice can't approve her own plan; with bob's approval she applies it
    ctx, alice = open_plan(browser, "alice", approved, sandbox)
    try:
        expect(alice.locator(".plan-meta")).to_contain_text("Approved by userpass-bob")
        alice.get_by_role("button", name="Check plan").click()
        expect(alice.locator(".plan-approvals")).to_contain_text("Approved by userpass-bob")
        alice.locator(".plan-actions .confirm input").check()
        alice.get_by_role("button", name="Apply plan").click()
        expect(alice.locator(".notice", has_text=re.compile("1 of 1 secret"))).to_be_visible()
        with alice.expect_download() as dl:
            alice.get_by_role("button", name="Make an undo plan").click()
        undo = tmp_path / dl.value.suggested_filename
        dl.value.save_as(undo)
    finally:
        ctx.close()
    assert vault_b.get("app-config", f"{sandbox}/db") == {"k": "new"}

    # The undo plan needs someone else's approval too
    ctx, alice = open_plan(browser, "alice", undo, sandbox)
    try:
        alice.get_by_role("button", name="Check undo plan").click()
        expect(alice.locator(".plan-approvals")).to_contain_text("Not approved yet")
        alice.get_by_label(re.compile("Put back 1 secret")).check()
        expect(alice.get_by_role("button", name="Apply undo plan")).to_be_disabled()
    finally:
        ctx.close()
    ctx, bob = open_plan(browser, "bob", undo, sandbox)
    try:
        bob.get_by_role("button", name="Check undo plan").click()
        with bob.expect_download() as dl:
            bob.get_by_role("button", name="Approve").click()
        undo_ok = tmp_path / dl.value.suggested_filename
        dl.value.save_as(undo_ok)
        expect(bob.locator(".plan-approvals")).to_contain_text("Approved by userpass-bob")
    finally:
        ctx.close()
    ctx, alice = open_plan(browser, "alice", undo_ok, sandbox)
    try:
        alice.get_by_role("button", name="Check undo plan").click()
        alice.get_by_label(re.compile("Put back 1 secret")).check()
        alice.get_by_role("button", name="Apply undo plan").click()
        expect(alice.locator(".notice", has_text="Undone: 1 of 1")).to_be_visible()
    finally:
        ctx.close()
    assert vault_b.get("app-config", f"{sandbox}/db") == {"k": "old"}
