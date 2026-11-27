"""Undo: after applying a copy, make an undo plan and put the old version back."""

import json
import re

from playwright.sync_api import expect

from conftest import choose_mount, compare, expand, key_row, sign_in_userpass


def test_copy_then_undo(page, sandbox, vault_a, vault_b, tmp_path):
    vault_a.put("app-config", f"{sandbox}/db", {"password": "new"})
    vault_b.put("app-config", f"{sandbox}/db", {"password": "old", "only_b": "x"})
    sign_in_userpass(page, "left", "alice", vault="Vault A")
    sign_in_userpass(page, "right", "alice", vault="Vault B")
    choose_mount(page, "left", "app-config", sandbox)
    choose_mount(page, "right", "app-config", sandbox)
    page.get_by_role("tab", name="Compare", exact=True).click()
    compare(page)
    key_row(expand(page, "db"), "password").get_by_role("button", name="Copy password from left to right").click()
    page.get_by_role("button", name="Review & apply…").click()
    dialog = page.locator("dialog.review")
    dialog.locator("label.confirm input").check()
    dialog.get_by_role("button", name="Apply").click()
    expect(dialog.locator(".plan .badge", has_text=re.compile(r"^Written$"))).to_have_count(1)
    assert vault_b.get("app-config", f"{sandbox}/db")["password"] == "new"

    with page.expect_download() as dl:
        dialog.get_by_role("button", name="Make an undo plan").click()
    path = tmp_path / dl.value.suggested_filename
    dl.value.save_as(path)
    assert path.name.startswith("lockstep-undo-") and "old" not in json.dumps(json.loads(path.read_text())["entries"])
    expect(dialog.get_by_role("status").first).to_contain_text("Undo plan saved as")
    dialog.get_by_role("button", name="Done, compare again").click()

    page.get_by_role("tab", name="Sync plans").click()
    page.get_by_label("Plan file").set_input_files(path)
    expect(page.locator(".plan-table")).to_contain_text("Put back v1")
    page.get_by_role("button", name="Check undo plan").click()
    expect(page.locator(".plan-table .badge", has_text="Can be undone")).to_have_count(1)
    page.get_by_label(re.compile("Put back 1 secret")).check()
    page.get_by_role("button", name="Apply undo plan").click()
    expect(page.get_by_role("status").last).to_contain_text("Undone: 1 of 1")
    assert vault_b.get("app-config", f"{sandbox}/db") == {"password": "old", "only_b": "x"}
