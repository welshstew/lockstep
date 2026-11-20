"""Destroying secrets (every version and the metadata), one at a time or all on one side."""

from playwright.sync_api import expect

from conftest import compare, expand, row
from test_editing import connect_both


def metadata_status(vault, path):
    return vault.c.get(f"app-config/metadata/{path}").status_code


def test_destroy_one_secret_needs_its_path_typed(page, sandbox, vault_a, vault_b):
    vault_a.put("app-config", f"{sandbox}/svc", {"pw": "A"})
    vault_b.put("app-config", f"{sandbox}/svc", {"pw": "B1"})
    vault_b.put("app-config", f"{sandbox}/svc", {"pw": "B2"})
    connect_both(page, sandbox)
    compare(page)
    r = expand(page, "svc")
    r.get_by_role("button", name="Destroy on right…").click()

    dialog = page.locator("dialog.destroy-dialog")
    expect(dialog).to_contain_text("can’t be undone")
    expect(dialog.locator(".destroy-list li")).to_have_count(1)
    go = dialog.get_by_role("button", name="Destroy permanently")
    expect(go).to_be_disabled()
    box = dialog.get_by_label("Confirmation phrase")
    box.fill("sv")
    expect(go).to_be_disabled()
    box.fill("svc")
    expect(go).to_be_enabled()
    go.click()

    expect(dialog.locator(".badge", has_text="Destroyed")).to_have_count(1)
    expect(dialog).to_contain_text("2 versions and the metadata")
    assert metadata_status(vault_b, f"{sandbox}/svc") == 404
    assert vault_a.get("app-config", f"{sandbox}/svc") == {"pw": "A"}  # the other side is untouched
    dialog.get_by_role("button", name="Close").first.click()
    # The comparison runs again: now only the left has it
    expect(row(page, "svc")).to_contain_text("Left only")


def test_cancel_destroys_nothing(page, sandbox, vault_a, vault_b):
    vault_a.put("app-config", f"{sandbox}/svc", {"pw": "A"})
    connect_both(page, sandbox)
    compare(page)
    expand(page, "svc").get_by_role("button", name="Destroy on left…").click()
    dialog = page.locator("dialog.destroy-dialog")
    dialog.get_by_role("button", name="Cancel").click()
    expect(dialog).to_have_count(0)
    assert metadata_status(vault_a, f"{sandbox}/svc") == 200


def test_destroy_all_on_left_acts_on_what_the_filter_shows(page, sandbox, vault_a, vault_b):
    for name in ("one", "two"):
        vault_a.put("app-config", f"{sandbox}/svc/{name}", {"k": name})
    vault_a.put("app-config", f"{sandbox}/keep/me", {"k": "x"})
    vault_b.put("app-config", f"{sandbox}/svc/one", {"k": "other"})
    connect_both(page, sandbox)
    compare(page)
    page.get_by_placeholder("Filter by path or key…").fill("svc/")
    tools = page.locator(".results-tools")
    expect(tools.get_by_role("button", name="Destroy all on right (1)…")).to_be_visible()
    tools.get_by_role("button", name="Destroy all on left (2)…").click()

    dialog = page.locator("dialog.destroy-dialog")
    expect(dialog.locator(".destroy-list li")).to_have_count(2)
    go = dialog.get_by_role("button", name="Destroy 2 secrets permanently")
    dialog.get_by_label("Confirmation phrase").fill("destroy 2 secret")
    expect(go).to_be_disabled()
    dialog.get_by_label("Confirmation phrase").fill("destroy 2 secrets")
    go.click()
    expect(dialog.locator(".badge", has_text="Destroyed")).to_have_count(2)
    assert metadata_status(vault_a, f"{sandbox}/svc/one") == 404
    assert metadata_status(vault_a, f"{sandbox}/svc/two") == 404
    assert metadata_status(vault_a, f"{sandbox}/keep/me") == 200  # not matched by the filter
    assert vault_b.get("app-config", f"{sandbox}/svc/one") == {"k": "other"}


def test_bob_cannot_destroy(page, sandbox, vault_a, vault_b):
    vault_b.put("app-config", f"{sandbox}/svc", {"pw": "B"})
    connect_both(page, sandbox, user="bob")
    compare(page)
    expand(page, "svc").get_by_role("button", name="Destroy on right…").click()
    dialog = page.locator("dialog.destroy-dialog")
    dialog.get_by_label("Confirmation phrase").fill("svc")
    dialog.get_by_role("button", name="Destroy permanently").click()
    expect(dialog.locator(".badge", has_text="Denied: not destroyed")).to_have_count(1)
    assert metadata_status(vault_b, f"{sandbox}/svc") == 200
