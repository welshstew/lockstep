"""Certificate expiry dashboard through the UI."""

import re

from playwright.sync_api import expect

from conftest import choose_mount, sign_in_userpass


def test_expiry_dashboard(page):
    sign_in_userpass(page, "left", "alice", vault="Vault A")
    sign_in_userpass(page, "right", "alice", vault="Vault B")
    choose_mount(page, "left", "certs")
    choose_mount(page, "right", "certs")
    page.get_by_role("tab", name="Certificate expiry").click()
    page.get_by_role("button", name="Scan for certificates").click()

    table = page.locator(".expiry-table")
    expect(table.locator("tbody tr").first).to_be_visible()
    expired_tile = page.locator(".tile", has_text="Expired or not yet valid")
    expect(expired_tile.locator(".tile-n")).not_to_have_text("0")
    total = int(page.locator(".tile", has_text="All certificates").locator(".tile-n").inner_text())
    buckets = sum(int(t.locator(".tile-n").inner_text()) for t in page.locator(".tile").all()[:4])
    assert buckets == total  # every certificate is in exactly one bucket
    assert total >= 20

    # keystores opened with their sibling password key
    expect(table).to_contain_text("opened with “keystore.password”")
    expect(page.locator("details.locked summary")).to_contain_text("not fully checked")

    expired_tile.click()
    rows = table.locator("tbody tr")
    expect(rows.filter(has_text="old.example.com").first).to_be_visible()
    for status in rows.locator("td:first-child .badge").all_inner_texts():
        assert status in ("Expired", "Not yet valid")

    page.locator(".tile", has_text="All certificates").click()
    page.get_by_label("Hide CA certificates").check()
    expect(table).not_to_contain_text("Example Root CA")
    page.get_by_placeholder("Filter by name, path or key…").fill("jks-app")
    expect(rows).to_have_count(3)  # the JKS in both Vaults, plus Vault A's JCEKS built from the same key
    rows.first.get_by_role("button", name="Inspect").click()
    insp = page.locator("dialog.inspector")
    expect(insp.locator(".node-label").first).to_contain_text(re.compile("Java keystore"))
    assert page.locator("body").inner_text().count("changeit") == 0  # no values on the page
