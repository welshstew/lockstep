"""The environment matrix in the browser: the left side as the baseline, several environments, odd one out first."""

from playwright.sync_api import expect

from conftest import choose_mount, side, sign_in_userpass


def test_matrix_compares_several_environments(page, sandbox, vault_a, vault_b):
    vault_a.put("app-config", f"{sandbox}/prod/db", {"user": "svc", "password": "prod-pw"})
    vault_a.put("app-config", f"{sandbox}/prod/flags", {"checkout": "off"})
    vault_b.put("app-config", f"{sandbox}/stg/db", {"user": "svc", "password": "stg-pw"})
    vault_b.put("app-config", f"{sandbox}/stg/flags", {"checkout": "off"})
    vault_a.put("app-config", f"{sandbox}/dev/db", {"user": "svc", "password": "prod-pw"})
    vault_a.put("app-config", f"{sandbox}/dev/flags", {"checkout": "on"})

    page.get_by_role("tab", name="Compare", exact=True).click()
    sign_in_userpass(page, "left", "alice", vault="Vault A")
    choose_mount(page, "left", "app-config", f"{sandbox}/prod")
    sign_in_userpass(page, "right", "alice", vault="Vault B")
    choose_mount(page, "right", "app-config", f"{sandbox}/stg")

    page.get_by_role("tab", name="Matrix", exact=True).click()
    setup = page.get_by_label("Environment matrix setup")
    setup.get_by_label("Baseline name").fill("prod")
    # The right side is the first environment
    expect(setup.get_by_label("Environment 1 path prefix")).to_have_value(f"{sandbox}/stg")
    setup.get_by_label("Environment 1 name").fill("staging")
    setup.get_by_role("button", name="Add environment").click()  # starts on the baseline's Vault and mount
    setup.get_by_label("Environment 2 name").fill("dev")
    setup.get_by_label("Environment 2 path prefix").fill(f"{sandbox}/dev")
    setup.get_by_role("button", name="Compare all").click()

    grid = page.get_by_label("Environment matrix", exact=True)
    expect(grid.locator(".matrix-summary")).to_contain_text("2 rows differ from prod, 2 in only one environment")
    rows = grid.locator("tbody tr")
    expect(rows).to_have_count(2)
    expect(rows.nth(0)).to_contain_text("db")
    expect(rows.nth(0).locator("td.mcell")).to_have_class(["mcell different", "mcell equal"])
    expect(rows.nth(1)).to_contain_text("checkout")
    expect(rows.nth(1).locator("td.mcell")).to_have_class(["mcell equal", "mcell different"])
    expect(grid).not_to_contain_text("prod-pw")

    # One pair, side by side
    grid.get_by_role("button", name="Open in Compare").first.click()
    expect(page.get_by_role("tab", name="Compare", exact=True)).to_have_attribute("aria-selected", "true")
    expect(side(page, "right").get_by_placeholder("e.g. payments/")).to_have_value(f"{sandbox}/stg")
