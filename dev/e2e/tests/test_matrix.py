"""The environment matrix in the browser: a baseline, several environments, odd one out first."""

import json
import re

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
    # No left/right cards here: the baseline starts as the left side's, the right side is the first environment
    expect(page.locator("section.side-card")).to_have_count(0)
    expect(setup.get_by_label("Baseline path prefix")).to_have_value(f"{sandbox}/prod")
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


def test_matrix_from_an_export_with_accepted_drift(page, sandbox, vault_a, vault_b, tmp_path):
    """The baseline is an export file; an environment's accepted drift (base.json) marks known drift."""
    vault_a.put("app-config", f"{sandbox}/prod/db", {"user": "svc", "password": "prod-pw"})
    vault_a.put("app-config", f"{sandbox}/prod/flags", {"checkout": "off"})
    vault_b.put("app-config", f"{sandbox}/stg/db", {"user": "svc", "password": "stg-pw"})
    vault_b.put("app-config", f"{sandbox}/stg/flags", {"checkout": "on"})
    sign_in_userpass(page, "left", "alice", vault="Vault A")
    choose_mount(page, "left", "app-config", f"{sandbox}/prod")
    sign_in_userpass(page, "right", "alice", vault="Vault B")
    choose_mount(page, "right", "app-config", f"{sandbox}/stg")

    # A plain export of prod (Vault A allows one), opened as the left side
    page.get_by_role("tab", name="Export & import").click()
    exp = page.locator("section[aria-label=Export]")
    exp.get_by_role("radio", name=re.compile("Nothing \\(plain text\\)")).check()
    with page.expect_download() as dl:
        exp.get_by_role("button", name="Export and download").click()
    path = tmp_path / dl.value.suggested_filename
    dl.value.save_as(path)
    left = side(page, "left")
    left.get_by_role("button", name="Export file").click()
    left.get_by_label("Export file").set_input_files(str(path))
    expect(left.locator(".file-chip")).to_be_visible()

    # staging's password is accepted drift; its flag isn't
    drift = tmp_path / "staging.base.json"
    drift.write_text(json.dumps({"lockstep_baseline": 1, "left": {"mount": "app-config", "prefix": f"{sandbox}/prod"},
                                 "right": {"mount": "app-config", "prefix": f"{sandbox}/stg"},
                                 "drift": [{"path": "db", "key": "password", "status": "different"}]}))
    page.get_by_role("tab", name="Matrix", exact=True).click()
    setup = page.get_by_label("Environment matrix setup")
    expect(setup).to_contain_text("(export file)")
    setup.get_by_label("Baseline name").fill("prod")
    setup.get_by_label("Environment 1 name").fill("staging")
    setup.get_by_label("Environment 1 accepted drift").set_input_files(str(drift))
    expect(setup.locator(".accepted-file")).to_contain_text("staging.base.json")
    setup.get_by_role("button", name="Compare all").click()

    grid = page.get_by_label("Environment matrix", exact=True)
    expect(grid.locator(".matrix-summary")).to_contain_text("1 row differs from prod")
    expect(grid.locator(".matrix-summary")).to_contain_text("1 only accepted drift")
    rows = grid.locator("tbody tr")
    expect(rows).to_have_count(2)
    expect(rows.nth(0)).to_contain_text("checkout")
    expect(rows.nth(1)).to_contain_text("password")
    expect(rows.nth(1).locator("td.mcell")).to_have_class("mcell different accepted")
    expect(grid.locator("thead")).to_contain_text("accepted: staging.base.json")
    expect(grid).not_to_contain_text("prod-pw")

    bad = tmp_path / "bad.json"
    bad.write_text("{}")
    setup.get_by_role("button", name="Remove accepted drift for staging").click()
    setup.get_by_label("Environment 1 accepted drift").set_input_files(str(bad))
    expect(setup.get_by_role("alert")).to_contain_text("isn't a Lockstep drift baseline")


def test_matrix_release_baseline_against_test_and_dev(page):
    """The seeded demo: apps-baseline (the last release) against test and dev, after the ELP rename."""
    page.get_by_role("tab", name="Compare", exact=True).click()
    sign_in_userpass(page, "left", "bob", vault="Vault A")
    choose_mount(page, "left", "apps-baseline")
    sign_in_userpass(page, "right", "bob", vault="Vault B")
    choose_mount(page, "right", "apps")

    page.get_by_role("tab", name="Matrix", exact=True).click()
    setup = page.get_by_label("Environment matrix setup")
    setup.get_by_label("Baseline name").fill("release")
    setup.get_by_label("Environment 1 name").fill("dev")
    setup.get_by_label("Environment 1 profile").select_option(label="Release ↔ dev: apps (ELP rename)")
    setup.get_by_role("button", name="Add environment").click()  # starts on the baseline's Vault and mount
    env2 = setup.locator(".matrix-env").nth(1)
    setup.get_by_label("Environment 2 name").fill("test")
    sel = env2.locator(".field", has_text="KV secret engine").locator("select")
    expect(sel.locator("option[value='apps']")).to_have_count(1)
    sel.select_option(value="apps")
    setup.get_by_label("Environment 2 profile").select_option(label="Release ↔ test: apps")
    setup.get_by_role("button", name="Compare all").click()

    grid = page.get_by_label("Environment matrix", exact=True)
    expect(grid.locator(".matrix-summary")).to_contain_text("6 rows differ from release, 5 in only one environment")
    rows = grid.locator("tbody tr")
    expect(rows).to_have_count(6)
    # dev's changes since the release are the odd ones out; test matches
    batch = rows.filter(has_text="batch_size")
    expect(batch.locator("td.mcell")).to_have_class(["mcell different", "mcell equal"])
    expect(rows.filter(has_text="legacy-syslog").locator("td.mcell")).to_have_class(["mcell missing", "mcell equal"])
    # retention_days differs everywhere (prod keeps logs longer on purpose): listed last
    expect(rows.last).to_contain_text("retention_days")
    expect(grid).not_to_contain_text("tok-prod")


def test_matrix_baseline_and_sign_in_from_the_connections_list(page, sandbox, vault_a, vault_b):
    """The baseline is picked in the Matrix itself, from any connection; signing in to another happens on the tab."""
    vault_a.put("app-config", f"{sandbox}/prod/db", {"user": "svc"})
    vault_b.put("app-config", f"{sandbox}/stg/db", {"user": "other"})
    page.get_by_role("tab", name="Matrix", exact=True).click()
    pane = page.get_by_label("Connections", exact=True)
    # Nothing signed in yet: the sign-in form is open in the list
    pane.get_by_role("button", name="Username", exact=True).click()
    pane.get_by_label("Username").fill("alice")
    pane.get_by_label("Password").fill("password")
    pane.get_by_role("button", name="Connect", exact=True).click()
    expect(pane.locator(".conn-row")).to_have_count(1)
    pane.get_by_role("group", name="Sign in to another").get_by_role("button", name="Vault B", exact=True).click()
    pane.get_by_role("button", name="Username", exact=True).click()
    pane.get_by_label("Username").fill("alice")
    pane.get_by_label("Password").fill("password")
    pane.get_by_role("button", name="Connect", exact=True).click()
    expect(pane.locator(".conn-row")).to_have_count(2)

    setup = page.get_by_label("Environment matrix setup")
    base = setup.get_by_label("Baseline connection or file")
    base.select_option(value=base.locator("option", has_text="Vault A").first.get_attribute("value"))
    bsel = setup.locator(".matrix-baseline .field", has_text="KV secret engine").locator("select")
    expect(bsel.locator("option[value='app-config']")).to_have_count(1)
    bsel.select_option(value="app-config")
    setup.get_by_label("Baseline path prefix").fill(f"{sandbox}/prod")
    setup.get_by_label("Baseline name").fill("prod")
    setup.get_by_role("button", name="Add environment").click()
    env = setup.locator(".matrix-env").first
    setup.get_by_label("Environment 1 name").fill("staging")
    conn = setup.get_by_label("Environment 1 connection")
    conn.select_option(value=conn.locator("option", has_text="Vault B").first.get_attribute("value"))
    esel = env.locator(".field", has_text="KV secret engine").locator("select")
    expect(esel.locator("option[value='app-config']")).to_have_count(1)
    esel.select_option(value="app-config")
    setup.get_by_label("Environment 1 path prefix").fill(f"{sandbox}/stg")
    setup.get_by_role("button", name="Compare all").click()
    grid = page.get_by_label("Environment matrix", exact=True)
    expect(grid.locator(".matrix-summary")).to_contain_text("1 row differs from prod")

    # Open in Compare: the baseline on the left, the environment on the right
    grid.get_by_role("button", name="Open in Compare").click()
    expect(side(page, "left").get_by_placeholder("e.g. payments/")).to_have_value(f"{sandbox}/prod")
    expect(side(page, "right").get_by_placeholder("e.g. payments/")).to_have_value(f"{sandbox}/stg")
