"""The Browse tab: the tree, a secret's values and versions, and editing with check-and-set."""

import re

from playwright.sync_api import expect

from conftest import BASE, choose_mount, sign_in_userpass


def open_browse(page, prefix, user="alice"):
    sign_in_userpass(page, "left", user, vault="Vault A")
    choose_mount(page, "left", "app-config", prefix)
    page.get_by_role("tab", name="Browse", exact=True).click()


def tree(page):
    return page.get_by_role("navigation", name="Secrets")


def test_browse_is_the_default_tab(browser):
    ctx = browser.new_context(viewport={"width": 1440, "height": 900})
    page = ctx.new_page()
    page.goto(BASE)
    expect(page.get_by_role("tab", name="Browse", exact=True)).to_have_attribute("aria-selected", "true")
    expect(page.get_by_role("tab").first).to_have_text("Browse")
    ctx.close()


def test_tree_show_copyable_value_versions_and_diff(page, sandbox, vault_a):
    vault_a.put("app-config", f"{sandbox}/svc/db", {"user": "u", "pw": "one"})
    vault_a.put("app-config", f"{sandbox}/svc/db", {"user": "u", "pw": "two", "port": "5432"})
    vault_a.put("app-config", f"{sandbox}/top", {"k": "v"})
    open_browse(page, sandbox)
    t = tree(page)
    expect(t.get_by_role("button", name="svc/")).to_be_visible()
    t.get_by_role("button", name="svc/").click()
    t.get_by_role("button", name="db", exact=True).click()
    panel = page.locator(".secret-panel")
    expect(panel.locator(".crumbs")).to_contain_text("svc/db")
    pw = panel.locator("tr", has=page.locator("td.key", has_text=re.compile("^pw$")))
    expect(pw.locator("td.bval")).to_contain_text("••••")
    pw.get_by_role("button", name="Show").click()
    expect(pw.locator("td.bval")).to_contain_text("two")
    expect(pw.get_by_role("button", name="Copy")).to_be_visible()
    # The address is a link to this secret
    assert re.search(rf"#/browse/left/app-config/{sandbox}/svc/db$", page.url)

    panel.get_by_role("button", name=re.compile(r"^v1 ")).click()
    expect(panel.locator(".panel-head")).to_contain_text("viewing v1 of 2")
    panel.get_by_role("button", name="Compare with v2").click()
    diff = panel.locator(".version-diff")
    expect(diff.locator("tr.added")).to_contain_text("port")
    expect(diff.locator("tr.changed")).to_contain_text("pw")

    # The link opens the same secret after a reload
    page.reload()
    expect(page.locator(".secret-panel .crumbs")).to_contain_text("svc/db")


def test_edit_inline_save_and_conflict(page, sandbox, vault_a):
    vault_a.put("app-config", f"{sandbox}/cfg", {"user": "u", "old": "x"})
    open_browse(page, sandbox)
    tree(page).get_by_role("button", name="cfg", exact=True).click()
    panel = page.locator(".secret-panel")
    user = panel.locator("tr", has=page.locator("td.key", has_text=re.compile("^user$")))
    user.get_by_role("button", name="Edit").click()
    box = panel.get_by_label("New value for user")
    expect(box).to_have_value("u")  # starts from the current value
    box.fill("u2")
    user.get_by_role("button", name="Set value").click()
    panel.locator("tr", has=page.locator("td.key", has_text=re.compile("^old$"))).get_by_role("button", name="Delete").click()
    panel.get_by_label("New key name").fill("added")
    panel.get_by_role("button", name="＋ Add key").click()
    panel.get_by_label("New value for added").fill("new!")
    panel.locator("tr", has=page.locator("td.key", has_text=re.compile("^added"))).get_by_role("button", name="Set value").click()
    confirm = panel.get_by_role("region", name="Unsaved changes")
    expect(confirm).to_contain_text("3 unsaved changes")
    expect(confirm).to_contain_text("becomes v2")
    confirm.get_by_role("button", name="Save").click()
    expect(panel.locator(".notice", has_text="Saved as v2")).to_be_visible()
    assert vault_a.get("app-config", f"{sandbox}/cfg") == {"user": "u2", "added": "new!"}

    # Someone else writes meanwhile: the next save is a conflict, and nothing is written.
    # (Wait for the panel to have reloaded v2 first, or it might load their v3 instead.)
    expect(panel.locator(".panel-head")).to_contain_text("v2 ·")
    vault_a.put("app-config", f"{sandbox}/cfg", {"user": "theirs"})
    panel.locator("tr", has=page.locator("td.key", has_text=re.compile("^user$"))).get_by_role("button", name="Edit").click()
    panel.get_by_label("New value for user").fill("mine")
    panel.get_by_role("button", name="Set value").click()
    panel.get_by_role("region", name="Unsaved changes").get_by_role("button", name="Save").click()
    expect(panel.locator(".notice.error")).to_contain_text("Changed since you loaded it")
    assert vault_a.get("app-config", f"{sandbox}/cfg") == {"user": "theirs"}


def test_new_secret_rollback_delete_and_undelete(page, sandbox, vault_a):
    vault_a.put("app-config", f"{sandbox}/keep", {"k": "v"})
    open_browse(page, sandbox)
    t = tree(page)
    t.get_by_role("button", name=re.compile("New secret")).click()
    t.get_by_label("New secret name").fill("fresh")
    t.get_by_role("button", name="Create").click()
    panel = page.locator(".secret-panel")
    panel.get_by_label("New key name").fill("a")
    panel.get_by_role("button", name="＋ Add key").click()
    panel.get_by_label("New value for a").fill("1")
    panel.get_by_role("button", name="Set value").click()
    panel.get_by_role("region", name="Unsaved changes").get_by_role("button", name="Save").click()
    expect(panel.locator(".notice", has_text="Saved as v1")).to_be_visible()
    expect(t.get_by_role("button", name="fresh", exact=True)).to_be_visible()
    vault_a.put("app-config", f"{sandbox}/fresh", {"a": "2"})
    page.reload()
    panel = page.locator(".secret-panel")
    panel.get_by_role("button", name=re.compile(r"^v1 ")).click()
    panel.get_by_role("button", name="Roll back to v1").click()
    panel.get_by_role("alertdialog").get_by_role("button", name="Confirm").click()
    expect(panel.locator(".notice", has_text="Saved as v3")).to_be_visible()
    assert vault_a.get("app-config", f"{sandbox}/fresh") == {"a": "1"}

    panel.get_by_role("button", name="Delete latest").click()
    panel.get_by_role("alertdialog").get_by_role("button", name="Confirm").click()
    expect(panel.locator(".notice.warn", has_text="latest version (v3) is deleted")).to_be_visible()
    panel.get_by_role("button", name="Undelete v3").click()
    panel.get_by_role("alertdialog").get_by_role("button", name="Confirm").click()
    expect(panel.locator(".notice.warn", has_text="is deleted")).to_have_count(0)
    assert vault_a.get("app-config", f"{sandbox}/fresh") == {"a": "1"}


def test_stage_changes_and_review(page, sandbox, vault_a):
    vault_a.put("app-config", f"{sandbox}/one", {"k": "1"})
    vault_a.put("app-config", f"{sandbox}/two", {"k": "2"})
    open_browse(page, sandbox)
    page.get_by_label("Stage changes").check()
    for name, val in (("one", "1b"), ("two", "2b")):
        tree(page).get_by_role("button", name=name, exact=True).click()
        panel = page.locator(".secret-panel")
        panel.get_by_role("button", name="Edit").click()
        panel.get_by_label("New value for k").fill(val)
        panel.get_by_role("button", name="Set value").click()
        panel.get_by_role("region", name="Unsaved changes").get_by_role("button", name="Stage").click()
    expect(page.get_by_role("region", name="Staged edits")).to_contain_text("2 changes staged in 2 secrets")
    page.get_by_role("button", name="Review & apply…").click()
    dialog = page.locator("dialog.review")
    dialog.get_by_role("button", name="Apply 2 changes").click()
    expect(dialog.locator(".badge", has_text="applied")).to_have_count(2)
    assert vault_a.get("app-config", f"{sandbox}/one") == {"k": "1b"}
    assert vault_a.get("app-config", f"{sandbox}/two") == {"k": "2b"}


def test_find_and_no_access(page, sandbox, vault_a):
    vault_a.put("app-config", f"{sandbox}/deep/er/needle", {"k": "v"})
    open_browse(page, sandbox)
    page.get_by_label("Find secrets").fill("needle")
    page.get_by_label("Find secrets").press("Enter")
    expect(tree(page)).to_contain_text("1 match")
    tree(page).get_by_role("button", name=f"{sandbox}/deep/er/needle").click()
    expect(page.locator(".secret-panel .crumbs")).to_contain_text("needle")


def test_carol_cannot_open_restricted(page):
    open_browse(page, "", user="carol")
    t = tree(page)
    t.get_by_role("button", name="restricted/").click()
    expect(t).to_contain_text("can’t list this folder")


def test_edit_metadata_and_see_who_wrote_it(page, sandbox, vault_a):
    vault_a.put("app-config", f"{sandbox}/meta", {"k": "v"})
    open_browse(page, sandbox)
    tree(page).get_by_role("button", name="meta", exact=True).click()
    panel = page.locator(".secret-panel")
    panel.locator("details.metadata summary").click()
    panel.get_by_role("button", name="Edit metadata").click()
    panel.get_by_label("Max versions").fill("7")
    panel.get_by_role("button", name="＋ Add label").click()
    panel.get_by_label("Custom metadata 1 key").fill("owner")
    panel.get_by_label("Custom metadata 1 value").fill("payments")
    panel.get_by_role("button", name="Save metadata").click()
    expect(panel.locator(".notice", has_text="Metadata saved")).to_be_visible()
    meta = vault_a.c.get(f"app-config/metadata/{sandbox}/meta").json()["data"]
    assert meta["max_versions"] == 7 and meta["custom_metadata"] == {"owner": "payments"}

    # Edit a value as alice: the version says who wrote it
    panel.get_by_role("button", name="Edit").click()
    panel.get_by_role("button", name="Generate").click()
    assert len(panel.get_by_label("New value for k").input_value()) == 32
    panel.get_by_role("button", name="Set value").click()
    panel.get_by_role("region", name="Unsaved changes").get_by_role("button", name="Save").click()
    expect(panel.locator(".panel-head")).to_contain_text("by userpass-alice")


def test_share_once_and_open_it(page, sandbox, vault_a):
    vault_a.put("app-config", f"{sandbox}/creds", {"user": "svc", "pw": "s3cret"})
    open_browse(page, sandbox)
    tree(page).get_by_role("button", name="creds", exact=True).click()
    panel = page.locator(".secret-panel")
    panel.get_by_role("button", name="Share once…").click()
    share = page.get_by_role("region", name="Share once")
    share.get_by_label("user").uncheck()
    share.get_by_role("button", name="Create one-time token").click()
    token = share.get_by_label("Wrapping token").inner_text()
    assert len(token) > 20

    page.get_by_role("button", name="Open a shared token…").click()
    dialog = page.get_by_role("dialog", name="Open a shared token")
    dialog.get_by_label("Shared token").fill(token)
    dialog.get_by_role("button", name="Check").click()
    expect(dialog.locator(".notice.info")).to_contain_text("expires")
    dialog.get_by_role("button", name="Open (works once)").click()
    expect(dialog.locator(".plan-keys")).to_contain_text("s3cret")
    expect(dialog.locator(".plan-keys")).not_to_contain_text("svc")


def test_snippets_and_theme(page, sandbox, vault_a):
    vault_a.put("app-config", f"{sandbox}/snip", {"user": "u"})
    open_browse(page, sandbox)
    tree(page).get_by_role("button", name="snip", exact=True).click()
    page.locator(".secret-panel").get_by_role("button", name="Snippets").click()
    snippets = page.locator(".snippets")
    expect(snippets).to_contain_text(f"vault kv get -mount=app-config {sandbox}/snip")
    expect(snippets).to_contain_text("user=<user>")
    expect(snippets).to_contain_text('resource "vault_kv_secret_v2"')
    expect(snippets).not_to_contain_text("=u ")
    page.get_by_label("Theme").select_option("dark")
    assert page.evaluate("document.documentElement.dataset.theme") == "dark"
    page.reload()
    assert page.evaluate("document.documentElement.dataset.theme") == "dark"


def test_yaml_view_masks_values(page, sandbox, vault_a):
    vault_a.put("app-config", f"{sandbox}/yaml", {"user": "svc", "pw": "s3cret", "port": 5432})
    open_browse(page, sandbox)
    tree(page).get_by_role("button", name="yaml", exact=True).click()
    panel = page.locator(".secret-panel")
    panel.get_by_role("button", name="YAML").click()
    yaml = panel.get_by_label("Secret as YAML")
    expect(yaml).to_contain_text('pw: "••••••••"')
    expect(yaml).not_to_contain_text("s3cret")
    page.get_by_text("Show values", exact=True).click()
    expect(yaml).to_contain_text("pw: s3cret")
    expect(yaml).to_contain_text("port: 5432")
