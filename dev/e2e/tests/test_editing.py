"""Staging in bulk, editing values in place, deleting keys and trimming the review."""

import json
import re

from playwright.sync_api import expect

from conftest import choose_mount, compare, expand, key_row, row, set_reveal, sign_in_userpass


def connect_both(page, prefix, user="alice"):
    sign_in_userpass(page, "left", user, vault="Vault A")
    sign_in_userpass(page, "right", user, vault="Vault B")
    choose_mount(page, "left", "app-config", prefix)
    choose_mount(page, "right", "app-config", prefix)


def test_every_key_picked_lights_up_all_keys(page, sandbox, vault_a, vault_b):
    vault_a.put("app-config", f"{sandbox}/cfg", {"a": "1", "b": "2", "same": "x"})
    vault_b.put("app-config", f"{sandbox}/cfg", {"a": "0", "same": "x"})
    connect_both(page, sandbox)
    compare(page)
    r = expand(page, "cfg")
    all_right = r.get_by_role("button", name="all keys to right →")
    for k in ("a", "b"):
        expect(all_right).to_have_attribute("aria-pressed", "false")
        key_row(r, k).get_by_role("button", name=f"Copy {k} from left to right").click()
    expect(all_right).to_have_attribute("aria-pressed", "true")
    all_right.click()  # pressed: unstages them all
    expect(page.locator(".changeset-bar")).to_have_count(0)


def test_group_by_folder_copy_a_folder_expand_and_collapse(page, sandbox, vault_a, vault_b):
    for name in ("one", "two", "three"):
        vault_a.put("app-config", f"{sandbox}/svc/{name}", {"k": f"A-{name}"})
    vault_a.put("app-config", f"{sandbox}/other/x", {"k": "A-x"})
    connect_both(page, sandbox)
    compare(page)

    page.get_by_label("Group secrets").select_option("folder")
    group = page.locator(".group").filter(has=page.locator(".group-head", has_text="svc/"))
    expect(group.locator(".secret")).to_have_count(3)
    group.get_by_role("button", name="all 3 secrets to right →").click()
    expect(page.locator(".changeset-bar")).to_contain_text("3 keys staged in 3 secrets")

    page.get_by_role("button", name="Expand all").click()
    expect(page.locator(".secret .keys")).to_have_count(4)
    page.get_by_role("button", name="Collapse all").click()
    expect(page.locator(".secret .keys")).to_have_count(0)

    page.get_by_label("Group secrets").select_option("staged")
    expect(page.locator(".group").first.locator(".group-head")).to_contain_text("Staged")
    expect(page.locator(".group").first.locator(".secret")).to_have_count(3)

    # Everything matching a filter, in one go
    page.get_by_label("Group secrets").select_option("none")
    page.get_by_placeholder("Filter by path or key…").fill("other")
    page.locator(".results-tools").get_by_role("button", name="all 1 secret to right →").click()
    expect(page.locator(".changeset-bar")).to_contain_text("4 keys staged in 4 secrets")


def test_edit_starts_from_the_other_side_and_shows_in_place(page, sandbox, vault_a, vault_b):
    vault_a.put("app-config", f"{sandbox}/svc", {"only_left": "left-value", "pw": "A"})
    vault_b.put("app-config", f"{sandbox}/svc", {"pw": "B"})
    connect_both(page, sandbox)
    compare(page)
    set_reveal(page, True)
    r = expand(page, "svc")
    right = key_row(r, "only_left").locator(".val-cell").nth(1)
    expect(right).to_contain_text("not present")
    right.get_by_role("button", name="Edit").click()
    box = r.get_by_label(re.compile("New value for only_left on"))
    expect(box).to_have_value("left-value")  # taken from the left
    box.fill("left-value-edited")
    r.get_by_role("button", name="Set value").click()
    staged = key_row(r, "only_left").locator(".val-cell.staged.set")
    expect(staged).to_contain_text("left-value-edited")  # the new value shows where "not present" was
    expect(staged).to_contain_text("new value")
    staged.get_by_role("button", name="Undo").click()
    expect(key_row(r, "only_left").locator(".val-cell").nth(1)).to_contain_text("not present")


def test_delete_a_key_everywhere_and_trim_the_review(page, sandbox, vault_a, vault_b):
    vault_a.put("app-config", f"{sandbox}/svc", {"old": "a", "k": "A", "keep": "x"})
    vault_b.put("app-config", f"{sandbox}/svc", {"old": "b", "k": "B", "keep": "x"})
    connect_both(page, sandbox)
    compare(page)
    r = expand(page, "svc")
    key_row(r, "old").get_by_role("button", name="Delete everywhere").click()
    expect(key_row(r, "old").locator(".val-cell.staged.remove")).to_have_count(2)
    key_row(r, "k").get_by_role("button", name="Copy k from left to right").click()
    expect(page.locator(".changeset-bar")).to_contain_text("3 keys staged in 1 secret")

    page.get_by_role("button", name="Review & apply…").click()
    dialog = page.locator("dialog.review")
    expect(dialog.locator(".plan-keys .action.remove")).to_have_count(2)
    # Take the copy of k back out from the review
    to_right = dialog.locator(".plan").filter(has=page.locator(".dir-r"))
    to_right.locator("tr", has_text="k").filter(has_not_text="old").get_by_role("button", name="Don't change k").click()
    expect(dialog.locator(".plan-keys tr")).to_have_count(2)
    expect(page.locator(".changeset-bar")).to_contain_text("2 keys staged in 1 secret")
    dialog.locator("label.confirm input").check()
    dialog.get_by_role("button", name="Apply").click()
    expect(dialog.locator(".plan .badge", has_text=re.compile(r"^Written$"))).to_have_count(2)
    assert vault_a.get("app-config", f"{sandbox}/svc") == {"k": "A", "keep": "x"}
    assert vault_b.get("app-config", f"{sandbox}/svc") == {"k": "B", "keep": "x"}


def test_remove_a_whole_change_from_the_review(page, sandbox, vault_a, vault_b):
    vault_a.put("app-config", f"{sandbox}/one", {"k": "A1"})
    vault_a.put("app-config", f"{sandbox}/two", {"k": "A2"})
    connect_both(page, sandbox)
    compare(page)
    page.locator(".results-tools").get_by_role("button", name="all 2 secrets to right →").click()
    page.get_by_role("button", name="Review & apply…").click()
    dialog = page.locator("dialog.review")
    expect(dialog.locator(".plan")).to_have_count(2)
    dialog.locator(".plan").filter(has_text="/two").get_by_role("button", name="Remove").click()
    expect(dialog.locator(".plan")).to_have_count(1)
    expect(page.locator(".changeset-bar")).to_contain_text("1 key staged in 1 secret")


def test_plan_with_typed_values(page, sandbox, vault_a, vault_b, tmp_path):
    vault_a.put("app-config", f"{sandbox}/svc", {"pw": "A"})
    vault_b.put("app-config", f"{sandbox}/svc", {"pw": "B"})
    connect_both(page, sandbox)
    compare(page)
    r = expand(page, "svc")
    key_row(r, "pw").locator(".val-cell").nth(1).get_by_role("button", name="Edit").click()
    r.get_by_label(re.compile("New value for pw on")).fill("typed-in-plan")
    r.get_by_role("button", name="Set value").click()
    page.get_by_role("button", name="Review & apply…").click()
    dialog = page.locator("dialog.review")
    save = dialog.get_by_role("button", name="Save as plan")
    expect(save).to_be_disabled()
    dialog.get_by_label("The plan file will hold the values I typed").check()
    with page.expect_download() as dl:
        save.click()
    path = tmp_path / dl.value.suggested_filename
    dl.value.save_as(path)
    plan = json.loads(path.read_text())
    assert plan["holds_values"] and plan["changes"][0]["set"] == {"pw": "typed-in-plan"}
    expect(dialog.get_by_role("status")).to_contain_text("It holds the values you typed")
    assert row(page, "svc").count() == 1
