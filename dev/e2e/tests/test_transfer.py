"""Export & import through the UI: an encrypted export, the file as a comparison side
(values, copying from it), and an import with a transform."""

import json
import re

from playwright.sync_api import expect

from conftest import choose_mount, compare, expand, key_row, row, set_reveal, side, sign_in_userpass


def test_export_compare_against_the_file_and_import(page, sandbox, vault_a, vault_b, tmp_path):
    vault_a.put("app-config", f"{sandbox}/dev/app", {"env": "application-dev-env", "dba": "devDBA"})
    vault_a.put("app-config", f"{sandbox}/shared", {"k": "from-A"})
    vault_b.put("app-config", f"{sandbox}/shared", {"k": "from-B", "only_b": "keep"})
    sign_in_userpass(page, "left", "alice", vault="Vault A")
    sign_in_userpass(page, "right", "alice", vault="Vault B")
    choose_mount(page, "left", "app-config", sandbox)
    choose_mount(page, "right", "app-config", sandbox)

    # ---- export Vault A's sandbox, encrypted
    page.get_by_role("tab", name="Export & import").click()
    exp = page.locator("section[aria-label=Export]")
    expect(exp.get_by_label("Export from")).to_contain_text("Vault A")
    with page.expect_download() as dl:
        exp.get_by_role("button", name="Export and download").click()
    path = tmp_path / dl.value.suggested_filename
    dl.value.save_as(path)
    assert path.name.endswith(".encrypted.json")
    assert "application-dev-env" not in path.read_text()
    key = exp.get_by_label("Export key").inner_text()
    assert key.startswith("lsk1.")
    expect(exp).to_contain_text("2 secrets, 3 keys")
    exp.get_by_role("button", name=re.compile("saved the key")).click()
    expect(exp.get_by_label("Export key")).to_have_count(0)

    # ---- the file as the left side of a comparison
    page.get_by_role("tab", name="Compare").click()
    left = side(page, "left")
    left.get_by_role("button", name="Export file").click()
    left.get_by_label("Export file").set_input_files(str(path))
    left.get_by_label("Export key").fill("lsk1.wrongwrongwrongwrongwrongwrongwrongwrongw")
    left.get_by_role("button", name="Open").click()
    expect(left.locator(".notice.error")).to_contain_text(re.compile("Wrong key|damaged"))
    left.get_by_label("Export key").fill(key)
    left.get_by_role("button", name="Open").click()
    expect(left.locator(".file-chip")).to_contain_text(f"Vault A · app-config/{sandbox} · 2 secrets")
    # ⇄ moves the file to the right card and back, and each card follows its selection
    page.get_by_role("button", name="Swap sides").click()
    expect(side(page, "right").locator(".file-chip")).to_be_visible()
    expect(side(page, "left").locator(".conn-chip")).to_contain_text("userpass-alice")
    page.get_by_role("button", name="Swap sides").click()
    expect(left.locator(".file-chip")).to_be_visible()
    compare(page)
    expect(row(page, "dev/app").locator(".badge").last).to_have_text("Left only")
    r = expand(page, "shared")
    set_reveal(page, True)
    expect(key_row(r, "k").locator(".val").first).to_have_text("from-A")  # read from the file in memory
    expect(key_row(r, "k").get_by_role("button", name="Copy k from right to left")).to_have_count(0)  # never into a file
    expect(r.get_by_role("button", name=re.compile("Override left"))).to_have_count(0)
    key_row(r, "k").get_by_role("button", name="Copy k from left to right").click()
    page.get_by_role("button", name="Review & apply…").click()
    dialog = page.locator("dialog.review")
    expect(dialog.get_by_role("button", name="Save as plan")).to_be_disabled()
    dialog.locator("label.confirm input").check()
    dialog.get_by_role("button", name="Apply").click()
    expect(dialog.locator(".plan .badge", has_text=re.compile(r"^Written$"))).to_have_count(1)
    dialog.get_by_role("button", name="Done, compare again").click()
    assert vault_b.get("app-config", f"{sandbox}/shared") == {"k": "from-A", "only_b": "keep"}

    # ---- import the (already opened) file into Vault B with transforms
    set_reveal(page, False)
    page.get_by_role("tab", name="Export & import").click()
    imp = page.locator("section[aria-label=Import]")
    imp.get_by_label("Opened files").select_option(label=path.name)
    imp.get_by_label("Import into").select_option("right")
    imp.get_by_label("Import: ignored paths").fill("shared")
    imp.get_by_role("button", name="＋ Add transform").click()
    imp.get_by_label("Transform 1 find").fill("-dev-")
    imp.get_by_label("Transform 1 replace with").fill("-test-")
    imp.get_by_role("button", name="＋ Add transform").click()
    imp.get_by_label("Transform 2 find").fill("devDBA")
    imp.get_by_label("Transform 2 replace with").fill("testDBA")
    imp.get_by_role("button", name="＋ Add transform").click()
    imp.get_by_label("Transform 3 applies to").select_option("paths")
    imp.get_by_label("Transform 3 find").fill("dev/")
    imp.get_by_label("Transform 3 replace with").fill("test/")

    with page.expect_download() as rules_dl:
        imp.get_by_role("button", name="Save rules").click()
    rules = json.loads(open(rules_dl.value.path()).read())
    assert rules["$schema"].endswith("lockstep-import-rules-v1.json") and len(rules["transforms"]) == 3

    imp.get_by_role("button", name="Preview import").click()
    prev = imp.locator(".import-preview")
    expect(prev.locator(".notice.info")).to_contain_text("1 secret after the rules (left out: 1 secret(s), 0 key(s))")
    expect(prev.locator(".plan-head")).to_contain_text(f"Vault B · app-config/{sandbox}/test/app")
    expect(prev).not_to_contain_text("application-test-env")  # values hidden without Show values
    prev.locator("label.confirm input").check()
    prev.get_by_role("button", name="Import").click()
    expect(imp.locator(".import-preview .notice")).to_contain_text("1 written")
    assert vault_b.get("app-config", f"{sandbox}/test/app") == {"env": "application-test-env", "dba": "testDBA"}
