"""End-to-end user journeys through the real UI."""

import re

import httpx
import pytest
from playwright.sync_api import expect

from conftest import (choose_mount, compare, expand, key_row, row, set_reveal, show_everything,
                      side, sign_in_userpass)


def connect_both(page, mount="app-config", user="alice", prefix=""):
    sign_in_userpass(page, "left", user, vault="Vault A")
    sign_in_userpass(page, "right", user, vault="Vault B")
    choose_mount(page, "left", mount, prefix)
    choose_mount(page, "right", mount, prefix)


def test_sign_in_compare_and_filter(page):
    connect_both(page)
    compare(page)
    expect(row(page, "payments/db").locator(".badge").last).to_have_text("Different")
    expect(row(page, "legacy/old-service").locator(".badge").last).to_have_text("Left only")
    expect(row(page, "new-service/config").locator(".badge").last).to_have_text("Right only")
    expect(row(page, "payments/api")).to_have_count(0)  # equal secrets are hidden by default
    page.locator(".chip", has_text="Equal").click()
    expect(row(page, "payments/api")).to_have_count(1)
    expect(row(page, "payments/db")).to_have_count(0)
    page.get_by_placeholder("Filter by path or key…").fill("team")
    expect(page.locator(".secret")).to_have_count(1)


def test_values_masked_until_revealed(page):
    connect_both(page)
    compare(page)
    r = expand(page, "payments/db")
    pw = key_row(r, "password")
    expect(pw.locator(".val.masked")).to_have_count(2)
    expect(page.locator("body")).not_to_contain_text("s3cret-A")
    set_reveal(page, True)
    expect(pw.locator(".val").first).to_have_text("s3cret-A")
    expect(pw.locator(".val").last).to_have_text("s3cret-B")
    set_reveal(page, False)
    expect(pw.locator(".val.masked")).to_have_count(2)
    expect(page.locator("body")).not_to_contain_text("s3cret-A")  # values are dropped, not just hidden


def test_type_difference_and_last_changed(page):
    connect_both(page)
    compare(page)
    set_reveal(page, True)
    r = expand(page, "types/mixed")
    port = key_row(r, "port")
    expect(port.locator(".key-reason")).to_have_text("different type: number on the left, text on the right")
    expect(port.locator(".type-tag").first).to_have_text("number")
    expect(port.locator(".type-tag").last).to_have_text("string")
    expect(port.locator(".val-meta").first).to_contain_text(re.compile(r"changed .* · v\d+"))


def test_copy_with_review_conflict_and_audit(page, sandbox, vault_a, vault_b):
    vault_a.put("app-config", f"{sandbox}/one", {"k": "from-A", "same": "x"})
    vault_b.put("app-config", f"{sandbox}/one", {"k": "from-B", "same": "x", "only_b": "keep"})
    vault_a.put("app-config", f"{sandbox}/two", {"k": "A2"})
    vault_b.put("app-config", f"{sandbox}/two", {"k": "B2"})
    connect_both(page, prefix=sandbox)
    compare(page)

    for path in ("one", "two"):
        r = expand(page, path)
        key_row(r, "k").get_by_role("button", name="Copy k from left to right").click()
    expect(page.locator(".changeset-bar")).to_contain_text("2 keys staged in 2 secrets")

    page.get_by_role("button", name="Review & apply…").click()
    dialog = page.locator("dialog.review")
    expect(dialog.locator(".plan .badge", has_text="Will be written")).to_have_count(2)

    # Someone else edits "two" in Vault B while the review is open.
    vault_b.put("app-config", f"{sandbox}/two", {"k": "edited-meanwhile"})

    apply = dialog.get_by_role("button", name="Apply")
    expect(apply).to_be_disabled()  # confirmation required
    dialog.locator(".confirm input").check()
    apply.click()
    expect(dialog.get_by_role("heading", name="Changes applied")).to_be_visible()
    expect(dialog.locator(".plan").filter(has_text="/one")).to_contain_text("Written")
    expect(dialog.locator(".plan").filter(has_text="/two")).to_contain_text("Conflict: not written")

    assert vault_b.get("app-config", f"{sandbox}/one") == {"k": "from-A", "same": "x", "only_b": "keep"}
    assert vault_b.get("app-config", f"{sandbox}/two") == {"k": "edited-meanwhile"}

    dialog.get_by_role("button", name="Done, compare again").click()
    expect(dialog).to_be_hidden()
    expect(page.locator(".changeset-bar")).to_have_count(0)


def test_oidc_redirect_login(page):
    card = side(page, "left")
    expect(card.get_by_text("This Vault offers")).to_contain_text("oidc")
    card.get_by_role("button", name="Continue with OIDC →").click()
    page.wait_for_url(re.compile(r"dex\.localhost:5556"))
    page.get_by_label(re.compile("email", re.I)).fill("alice@example.com")
    page.get_by_label(re.compile("password", re.I)).fill("password")
    page.get_by_role("button", name=re.compile("login", re.I)).click()
    page.wait_for_url(re.compile(r"localhost:8080/"))
    expect(side(page, "left").locator(".conn-chip")).to_contain_text("oidc-alice@example.com")
    expect(side(page, "left").locator(".conn-chip")).to_contain_text("lockstep-admin")


def test_jwt_login(page):
    """Vault's JWT auth method, with an ID token Dex issues directly (password grant)."""
    r = httpx.post("http://dex.localhost:5556/dex/token", auth=("vault", "vault-dev-secret"), data={
        "grant_type": "password", "username": "alice@example.com", "password": "password",
        "scope": "openid email profile"})
    r.raise_for_status()
    card = side(page, "left")
    expect(card.get_by_text("This Vault offers")).to_contain_text("jwt (jwt/)")
    card.get_by_role("button", name="JWT", exact=True).click()
    card.get_by_label("JWT", exact=True).fill(r.json()["id_token"])
    card.get_by_role("button", name="Connect", exact=True).click()
    expect(card.locator(".conn-chip")).to_contain_text("jwt-alice@example.com")
    expect(card.locator(".conn-chip")).to_contain_text("lockstep-admin")
    choose_mount(page, "left", "app-config")


def test_limited_user_sees_no_access_not_one_sided(page):
    sign_in_userpass(page, "left", "carol", vault="Vault A")
    expect(side(page, "left").get_by_text("only mounts it can access are shown")).to_be_visible()
    sign_in_userpass(page, "right", "alice", vault="Vault B")
    choose_mount(page, "left", "app-config")
    choose_mount(page, "right", "app-config")
    compare(page)
    expect(page.locator(".notice.warn")).to_contain_text("no permission to list restricted/")
    expect(row(page, "restricted/root-creds").locator(".badge").last).to_have_text("No access")
    expect(row(page, "payments/api").locator(".badge").last).to_have_text("No access")


def test_inspect_pkcs12_both_sides_and_trust_root(page):
    connect_both(page, mount="certs")
    compare(page)
    show_everything(page)
    r = expand(page, "keystores/app")
    expect(key_row(r, "keystore.p12").locator(".badge.kind").first).to_contain_text("PKCS#12 keystore · password needed")
    key_row(r, "keystore.p12").get_by_role("button", name="Inspect").click()
    insp = page.locator("dialog.inspector")
    expect(insp.locator(".pw-row select")).to_have_count(2)
    for col in insp.locator(".inspect-col").all():
        col.locator(".pw-row select").select_option("keystore.password")
        col.locator(".pw-row button[type=submit]").click()
    expect(insp.locator(".check.ok", has_text="password accepted")).to_have_count(2)
    expect(insp.locator(".cert-diff tr.diff th", has_text="Serial")).to_be_visible()
    expect(insp.locator(".chain-verdict .badge", has_text="Untrusted root").first).to_be_visible()

    insp.locator(".trust-picker summary").click()
    insp.locator(".trust-list label", has_text="Vault A · certs · ca/root").locator("input").check()
    expect(insp.locator(".chain-verdict .badge", has_text="Untrusted root")).to_have_count(0)
    expect(insp.locator(".chain-verdict .badge", has_text="Chain trusted").first).to_be_visible()


def test_password_finder_opens_a_keystore_with_a_password_from_elsewhere(page):
    connect_both(page, mount="certs", prefix="some-secrets")
    compare(page)
    show_everything(page)
    r = expand(page, "files/certs.p12")
    key_row(r, "certs.p12").get_by_role("button", name="Inspect").click()
    insp = page.locator("dialog.inspector")
    col = insp.locator(".inspect-col.left")
    finder = col.locator(".pw-finder")
    opener = finder.locator(".pw-candidate.opens")
    expect(opener).to_have_count(1)
    expect(opener).to_contain_text("some-secrets/strings/KEYSTORE_PASSWORD · value")
    expect(finder.locator(".pw-others summary")).to_contain_text("2 other candidates tried in some-secrets/")
    opener.get_by_role("button", name="Use").click()
    expect(col.locator(".check.ok", has_text="password accepted")).to_contain_text(
        "from some-secrets/strings/KEYSTORE_PASSWORD · value")
    expect(col.locator(".node-label", has_text="Private key")).not_to_have_count(0)
    expect(insp).not_to_contain_text("not-the-store-password")  # candidates are named, never shown


def test_svg_preview_does_not_run_scripts(page):
    connect_both(page)
    compare(page)
    show_everything(page)
    set_reveal(page, True)
    r = expand(page, "frontend/assets")
    key_row(r, "icon.svg").get_by_role("button", name="Inspect").click()
    imgs = page.locator("dialog.inspector .img-preview img")
    expect(imgs).to_have_count(2)
    page.wait_for_function("() => [...document.querySelectorAll('.img-preview img')].every(i => i.complete && i.naturalWidth > 0)")
    assert page.title() == "Lockstep"  # the SVG's <script> would have changed it




def test_kubernetes_sign_in_when_available(page):
    cfg = page.evaluate("fetch('/api/config').then(r => r.json())")
    if not cfg["k8s_auth"]["available"]:
        pytest.skip("Kubernetes auth not available (run with the k8s profile)")
    card = side(page, "left")
    card.get_by_role("button", name="Kubernetes", exact=True).click()
    expect(card.locator(".notice.warn")).to_contain_text("lockstep/lockstep")
    card.get_by_label("Role name").fill("lockstep-reader")
    card.get_by_role("button", name="Connect", exact=True).click()
    expect(card.locator(".conn-chip")).to_contain_text("kubernetes-lockstep-lockstep")
    expect(card.locator(".conn-chip")).to_contain_text("lockstep-readonly")


def test_override_values_on_both_sides(page, sandbox, vault_a, vault_b):
    vault_a.put("app-config", f"{sandbox}/svc", {"password": "A", "user": "app"})
    vault_b.put("app-config", f"{sandbox}/svc", {"password": "B", "user": "app"})
    connect_both(page, prefix=sandbox)
    compare(page)
    r = expand(page, "svc")

    # Values are edited in place, on each side
    for which in ("left", "right"):
        cells = key_row(r, "password").locator(".val-cell")
        cells.nth(0 if which == "left" else 1).get_by_role("button", name="Edit").click()
        box = r.get_by_label(re.compile(rf"New value for password on .*{'Vault A' if which == 'left' else 'Vault B'}"))
        expect(box).to_have_class(re.compile("masked-input"))  # Show values is off
        box.fill("rotated-pw")
        r.get_by_role("button", name="Set value").click()
    expect(key_row(r, "password").locator(".val-cell.staged.set")).to_have_count(2)

    r.get_by_label("New key name").fill("rotated_at")
    r.get_by_role("button", name="＋ Add to both").click()
    for box in r.get_by_label(re.compile("New value for rotated_at")).all():
        box.fill("2026")
    editing = key_row(r, "rotated_at").locator(".val-cell.editing")
    for _ in range(2):  # each Set closes that editor
        editing.first.get_by_label("JSON").check()
        editing.first.get_by_role("button", name="Set value").click()
    expect(key_row(r, "rotated_at").locator(".val-cell.staged.set")).to_have_count(2)
    expect(page.locator(".changeset-bar")).to_contain_text("4 keys staged in 1 secret")

    page.get_by_role("button", name="Review & apply…").click()
    dialog = page.locator("dialog.review")
    expect(dialog.locator(".plan .badge", has_text="Will be written")).to_have_count(2)
    expect(dialog.locator(".plan .muted", has_text="Typed values")).to_have_count(2)
    expect(dialog).to_contain_text("whoever applies it types them again")  # typed values never go in a plan file
    expect(dialog).not_to_contain_text("rotated-pw")  # values stay hidden in the review without Show values
    dialog.locator("label.confirm input").check()
    dialog.get_by_role("button", name="Apply").click()
    expect(dialog.locator(".plan .badge", has_text=re.compile(r"^Written$"))).to_have_count(2)

    for v in (vault_a, vault_b):
        assert v.get("app-config", f"{sandbox}/svc") == {"password": "rotated-pw", "user": "app", "rotated_at": 2026}


def test_renew_connection_token(page):
    sign_in_userpass(page, "left", "alice", vault="Vault A")
    card = side(page, "left")
    card.get_by_role("button", name="Renew", exact=True).click()
    expect(card.get_by_role("status")).to_contain_text("Renewed")


def test_compare_custom_metadata_when_asked(page, sandbox, vault_a, vault_b):
    for v, owner in ((vault_a, "team-a"), (vault_b, "team-b")):
        v.put("app-config", f"{sandbox}/svc", {"k": "v"})
        v.c.post(f"app-config/metadata/{sandbox}/svc", json={"custom_metadata": {"owner": owner}}).raise_for_status()
    connect_both(page, prefix=sandbox)
    compare(page)
    expect(row(page, "svc")).to_have_count(0)  # equal, so hidden
    page.get_by_label("Include custom metadata").check()
    compare(page)
    expect(row(page, "svc").locator(".badge").last).to_have_text("Different")
    r = expand(page, "svc")
    expect(r.get_by_label("Custom metadata differences")).to_contain_text("owner team-a → team-b")


def test_connection_list_offers_every_preset(page):
    """Once a side is signed in, its Connection list still offers every preset Vault (on the
    demo, the OpenBaos too), and picking one opens the sign-in form on it."""
    from conftest import field
    sign_in_userpass(page, "left", "alice", vault="Vault A")
    card = side(page, "left")
    conn = card.get_by_role("combobox").first
    offered = conn.locator("optgroup[label='Sign in to'] option").all_inner_texts()
    assert offered == ["Vault A…", "Vault B…", "Vault B (read-only)…", "Vault B (with approval)…"]
    conn.select_option(label="Vault B…")
    expect(field(card, "Vault").locator("select")).to_have_value("1")
    card.get_by_role("button", name="Cancel").click()
    expect(card.locator(".conn-chip")).to_contain_text("userpass-alice")  # back to the signed-in connection


def test_results_say_where_inside_a_value_it_differs(page, sandbox, vault_a, vault_b):
    """A JSON value that differs in one nested field: Results name the field and say why,
    without showing values."""
    vault_a.put("app-config", f"{sandbox}/svc", {"config": '{"db": {"host": "a.internal", "port": 5432}}', "mode": "Prod"})
    vault_b.put("app-config", f"{sandbox}/svc", {"config": '{"db": {"host": "b.internal", "port": 5432}}', "mode": "prod"})
    connect_both(page, prefix=sandbox)
    compare(page)
    r = expand(page, "svc")
    expect(r.locator(".key-row", has_text="config").locator(".key-reason")).to_have_text("different at db.host")
    expect(r.locator(".key-row", has_text="mode").locator(".key-reason")).to_have_text("differs only in upper and lower case")
    expect(r).not_to_contain_text("a.internal")  # values stay hidden until revealed


# A throwaway self-signed certificate (no key anywhere), for comparing encodings
E2E_CERT = """-----BEGIN CERTIFICATE-----
MIIBGDCBv6ADAgECAgEBMAoGCCqGSM49BAMCMBYxFDASBgNVBAMMC2UyZS5leGFt
cGxlMB4XDTI2MDEwMTAwMDAwMFoXDTM1MTIzMDAwMDAwMFowFjEUMBIGA1UEAwwL
ZTJlLmV4YW1wbGUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASOuaZ/4fXL/YPn
J55WU06po0Ce/zaOHpB3RduUCis4ch33op6VnkpUg1D6GzX1YMsAD+xqpz27GVWf
P+CxaaRWMAoGCCqGSM49BAMCA0gAMEUCIHLTk0/Xo+3rjJjfW99lJ4H2W3LCOfqh
JVtuF1r6Im2tAiEA6P3dMrZa+hMv1VmXKTx+v0u9j7l6mXmIDgiXIHQmmls=
-----END CERTIFICATE-----
"""


def test_same_certificate_written_differently_is_equal_and_says_why(page, sandbox, vault_a, vault_b):
    vault_a.put("app-config", f"{sandbox}/tls", {"cert": E2E_CERT, "mode": "a"})
    vault_b.put("app-config", f"{sandbox}/tls", {"cert": E2E_CERT.replace("\n", "\r\n"), "mode": "b"})
    connect_both(page, prefix=sandbox)
    compare(page)
    r = expand(page, "tls")
    expect(r.locator(".key-row", has_text="cert").locator(".key-reason")).to_have_text(
        "equal as certificates (same fingerprint; line endings differ)")


def _jks_with_key(encrypted: bytes) -> str:
    """A JKS keystore (as base64) with one key entry: E2E_CERT and a stand-in for its encrypted key."""
    import base64
    import hashlib
    import struct
    der = base64.b64decode("".join(E2E_CERT.strip().splitlines()[1:-1]))
    utf = lambda s: struct.pack(">H", len(s)) + s.encode()  # noqa: E731
    body = (struct.pack(">III", 0xFEEDFEED, 2, 1) + struct.pack(">I", 1) + utf("app") + struct.pack(">Q", 1)
            + struct.pack(">I", len(encrypted)) + encrypted + struct.pack(">I", 1) + utf("X.509")
            + struct.pack(">I", len(der)) + der)
    return base64.b64encode(body + hashlib.sha1(b"Mighty Aphrodite" + body).digest()).decode()  # nosec B324


def test_keystore_that_cant_be_opened_is_not_compared(page, sandbox, vault_a, vault_b):
    vault_a.put("app-config", f"{sandbox}/java", {"keystore.jks": _jks_with_key(b"\x30\x03\x02\x01\x01"), "mode": "x"})
    vault_b.put("app-config", f"{sandbox}/java", {"keystore.jks": _jks_with_key(b"\x30\x03\x02\x01\x02"), "mode": "x"})
    connect_both(page, prefix=sandbox)
    compare(page)
    expect(page.locator(".chip", has_text="Not compared")).to_be_visible()
    r = expand(page, "java")
    expect(r.locator(".secret-head")).to_contain_text("Not compared")
    expect(key_row(r, "keystore.jks").locator(".key-reason")).to_contain_text("can't be checked without the password")
