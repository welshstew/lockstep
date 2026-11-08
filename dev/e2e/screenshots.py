"""Generate the README screenshots by driving the real app against the seeded dev Vaults.

    make screenshots     # → docs/images/<scene>-<theme>.png (dark and light)

Everything shown is dev fixture data from dev/seed. The script only reads, except for
staging a copy and saving it as a plan, which it never applies.
"""

from __future__ import annotations

import os
from pathlib import Path

from playwright.sync_api import Page, expect, sync_playwright

# Not "http://app:8080": .app is an HSTS-preloaded TLD, so Chromium forces HTTPS for a host named "app".
BASE = os.environ.get("APP_URL", "http://lockstep:8080")
OUT = Path(os.environ.get("OUT_DIR", "/out"))
VIEWPORT = {"width": 1440, "height": 900}
API = {"X-Requested-With": "lockstep", "Content-Type": "application/json"}


def api(page: Page, method: str, path: str, body: dict | None = None):
    return page.evaluate(
        """async ([m, p, b, h]) => {
            const r = await fetch(p, {method: m, headers: h, body: b ? JSON.stringify(b) : undefined});
            return r.status === 204 ? null : r.json();
        }""", [method, path, body, API])


def sign_in(page: Page, mount: str, prefix: str = "") -> None:
    """Connect alice (userpass) to both Vaults and pre-select the mount, through the API."""
    for c in api(page, "GET", "/api/connections"):
        api(page, "DELETE", f"/api/connections/{c['id']}")
    a = api(page, "POST", "/api/connections", {"preset_id": 0, "auth": {"method": "userpass", "username": "alice", "password": "password"}})
    b = api(page, "POST", "/api/connections", {"preset_id": 1, "auth": {"method": "userpass", "username": "alice", "password": "password"}})
    page.evaluate("s => localStorage.setItem('lockstep.sides', JSON.stringify(s))",
                  [{"connId": a["id"], "mount": mount, "prefix": prefix}, {"connId": b["id"], "mount": mount, "prefix": prefix}])
    page.reload()


def compare(page: Page, everything: bool = False) -> None:
    page.get_by_role("button", name="Compare", exact=True).click()
    expect(page.locator(".secret").first).to_be_visible()
    if everything:
        page.locator(".chip", has_text="Everything").click()


def row(page: Page, path: str):
    return page.locator(".secret").filter(has=page.locator(".secret-path", has_text=path)).first


def open_row(page: Page, path: str):
    r = row(page, path)
    r.locator(".secret-head").click()
    expect(r.locator(".key-row").first).to_be_visible()
    return r


def scroll_to(locator, offset: int = 24) -> None:
    """Put an element `offset` px below the top of the window (scroll_into_view_if_needed
    does nothing when the element is already partly visible)."""
    locator.evaluate("(el, off) => window.scrollTo(0, el.getBoundingClientRect().top + window.scrollY - off)", offset)


def reveal(page: Page) -> None:
    page.locator(".toggle input").check(force=True)


def shot(page: Page, name: str, theme: str, clip_to=None) -> None:
    path = OUT / f"{name}-{theme}.png"
    page.wait_for_timeout(350)  # let transitions settle
    if clip_to is not None:
        clip_to.screenshot(path=str(path))
    else:
        page.screenshot(path=str(path))
    print("wrote", path)


def scenes(page: Page, theme: str) -> None:
    # 1. Connect screen: login methods discovered from each Vault, OIDC preselected.
    page.goto(BASE)
    for c in api(page, "GET", "/api/connections"):
        api(page, "DELETE", f"/api/connections/{c['id']}")
    page.evaluate("localStorage.clear()")
    page.reload()
    expect(page.get_by_text("This Vault offers").first).to_be_visible()
    shot(page, "01-connect", theme, page.locator(".sides"))

    # 2. Comparison overview: statuses, filters, masked values.
    sign_in(page, "app-config")
    compare(page)
    page.locator(".results-head").scroll_into_view_if_needed()
    page.evaluate("window.scrollTo(0, document.querySelector('.compare-bar').offsetTop - 12)")
    shot(page, "02-compare", theme)

    # 3. Key-level detail with values shown, a staged copy and last-changed metadata.
    reveal(page)
    r = open_row(page, "payments/db")
    open_row(page, "frontend/settings")
    r.get_by_role("button", name="Copy password from left to right").click()
    expect(page.locator(".changeset-bar")).to_be_visible()
    scroll_to(r)
    shot(page, "03-detail-and-copy", theme)

    # 4. Review before applying (never applied here).
    page.get_by_role("button", name="Review & apply…").click()
    dialog = page.locator("dialog.review")
    expect(dialog.locator(".plan").first).to_be_visible()
    shot(page, "04-review", theme)

    # 12. The same changes saved as a plan, then opened and checked in the Sync plans tab (never applied).
    dialog.get_by_label("Plan note").fill("Rotate the payments database password in Vault B")
    with page.expect_download() as dl:
        dialog.get_by_role("button", name="Save as plan").click()
    plan_file = Path("/tmp") / dl.value.suggested_filename
    dl.value.save_as(plan_file)
    dialog.get_by_role("button", name="Cancel").click()
    page.get_by_role("tab", name="Sync plans").click()
    page.get_by_label("Plan file").set_input_files(plan_file)
    page.get_by_role("button", name="Check plan").click()
    expect(page.get_by_role("status")).to_contain_text("exactly as they were")
    scroll_to(page.locator("nav.tabs"))
    shot(page, "12-sync-plan", theme)
    page.get_by_role("tab", name="Compare").click()

    # 9. A comparison profile: prod paths in A paired with staging paths in B, host ignored.
    page.locator("section.profile-bar").get_by_role("combobox").select_option(label="Prod ↔ staging services")
    compare(page)
    page.locator(".chip", has_text="Everything").click()
    db = page.locator(".secret").filter(has=page.locator(".map-l", has_text="services/billing/prod/db"))
    db.locator(".secret-head").click()
    expect(db.locator(".key-row.ignored")).to_have_count(1)
    scroll_to(page.locator(".profile-bar"))
    shot(page, "09-profile", theme)

    # 10. The profile editor (a copy of the shared profile).
    page.locator("section.profile-bar").get_by_role("button", name="Duplicate").click()
    ed = page.locator("dialog.profile-editor")
    expect(ed).to_be_visible()
    shot(page, "10-profile-editor", theme)
    ed.get_by_role("button", name="Cancel").click()
    page.locator("section.profile-bar").get_by_role("combobox").select_option("")

    # 5. Certificates mount: value-type badges, including an expired certificate.
    sign_in(page, "certs")
    compare(page, everything=True)
    for p in ("keystores/app", "web/expired"):
        open_row(page, p)
    scroll_to(row(page, "keystores/app"))
    shot(page, "05-badges", theme)

    # 6. Inspect both sides of a PKCS#12: password from a sibling key, chain trusted via ca/root.
    row(page, "keystores/app").locator(".key-row").filter(has_text="keystore.p12").get_by_role("button", name="Inspect").click()
    insp = page.locator("dialog.inspector")
    expect(insp.locator(".pw-row select")).to_have_count(2)  # both columns analysed
    for col in insp.locator(".inspect-col").all():
        col.locator(".pw-row select").select_option("keystore.password")
        col.locator(".pw-row button[type=submit]").click()
    expect(insp.locator(".check.ok", has_text="password accepted")).to_have_count(2)
    expect(insp.locator(".cert-diff")).to_be_visible()
    insp.locator(".trust-picker summary").click()
    insp.locator(".trust-list label", has_text="Vault A · certs · ca/root").locator("input").check()
    insp.locator(".trust-picker summary").click()
    expect(insp.locator(".chain-verdict", has_text="Chain trusted").first).to_be_visible()
    shot(page, "06-inspect-pkcs12", theme)
    insp.locator(".inspect-col.left .cert-card").first.scroll_into_view_if_needed()
    shot(page, "07-certificate-chain", theme)
    insp.get_by_role("button", name="Close").click()

    # 8. A Java keystore (JKS) opened with its password.
    open_row(page, "keystores/java-app").locator(".key-row").filter(has_text="keystore.jks").get_by_role("button", name="Inspect").click()
    insp = page.locator("dialog.inspector")
    expect(insp.locator(".pw-row select")).to_have_count(2)
    for col in insp.locator(".inspect-col").all():
        col.locator(".pw-row select").select_option("keystore.password")
        col.locator(".pw-row button[type=submit]").click()
    expect(insp.get_by_text("✓ verified").first).to_be_visible()
    shot(page, "08-inspect-jks", theme)
    insp.get_by_role("button", name="Close").click()

    # 11. Certificate expiry dashboard across both Vaults' certs mounts.
    page.get_by_role("tab", name="Certificate expiry").click()
    page.get_by_role("button", name="Scan for certificates").click()
    expect(page.locator(".expiry-table tbody tr").first).to_be_visible()
    scroll_to(page.locator(".tabs"))
    shot(page, "11-expiry", theme)
    page.get_by_role("tab", name="Compare").click()


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        for theme in ("dark", "light"):
            ctx = browser.new_context(viewport=VIEWPORT, device_scale_factor=2, color_scheme=theme)
            page = ctx.new_page()
            page.set_default_timeout(15000)
            scenes(page, theme)
            ctx.close()
        browser.close()


if __name__ == "__main__":
    main()
