"""Page layout: the top bar's tabs scroll with arrows when they don't fit."""

from playwright.sync_api import expect

from conftest import REPORTS


def test_tab_arrows_when_tabs_overflow(page):
    page.set_viewport_size({"width": 1000, "height": 800})
    more = page.get_by_role("button", name="Show more tabs")
    earlier = page.get_by_role("button", name="Show earlier tabs")
    expect(more).to_be_visible()
    expect(earlier).to_be_hidden()
    page.screenshot(path=str(REPORTS / "tab-arrows.png"))
    more.click()
    expect(earlier).to_be_visible()
    tools = page.get_by_role("tab", name="Tools")
    expect(tools).to_be_in_viewport()
    tools.click()
    expect(tools).to_have_attribute("aria-selected", "true")
    page.screenshot(path=str(REPORTS / "tab-arrows-scrolled.png"))


def test_no_tab_arrows_when_tabs_fit(page):
    expect(page.get_by_role("tab", name="Tools")).to_be_visible()
    expect(page.get_by_role("button", name="Show more tabs")).to_be_hidden()
    expect(page.get_by_role("button", name="Show earlier tabs")).to_be_hidden()
