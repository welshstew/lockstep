"""The Configuration tab: two Vaults' secrets engines and auth methods compared."""

from playwright.sync_api import expect

from conftest import sign_in_userpass


def test_compare_configuration(page, sandbox, vault_a, vault_b):
    tag = sandbox.replace("/", "")[-6:]
    vault_a.c.post(f"sys/mounts/e2e-cfg-{tag}", json={"type": "kv", "options": {"version": "2"}, "config": {"max_lease_ttl": "1h"}}).raise_for_status()
    vault_b.c.post(f"sys/mounts/e2e-cfg-{tag}", json={"type": "kv", "options": {"version": "2"}, "config": {"max_lease_ttl": "2h"}}).raise_for_status()
    try:
        sign_in_userpass(page, "left", "alice", vault="Vault A")
        sign_in_userpass(page, "right", "alice", vault="Vault B")
        page.get_by_role("tab", name="Configuration").click()
        page.get_by_role("button", name="Compare configuration").click()
        expect(page.locator(".overview.left")).to_contain_text("Version")
        engines = page.get_by_role("region", name="Secrets engines")
        row = engines.locator(".policy-pair", has_text=f"e2e-cfg-{tag}/")
        expect(row).to_contain_text("Different")
        row.locator(".pair-head").click()
        expect(row.locator(".rule-diff")).to_contain_text("config.max_lease_ttl")
        expect(row.locator(".rule-diff")).to_contain_text("7200")
        expect(engines).to_contain_text("team-a-only/")  # only in Vault A
        expect(engines).not_to_contain_text("cubbyhole/")  # built-in mounts hidden
        page.get_by_text("Built-in mounts").click()
        page.get_by_text("Only differences").click()
        expect(engines).to_contain_text("cubbyhole/")
        roles = page.get_by_role("region", name="Engine roles and keys")
        key = roles.locator(".policy-pair", has_text="transit/keys/app-key")
        expect(key).to_contain_text("Different")
        key.locator(".pair-head").click()
        expect(key.locator(".rule-diff")).to_contain_text("deletion_allowed")
    finally:
        vault_a.c.delete(f"sys/mounts/e2e-cfg-{tag}")
        vault_b.c.delete(f"sys/mounts/e2e-cfg-{tag}")
