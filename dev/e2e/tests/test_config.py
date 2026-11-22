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


def test_configuration_profile_pairs_different_paths(page, sandbox, vault_a, vault_b):
    tag = sandbox.replace("/", "")[-6:]
    vault_a.c.post(f"sys/mounts/kv-dev-{tag}", json={"type": "kv", "description": "dev settings", "options": {"version": "2"}}).raise_for_status()
    vault_b.c.post(f"sys/mounts/kv-prod-{tag}", json={"type": "kv", "description": "prod settings", "options": {"version": "2"}}).raise_for_status()
    try:
        sign_in_userpass(page, "left", "alice", vault="Vault A")
        sign_in_userpass(page, "right", "alice", vault="Vault B")
        page.get_by_role("tab", name="Configuration").click()
        page.get_by_role("button", name="New profile…").click()
        page.get_by_label("Name", exact=True).fill(f"e2e {tag}")
        page.get_by_label("Mount mappings").fill("kv-dev-* => kv-prod-*")
        page.get_by_label("Value rewrites").fill("dev => prod")
        page.get_by_role("button", name="Save profile").click()
        expect(page.get_by_label("Configuration profile")).to_have_value(f"personal:e2e {tag}")
        page.get_by_role("button", name="Compare configuration").click()
        engines = page.get_by_role("region", name="Secrets engines")
        page.get_by_text("Only differences").click()
        row = engines.locator(".policy-pair", has_text=f"kv-dev-{tag}/")
        expect(row).to_contain_text(f"⇄ kv-prod-{tag}/")
        expect(row).to_contain_text("Equal")
    finally:
        vault_a.c.delete(f"sys/mounts/kv-dev-{tag}")
        vault_b.c.delete(f"sys/mounts/kv-prod-{tag}")


def test_copy_tuning_to_the_other_side(page, sandbox, vault_a, vault_b):
    tag = sandbox.replace("/", "")[-6:]
    vault_a.c.post(f"sys/mounts/e2e-cp-{tag}", json={"type": "kv", "config": {"max_lease_ttl": "1h"}}).raise_for_status()
    vault_b.c.post(f"sys/mounts/e2e-cp-{tag}", json={"type": "kv", "config": {"max_lease_ttl": "2h"}}).raise_for_status()
    try:
        sign_in_userpass(page, "left", "alice", vault="Vault A")
        sign_in_userpass(page, "right", "alice", vault="Vault B")
        page.get_by_role("tab", name="Configuration").click()
        page.get_by_role("button", name="Compare configuration").click()
        engines = page.get_by_role("region", name="Secrets engines")
        row = engines.locator(".policy-pair", has_text=f"e2e-cp-{tag}/")
        row.locator(".pair-head").click()
        row.get_by_role("button", name="Copy tuning to Vault B…").click()
        dialog = page.get_by_role("dialog", name="Write policies and roles")
        expect(dialog.locator(".plan")).to_contain_text(f"secrets engine e2e-cp-{tag}/ tuning")
        dialog.locator("label.confirm input").check()
        dialog.get_by_role("button", name="Write", exact=True).click()
        expect(dialog.locator(".badge", has_text="Done")).to_have_count(1)
        dialog.get_by_role("button", name="Close").last.click()
        assert vault_b.c.get(f"sys/mounts/e2e-cp-{tag}/tune").json()["data"]["max_lease_ttl"] == 3600
        expect(engines.locator(".policy-pair", has_text=f"e2e-cp-{tag}/")).to_have_count(0)  # equal now, hidden
    finally:
        vault_a.c.delete(f"sys/mounts/e2e-cp-{tag}")
        vault_b.c.delete(f"sys/mounts/e2e-cp-{tag}")
