"""The Tools tab: the Transit playground (seeded transit/ keys)."""

from playwright.sync_api import expect

from conftest import sign_in_userpass


def test_encrypt_decrypt_sign_verify(page, sandbox):
    sign_in_userpass(page, "left", "alice", vault="Vault A")
    page.get_by_role("tab", name="Tools").click()
    page.get_by_role("navigation", name="Keys").get_by_role("button", name="app-key").click()
    op = page.get_by_label("Transit operation")
    op.get_by_label("Input").fill("hello transit")
    op.get_by_role("button", name="Encrypt", exact=True).click()
    out = op.get_by_label("Output")
    expect(out).to_contain_text("vault:v1:")
    op.get_by_role("button", name="Decrypt it").click()
    op.get_by_role("button", name="Decrypt", exact=True).click()
    expect(op.get_by_label("Output")).to_have_text("hello transit")

    page.get_by_role("navigation", name="Keys").get_by_role("button", name="signing-key").click()
    op.get_by_role("tab", name="Sign").click()
    op.get_by_label("Input").fill("release 1.2.3")
    op.get_by_role("button", name="Sign", exact=True).click()
    expect(op.get_by_label("Output")).to_contain_text("vault:v1:")
    op.get_by_role("button", name="Verify it").click()
    op.get_by_role("button", name="Verify", exact=True).click()
    expect(op.get_by_label("Output")).to_have_text("valid")


def test_leases_browse_and_revoke(page, sandbox):
    import httpx
    import os
    url = os.environ.get("VAULT_A_ADDR", "http://vault-a:8200")
    v = httpx.Client(base_url=f"{url}/v1/", headers={"X-Vault-Token": "root-a"})
    token = v.post("auth/token/create", json={"ttl": "13h", "policies": ["default"]}).json()["auth"]["client_token"]
    sign_in_userpass(page, "left", "alice", vault="Vault A")
    page.get_by_role("tab", name="Tools").click()
    page.get_by_role("tab", name="Leases").click()
    panel = page.get_by_role("region", name="Leases")
    panel.get_by_role("button", name="auth/").click()
    panel.get_by_role("button", name="token/").click()
    panel.get_by_role("button", name="create/").click()
    row = panel.locator("tr", has_text="in 13 hours").first
    expect(row).to_be_visible()
    row.get_by_role("checkbox").check()
    panel.get_by_label("Confirm revoke").fill("revoke 1 lease")
    panel.get_by_role("button", name="Revoke", exact=True).click()
    expect(panel.get_by_role("status")).to_contain_text("Revoked 1 lease")
    assert v.post("auth/token/lookup", json={"token": token}).status_code == 403


def test_database_credentials(page, sandbox):
    sign_in_userpass(page, "left", "alice", vault="Vault A")
    page.get_by_role("tab", name="Tools").click()
    page.get_by_role("tab", name="Database credentials").click()
    panel = page.get_by_role("region", name="Database credentials")
    expect(panel).to_contain_text("postgresql-database-plugin")
    panel.get_by_label("Database role").select_option("orders-readonly")
    panel.get_by_role("button", name="Generate credentials").click()
    creds = page.get_by_role("region", name="Generated credentials")
    expect(creds).to_contain_text("Valid for 1 h")
    expect(creds.get_by_label("password")).to_have_text("••••••••")
    creds.get_by_role("button", name="Show").click()
    expect(creds.get_by_label("password")).not_to_have_text("••••••••")
    creds.get_by_role("button", name="Revoke now").click()
    expect(creds).to_contain_text("Revoked")
