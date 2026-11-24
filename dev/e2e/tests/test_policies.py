"""The Policies tab: explaining policies on a mount."""

import re

from playwright.sync_api import expect

from conftest import choose_mount, sign_in_userpass


def open_policies(page, user="alice", prefix="payments"):
    sign_in_userpass(page, "left", user, vault="Vault A")
    choose_mount(page, "left", "app-config", prefix)
    page.get_by_role("tab", name="Policies", exact=True).click()


def cell(page, path, col):
    """The mark in a secret's row for a column (0 = See names … 5 = History)."""
    row = page.locator(".policy-table tbody tr").filter(has=page.get_by_role("button", name=f"Why: {path}"))
    return row.locator(".pcell").nth(col)


def test_explain_a_policy_from_vault_and_see_why(page, sandbox):
    open_policies(page)
    page.get_by_role("tab", name="Policies in Vault").click()
    page.locator(".chips-wrap").get_by_role("button", name="lockstep-limited").click()
    page.get_by_role("button", name="Explain", exact=True).click()

    expect(page.locator(".policy-chip")).to_contain_text("lockstep-limited")
    expect(cell(page, "payments/db", 1)).to_have_text("✓")  # Read
    expect(cell(page, "payments/api", 1)).to_have_text("✗")  # denied by a deny rule
    expect(cell(page, "payments/db", 4)).to_have_text("·")  # Destroy: not granted

    page.get_by_role("button", name="Why: payments/api").click()
    why = page.locator(".why")
    expect(why).to_contain_text("app-config/payments/api")
    expect(why).to_contain_text('path "app-config/data/payments/api"')
    expect(why).to_contain_text("lockstep-limited:")


def test_own_token_without_rights_falls_back_to_vault(page, sandbox):
    open_policies(page, user="carol", prefix="")
    page.get_by_role("tab", name="My token’s policies").click()
    page.get_by_role("button", name="Explain", exact=True).click()
    expect(page.locator(".notice", has_text="come from Vault itself")).to_be_visible()
    expect(page.locator(".notice", has_text="missing rights")).to_contain_text("read on sys/policies/acl/lockstep-limited")
    expect(cell(page, "payments/api", 1)).to_have_text("·")
    expect(cell(page, "payments/db", 2)).to_have_text("✓")  # carol may write


def test_paste_a_policy_and_get_findings(page, sandbox):
    open_policies(page)
    page.get_by_role("tab", name="Paste a policy").click()
    page.get_by_label("Policy text").fill('path "app-config/payments/*" {\n  capabilities = ["read"]\n}\n'
                                          'path "app-config/metadata/*" { capabilities = ["list"] }')
    page.get_by_role("button", name="Explain", exact=True).click()
    findings = page.locator(".findings")
    expect(findings).to_contain_text("Did you mean app-config/data/payments/*")
    expect(cell(page, "payments/db", 0)).to_have_text("✓")  # listed via metadata
    expect(cell(page, "payments/db", 1)).to_have_text("·")  # the rule without data/ doesn't grant reads


def test_compare_policies_across_vaults_with_a_profile(page, sandbox, vault_a, vault_b):
    tag = sandbox.replace("/", "")[-6:]
    made = [(vault_a, f"e{tag}-pay-dev", 'path "app-config/data/dev/*" { capabilities = ["read"] }'),
            (vault_b, f"e{tag}-pay-prod", 'path "app-config/data/prod/*" {\n  capabilities = ["read", "update"]\n}')]
    for v, n, t in made:
        v.c.put(f"sys/policies/acl/{n}", json={"policy": t}).raise_for_status()
    try:
        sign_in_userpass(page, "left", "alice", vault="Vault A")
        sign_in_userpass(page, "right", "alice", vault="Vault B")
        choose_mount(page, "left", "app-config", "payments")
        choose_mount(page, "right", "app-config", "payments")
        page.get_by_role("tab", name="Policies", exact=True).click()
        page.get_by_role("tab", name="Compare across Vaults").click()

        page.get_by_role("button", name="New profile…").click()
        page.get_by_role("button", name="＋ Add mapping").click()
        page.get_by_label("Mapping 1 left").fill(f"e{tag}-*-dev")
        page.get_by_label("Mapping 1 right").fill(f"e{tag}-*-prod")
        page.get_by_role("button", name="＋ Add rewrite").click()
        page.get_by_label("Rewrite 1 find").fill("/dev/")
        page.get_by_label("Rewrite 1 replace").fill("/prod/")
        page.get_by_role("button", name="Compare policies").click()

        page.get_by_placeholder("Filter by name…").fill(f"e{tag}")
        pair = page.locator(".policy-pair")
        expect(pair).to_have_count(1)
        expect(pair).to_contain_text("mapped")
        expect(pair).to_contain_text("Different")
        pair.locator(".pair-head").click()
        expect(pair.locator(".rule-diff tr.changed")).to_contain_text("app-config/data/prod/*")
        expect(pair.locator(".rule-diff tr.changed")).to_contain_text("read, update")

        pair.get_by_role("button", name="Show text").click()
        expect(pair.get_by_label("Right policy text")).to_contain_text("capabilities")

        # Seeded policies are the same on both Vaults
        page.get_by_placeholder("Filter by name…").fill("lockstep-limited")
        page.get_by_role("button", name="Everything").click()
        expect(page.locator(".policy-pair")).to_contain_text("Equal")
        page.locator(".policy-pair .pair-head").click()
        page.get_by_role("button", name="Compare access on app-config ⇄ app-config").click()
        expect(page.locator(".access-compare")).to_contain_text("0 of 2 secrets differ")
    finally:
        for v, n, _ in made:
            v.c.delete(f"sys/policies/acl/{n}")


def test_side_cards_collapse_to_a_summary(page, sandbox):
    sign_in_userpass(page, "left", "alice", vault="Vault A")
    choose_mount(page, "left", "app-config", "payments")
    card = page.locator("section.side-card.left")
    page.get_by_role("button", name="Collapse the left side").click()
    summary = card.locator(".side-summary")
    expect(summary).to_contain_text("alice")
    expect(summary).to_contain_text("via userpass on")
    expect(summary).to_contain_text("Vault A")
    expect(summary).to_contain_text("app-config/payments")
    expect(card.get_by_label("Path prefix (optional)")).to_have_count(0)
    page.reload()  # remembered
    expect(card.locator(".side-summary")).to_contain_text("alice")
    card.locator(".summary-btn").click()
    expect(card.locator(".side-summary")).to_have_count(0)
    expect(page.locator("section.side-card.right .side-summary")).to_have_count(0)


def open_build(page, prefix="services"):
    sign_in_userpass(page, "left", "alice", vault="Vault A")
    choose_mount(page, "left", "app-config", prefix)
    page.get_by_role("tab", name="Policies", exact=True).click()
    page.get_by_role("tab", name="Build & suggest").click()


def test_build_a_policy_preview_and_download(page, sandbox, tmp_path):
    import zipfile
    open_build(page, prefix="payments")
    page.get_by_role("button", name="＋ New policy").click()
    page.get_by_label("Policy name").fill("payments-reader")
    page.get_by_label("Rule 1 where").fill("payments/**")
    page.get_by_label("Rule 1 History").check()
    hcl = page.get_by_label("Generated HCL")
    expect(hcl).to_contain_text('path "app-config/data/payments/*"')
    expect(hcl).to_contain_text('path "app-config/metadata/payments"')
    page.get_by_role("button", name="Preview on Vault A · app-config/payments").click()
    expect(cell(page, "payments/db", 1)).to_have_text("✓")
    expect(cell(page, "payments/db", 2)).to_have_text("·")

    page.get_by_role("button", name="Write or download…").click()
    dialog = page.get_by_role("dialog", name="Download for an admin")
    dialog.get_by_label("OpenTofu").check()
    with page.expect_download() as dl:
        dialog.get_by_role("button", name="Download zip").click()
    path = tmp_path / "b.zip"
    dl.value.save_as(path)
    names = zipfile.ZipFile(path).namelist()
    assert "policies/payments-reader.hcl" in names and "apply.sh" in names and "opentofu/versions.tf" in names


def test_suggest_from_the_layout_and_keep_a_profile(page, sandbox):
    open_build(page)
    page.get_by_role("button", name="Suggest policies for app-config/services").click()
    box = page.locator(".suggest-box")
    expect(box).to_contain_text("{app}/{env}/**")
    expect(box).to_contain_text("billing-prod-app")
    box.get_by_role("button", name="None").click()
    box.locator("label", has_text="billing-prod-app").locator("input").check()
    box.get_by_role("button", name="Add 1 to my policies").click()
    expect(page.get_by_role("navigation", name="My policies")).to_contain_text("billing-prod-app")
    expect(page.get_by_label("Generated HCL")).to_contain_text("app-config/data/services/billing/prod/*")

    # A pattern of your own
    page.get_by_role("button", name="Use my pattern…").click()
    page.get_by_label("Suggestion pattern").fill("layout: '{app}/**'\npolicies:\n  - name: '{app}-ro'\n    rules: [{where: '{app}/**', can: [read]}]\n")
    page.get_by_role("button", name="Suggest with this pattern").click()
    expect(page.locator(".suggest-box")).to_contain_text("billing-ro")
    expect(page.locator(".suggest-box")).to_contain_text("search-ro")


def open_roles(page, prefix="payments", both=False):
    sign_in_userpass(page, "left", "alice", vault="Vault A")
    choose_mount(page, "left", "app-config", prefix)
    if both:
        sign_in_userpass(page, "right", "alice", vault="Vault B")
    page.get_by_role("tab", name="Policies", exact=True).click()
    page.get_by_role("tab", name="Roles", exact=True).click()


def test_roles_on_a_mount_explain_and_granting(page, sandbox):
    open_roles(page)
    page.get_by_label("Auth mount for roles").select_option("jwt")
    editor = page.get_by_label("Role default")
    expect(editor).to_contain_text("auth/jwt/role/default")
    expect(editor).to_contain_text("User claim")
    expect(editor).to_contain_text("Only the audience is checked")
    editor.get_by_role("button", name="What can it do on app-config/payments?").click()
    expect(cell(page, "payments/db", 1)).to_have_text("✓")  # lockstep-readonly reads everything
    expect(cell(page, "payments/db", 2)).to_have_text("·")

    page.get_by_label("Which roles grant a policy").fill("lockstep-readonly")
    page.get_by_label("Which roles grant a policy").press("Enter")
    expect(page.locator(".notice.info", has_text="is given by")).to_contain_text("auth/jwt/role/default")
    expect(page.locator(".notice.info", has_text="is given by")).to_contain_text("auth/oidc/role/default")


def test_compare_roles_and_build_one(page, sandbox, tmp_path):
    import zipfile
    open_roles(page, both=True)
    page.get_by_role("tab", name="Compare across Vaults").last.click()
    page.get_by_label("Left auth mount").select_option("jwt")
    page.get_by_label("Right auth mount").select_option("jwt")
    page.get_by_role("button", name="Compare roles").click()
    expect(page.locator(".policy-roles")).to_contain_text("1 equal")

    page.get_by_role("tab", name="New role").click()
    page.get_by_role("button", name="＋ GitLab CI job (id_tokens)").click()
    page.get_by_label("Role name").fill("deploy-payments")
    editor = page.get_by_label("Role editor")
    chosen = editor.get_by_role("group", name="Role policies")
    chosen.get_by_role("button", name="lockstep-limited", exact=True).click()  # an existing policy, picked
    expect(chosen.get_by_role("button", name="root", exact=True)).to_have_count(0)
    editor.get_by_label("Add a policy name to Role policies").fill("not-there")
    editor.get_by_label("Add a policy name to Role policies").press("Enter")  # one that doesn't exist yet
    expect(chosen.get_by_role("button", name=re.compile("^not-there"))).to_have_attribute("aria-pressed", "true")
    expect(chosen.get_by_role("button", name=re.compile("^not-there"))).to_contain_text("not on this Vault")
    expect(page.get_by_label("Role JSON")).to_contain_text('"lockstep-limited"')
    expect(editor).to_contain_text("No such policy on this Vault: not-there")
    expect(page.get_by_label("Role JSON")).to_contain_text('"project_path": "mygroup/my-app"')
    with page.expect_download() as dl:
        page.get_by_role("button", name="Download for an admin…").click()
    path = tmp_path / "r.zip"
    dl.value.save_as(path)
    assert "roles/jwt/deploy-payments.json" in zipfile.ZipFile(path).namelist()


def test_write_a_built_policy_to_vault(page, sandbox, vault_a):
    name = f"e2e-write-{sandbox.replace('/', '')[-6:]}"
    try:
        open_build(page, prefix="payments")
        page.get_by_role("button", name="＋ New policy").click()
        page.get_by_label("Policy name").fill(name)
        page.get_by_label("Rule 1 where").fill("payments/**")
        expect(page.get_by_label("Generated HCL")).to_contain_text("payments")
        page.get_by_role("button", name="Write or download…").click()
        page.get_by_role("dialog", name="Download for an admin").get_by_role("button", name="Write to Vault A · app-config/payments…").click()
        dialog = page.get_by_role("dialog", name="Write policies and roles")
        expect(dialog.locator(".plan")).to_contain_text("new")
        dialog.locator("label.confirm input").check()
        dialog.get_by_role("button", name="Write", exact=True).click()
        expect(dialog.locator(".badge", has_text="Done")).to_have_count(1)
        assert "app-config/data/payments/*" in vault_a.c.get(f"sys/policies/acl/{name}").json()["data"]["policy"]
    finally:
        vault_a.c.delete(f"sys/policies/acl/{name}")


def test_copy_a_policy_across_and_delete_a_role(page, sandbox, vault_a, vault_b):
    tag = sandbox.replace("/", "")[-6:]
    name = f"e2e-copy-{tag}"
    vault_a.c.put(f"sys/policies/acl/{name}", json={"policy": 'path "app-config/data/dev/*" { capabilities = ["read"] }'}).raise_for_status()
    vault_a.c.post(f"auth/jwt/role/e2e-del-{tag}", json={"role_type": "jwt", "user_claim": "sub", "bound_subject": "x",
                                                          "token_policies": ["default"]}).raise_for_status()
    try:
        sign_in_userpass(page, "left", "alice", vault="Vault A")
        sign_in_userpass(page, "right", "alice", vault="Vault B")
        page.get_by_role("tab", name="Policies", exact=True).click()
        page.get_by_role("tab", name="Compare across Vaults").first.click()
        page.get_by_role("button", name="Compare policies").click()
        page.get_by_placeholder("Filter by name…").fill(name)
        pair = page.locator(".policy-pair")
        pair.locator(".pair-head").click()
        pair.get_by_role("button", name="Copy to right →").click()
        dialog = page.get_by_role("dialog", name="Write policies and roles")
        dialog.locator("label.confirm input").check()
        dialog.get_by_role("button", name="Write", exact=True).click()
        expect(dialog.locator(".badge", has_text="Done")).to_have_count(1)
        dialog.get_by_role("button", name="Close").last.click()
        expect(page.locator(".policy-pair")).to_have_count(0)  # now equal, so not among the changes
        assert vault_b.c.get(f"sys/policies/acl/{name}").status_code == 200

        page.get_by_role("tab", name="Roles", exact=True).click()
        page.get_by_label("Auth mount for roles").select_option("jwt")
        page.get_by_role("navigation", name="Roles").get_by_role("button", name=f"e2e-del-{tag}").click()
        page.get_by_role("button", name="Delete role…").click()
        dialog = page.get_by_role("dialog", name="Write policies and roles")
        dialog.get_by_label("Confirmation phrase").fill(f"delete jwt/e2e-del-{tag}")
        dialog.get_by_role("button", name="Delete", exact=True).click()
        expect(dialog.locator(".badge", has_text="Done")).to_have_count(1)
        assert vault_a.c.get(f"auth/jwt/role/e2e-del-{tag}").status_code == 404
    finally:
        vault_a.c.delete(f"sys/policies/acl/{name}")
        vault_b.c.delete(f"sys/policies/acl/{name}")
        vault_a.c.delete(f"auth/jwt/role/e2e-del-{tag}")


def test_explain_someone_else_and_groups(page, sandbox, vault_a):
    tag = sandbox.replace("/", "")[-6:]
    alice = vault_a.c.get("identity/entity/name/alice").json()["data"]["id"]
    vault_a.c.post("identity/group", json={"name": f"e2e-g-{tag}", "policies": ["lockstep-limited"],
                                           "member_entity_ids": [alice]}).raise_for_status()
    try:
        open_build(page, prefix="payments")
        page.get_by_role("tab", name="Explain on a mount").click()
        page.get_by_role("tab", name="Someone else").click()
        page.get_by_label("Who").select_option("entity")
        page.get_by_label("Name or accessor").fill("alice")
        page.get_by_role("button", name="Explain", exact=True).click()
        sources = page.locator(".identity-sources")
        expect(sources).to_contain_text("entity alice")
        expect(sources).to_contain_text(f"e2e-g-{tag}")
        expect(cell(page, "payments/db", 1)).to_have_text("✓")

        page.get_by_role("tab", name="Roles", exact=True).click()
        page.get_by_label("Auth mount for roles").select_option("__groups__")
        page.get_by_role("navigation", name="Groups").get_by_role("button", name=f"e2e-g-{tag}").click()
        group = page.get_by_label(f"Group e2e-g-{tag}")
        expect(group).to_contain_text("alice")
        group.get_by_role("button", name="What can its members do on app-config?").click()
        expect(cell(page, "payments/api", 1)).to_have_text("✗")
        page.get_by_label("Which roles grant a policy").fill("lockstep-limited")
        page.get_by_label("Which roles grant a policy").press("Enter")
        expect(page.locator(".notice.info", has_text="is given by")).to_contain_text(f"group e2e-g-{tag}")
    finally:
        vault_a.c.delete(f"identity/group/name/e2e-g-{tag}")


def test_approle_role_and_issue_a_secret_id(page, sandbox, vault_a):
    tag = sandbox.replace("/", "")[-6:]
    mount = f"e2e-approle-{tag}"
    vault_a.c.post(f"sys/auth/{mount}", json={"type": "approle"}).raise_for_status()
    vault_a.c.post(f"auth/{mount}/role/ci", json={"token_policies": ["lockstep-readonly"]}).raise_for_status()
    try:
        open_roles(page)
        page.get_by_label("Auth mount for roles").select_option(mount)
        role = page.get_by_label("Role ci")
        expect(role).to_contain_text("Secret IDs never expire")
        role.get_by_role("button", name="Issue a secret ID…").click()
        page.get_by_role("region", name="Issue a secret ID").get_by_role("button", name="Issue").click()
        issued = page.get_by_role("region", name="Issued secret ID")
        token = issued.get_by_label("Wrapped secret ID").inner_text()
        assert len(token) > 20
        unwrapped = vault_a.c.post("sys/wrapping/unwrap", headers={"X-Vault-Token": token}).json()["data"]
        assert unwrapped["secret_id"]
    finally:
        vault_a.c.delete(f"sys/auth/{mount}")


def test_save_an_access_plan_and_apply_it_as_someone_else(page, sandbox, vault_a, tmp_path):
    """Bob can't write policies: he saves an access plan; alice opens, checks and applies it."""
    name = f"e2e-plan-{sandbox.replace('/', '')[-6:]}"
    try:
        sign_in_userpass(page, "left", "bob", vault="Vault A")
        choose_mount(page, "left", "app-config", "payments")
        page.get_by_role("tab", name="Policies", exact=True).click()
        page.get_by_role("tab", name="Build & suggest").click()
        page.get_by_role("button", name="＋ New policy").click()
        page.get_by_label("Policy name").fill(name)
        page.get_by_label("Rule 1 where").fill("payments/**")
        expect(page.get_by_label("Generated HCL")).to_contain_text("payments")
        page.get_by_role("button", name="Write or download…").click()
        dialog = page.get_by_role("dialog", name="Download for an admin")
        with page.expect_download() as dl:
            dialog.get_by_role("button", name="Save as access plan").click()
        expect(dialog.get_by_role("status")).to_contain_text("Saved access plan")
        path = tmp_path / dl.value.suggested_filename
        dl.value.save_as(path)
        assert path.name.startswith("lockstep-access-plan-")
        dialog.get_by_role("button", name="Cancel").click()

        sign_in_userpass(page, "right", "alice", vault="Vault A")
        page.get_by_label("Open an access plan").set_input_files(str(path))
        review = page.get_by_role("dialog", name="Write policies and roles")
        expect(review).to_contain_text("Made by userpass-bob")
        expect(review.locator(".plan")).to_contain_text("Will be written")
        review.locator("label.confirm input").check()
        review.get_by_role("button", name="Write", exact=True).click()
        expect(review.locator(".badge", has_text="Done")).to_have_count(1)
        assert "app-config/data/payments/*" in vault_a.c.get(f"sys/policies/acl/{name}").json()["data"]["policy"]
    finally:
        vault_a.c.delete(f"sys/policies/acl/{name}")


def test_try_a_draft_policy_for_real(page, sandbox, vault_a):
    open_build(page, prefix="payments")
    page.get_by_role("button", name="＋ New policy").click()
    page.get_by_label("Policy name").fill("try-me")
    page.get_by_label("Rule 1 where").fill("payments/**")
    expect(page.get_by_label("Generated HCL")).to_contain_text("payments")
    page.get_by_role("button", name="Try for real on Vault A · app-config/payments").click()
    note = page.get_by_role("status").filter(has_text="Tried for real")
    expect(note).to_contain_text("agrees with Vault everywhere")
    expect(cell(page, "payments/db", 1)).to_have_text("✓")
    keys = vault_a.c.request("LIST", "sys/policies/acl").json()["data"]["keys"]
    assert not [k for k in keys if k.startswith("lockstep-try-")]


def test_edit_a_groups_policies(page, sandbox, vault_a):
    tag = sandbox.replace("/", "")[-6:]
    name = f"e2e-ge-{tag}"
    vault_a.c.post("identity/group", json={"name": name, "policies": ["lockstep-limited"]}).raise_for_status()
    try:
        open_roles(page)
        page.get_by_label("Auth mount for roles").select_option("__groups__")
        page.get_by_role("navigation", name="Groups").get_by_role("button", name=name).click()
        group = page.get_by_label(f"Group {name}")
        group.get_by_role("button", name="Edit policies").click()
        chosen = group.get_by_role("group", name="Group policies")
        expect(chosen.get_by_role("button", name="lockstep-limited", exact=True)).to_have_attribute("aria-pressed", "true")
        chosen.get_by_role("button", name="lockstep-readonly", exact=True).click()
        group.get_by_role("button", name="Review…").click()
        dialog = page.get_by_role("dialog", name="Write policies and roles")
        expect(dialog.locator(".plan")).to_contain_text("+lockstep-readonly")
        dialog.locator("label.confirm input").check()
        dialog.get_by_role("button", name="Write", exact=True).click()
        expect(dialog.locator(".badge", has_text="Done")).to_have_count(1)
        dialog.get_by_role("button", name="Close").last.click()
        expect(group).to_contain_text("lockstep-limited, lockstep-readonly")
        assert sorted(vault_a.c.get(f"identity/group/name/{name}").json()["data"]["policies"]) == ["lockstep-limited", "lockstep-readonly"]
    finally:
        vault_a.c.delete(f"identity/group/name/{name}")


def test_userpass_users_compare_and_reset(page, sandbox, vault_a):
    import httpx
    from conftest import VAULT_A
    name = f"e2e-u-{sandbox.replace('/', '')[-6:]}"
    vault_a.c.post(f"auth/userpass/users/{name}", json={"password": "old-password", "token_policies": "default"}).raise_for_status()
    try:
        open_roles(page, both=True)
        page.get_by_label("Auth mount for roles").select_option("__users__:userpass")
        users = page.get_by_role("region", name="Userpass users")
        expect(users).to_contain_text("svc-ci")
        page.get_by_role("button", name="Compare with Vault B").click()
        compared = page.get_by_role("region", name="Compared users")
        expect(compared.locator("tr", has_text="svc-ci").locator(".badge")).to_have_text("Different")
        expect(compared.locator("tr", has_text=name).locator(".badge")).to_have_text("Left only")
        users.locator("tr", has_text=name).get_by_role("button", name="Reset password…").click()
        form = page.get_by_role("region", name=f"Reset {name}'s password")
        form.get_by_role("button", name="Reset password").click()
        shown = form.locator("code.reveal-once")
        expect(shown).to_have_count(1)
        pw = shown.inner_text()
        assert httpx.post(f"{VAULT_A}/v1/auth/userpass/login/{name}", json={"password": pw}).status_code == 200

        page.get_by_label("Auth mount for roles").select_option("__users__:ldap")
        groups = page.get_by_role("region", name="LDAP group mappings")
        expect(groups.locator("tr", has_text="payments-devs")).to_contain_text("payments-dev")
    finally:
        vault_a.c.delete(f"auth/userpass/users/{name}")


def test_create_a_userpass_user_with_chosen_policies(page, sandbox, vault_a):
    name = f"e2e-nu-{sandbox.replace('/', '')[-6:]}"
    try:
        open_roles(page)
        page.get_by_label("Auth mount for roles").select_option("__users__:userpass")
        page.get_by_role("button", name="＋ New user").click()
        form = page.get_by_role("region", name="New userpass user")
        form.get_by_label("Username").fill(name)
        chosen = form.get_by_role("group", name="User policies")
        chosen.get_by_role("button", name="lockstep-readonly", exact=True).click()
        chosen.get_by_role("button", name="lockstep-limited", exact=True).click()
        chosen.get_by_role("button", name="lockstep-limited", exact=True).click()  # and changed their mind
        expect(form).to_contain_text("1 chosen: lockstep-readonly")
        form.get_by_role("button", name="Create user").click()
        expect(form.locator("code.reveal-once")).to_have_count(1)
        assert vault_a.c.get(f"auth/userpass/users/{name}").json()["data"]["token_policies"] == ["lockstep-readonly"]
    finally:
        vault_a.c.delete(f"auth/userpass/users/{name}")
