# Moving the dev stack to Vault 2.x

**Status:** done (2026-11-27): Vault 2.2.2 by digest, `vault-legacy` on 1.21.4, the weekly job sets `VAULT_IMAGE` (vault-a and vault-b) · **Written:** 2026-11-22 · **Owner:** unassigned

The dev and demo stacks run Vault **1.21.4** for `vault-a` and `vault-b`. Only the test-only `vault-latest` runs **2.2.2**, which checks the policy matcher. This plan covers moving the everyday stack to 2.x and what that changes. It's implemented: see the status above, and the CHANGELOG.

## Why

- New users try Lockstep against the newest Vault first. The demo and the screenshots show an older release.
- Vault 2.2.2 changed how policies match: trailing slashes, and case-insensitive `deny`. Lockstep follows both rule sets (`lockstep/policy/acl.py`). Today, though, the 2.x rules are exercised only by the matcher's differential tests. Every other test, and every manual check, runs on 1.21's rules.
- The weekly `vault-release` workflow will keep reporting newer releases, and the gap between the dev stack and current Vault will keep growing.

## What a trial run showed

On 2026-11-22, I ran the whole stack with `vault-a` and `vault-b` on `hashicorp/vault:2.2.2`. It used a throwaway compose override, outside the repository:

| Check | Result on 2.2.2 |
| --- | --- |
| Seed (`dev/seed/seed.py`): KV, PKI, Transit, database, LDAP, userpass, OIDC, JWT, AppRole, identity, MFA fixtures | Runs unchanged |
| Backend tests (334) | 333 pass. The one failure is a test that asserts the version string starts with `1.21` (`test_explain_reports_the_vault_version`) |
| Browser tests (71, without Kubernetes) | All pass |
| Kubernetes profile (k3s, `seed_k8s.py`, `test_k8s_auth.py`) | Not run in the trial |

So the application itself needs no changes. The work is in pins, tests, docs and images.

## What needs to change

1. **compose.yaml**
   - Move the `x-vault` image from `docker.io/hashicorp/vault:1.21.4` to the 2.x release, pinned by its multi-arch index digest (see the image pinning note: CI is amd64).
   - Turn `vault-latest` into **`vault-legacy`** on `1.21.4`, so the 1.x evaluation rules (`LEGACY` in `acl.py`) keep a real Vault to be checked against. Rename `VAULT_LATEST_ADDR`/`root-latest` to match, and keep the `VAULT_LATEST_IMAGE` override for the weekly job. That job then sets the image of `vault-a`/`vault-b`, or of a separate `vault-next` service. Decide which.
2. **deploy/demo/compose.yaml:** the same image move. Re-run `scripts/deploy-demo.sh`. The demo's hourly reseed runs the same seed, which already works on 2.x.
3. **Tests**
   - `backend/tests/test_policies.py::test_explain_reports_the_vault_version`: expect `2.` and the 2.2.2+ evaluation note.
   - `backend/tests/test_policy_acl.py`: the "latest" tests point at `vault-legacy` and assert the legacy rules. The main differential tests then run on 2.x by default.
   - Run the Kubernetes profile (`--profile k8s`, `test_k8s_auth.py`, the k8s browser test) on 2.x before switching. That's the part the trial didn't cover.
4. **CI (`.github` and `.gitea` workflows):** no changes apart from the service rename. The `vault-release` workflow reads the pin from compose.yaml with a `sed` on `VAULT_LATEST_IMAGE:-…`, so it must follow whatever the variable and service end up being called.
5. **Screenshots:** `make screenshots`. The Configuration and Policies screenshots show the Vault version and "Matched like Vault …".
6. **Docs**
   - `docs/cli.md`'s sample output (`Vault 1.21.4 ⇄ Vault 2.2.2`).
   - `docs/development.md`/README, wherever they name the dev Vault version.
   - The bug report template's placeholder (`.github/ISSUE_TEMPLATE/bug_report.yml`).
   - `docs/usage.md` says who-wrote-it metadata needs 1.21+, which is still true, so it stays.
7. **CHANGELOG:** a "Changed" entry. It's a dev-stack change, not an app change.

## What doesn't change

- Lockstep keeps supporting 1.x Vaults. `behaviour_for()` picks the rules from each Vault's reported version, so a 1.21 Vault in production is matched with 1.21's rules whatever the dev stack runs.
- The Helm chart and the image are unaffected: the chart doesn't ship a Vault.

## Risks and checks

- **Dev-mode defaults.** A 2.x dev server could enable or tune something differently, such as default mounts or audit settings. The trial found nothing, but the configuration comparison's expected output (`test_vaultconfig.py`) would show it.
- **Plugin versions.** Built-in plugin versions change with the release. Configuration compare shows them, and both sides move together, so nothing should appear as drift.
- **Rollback:** the move is one image line per compose file. Revert the commit and recreate the containers; the dev Vaults are in-memory.

## Order of work

1. One PR containing:
   - the image move, with `vault-legacy` for 1.21.4 and the test adjustments;
   - a Kubernetes profile run;
   - the workflow rename;
   - the docs and the CHANGELOG.
2. A second PR with the regenerated screenshots, which keeps the first one reviewable.
3. Redeploy the demo.
