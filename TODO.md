# TODO

Open items left over from the proposals in [docs/proposals](docs/proposals/). Each says where it came from. Finished work is in the [CHANGELOG](CHANGELOG.md).

## Promotion and governance

From [promotion-governance.md](docs/proposals/promotion-governance.md).

- [x] **Approvals for access plans and undo plans**, and a preset's `approvals` covering policy and role writes from the Policies tab.
- [x] **Undo plans for Browse edits and imports.**
- [x] **Approver groups and more than one approver:** up to 5 approvals from different people, and approver policies (granted through Vault groups).
- [x] **`audience` in the UI:** **Only for** when saving a sync or access plan, with the known server names suggested.
- [x] **Require one kind of export protection:** `LOCKSTEP_EXPORT_PROTECTION` and a preset's `export_protection` (key, passphrase, age, teams).

## Continuous drift

From [continuous-drift.md](docs/proposals/continuous-drift.md).

- [ ] **Try the GitHub Action on real GitHub** (`uses: welshstew/lockstep@v0.12.0`). It's tested locally, but has never run in a GitHub workflow.
- [x] **Sign drift baselines** (and waivers) with the plan key: `--sign`, `baseline sign`, `waivers sign`, `--require-signed`.
- [ ] **Scheduling inside the app** (phase 7). It was skipped: the chart's `driftCheck` CronJob and CI cover scheduled checks.

## Vault Enterprise and the dev stack

- [ ] **Licence expiry** ([vault-enterprise.md](docs/proposals/vault-enterprise.md)). This is blocked until there's an Enterprise licence to test with. Namespaces are done and tested on OpenBao.
- [x] **Move the dev stack to Vault 2.x** ([vault-2-dev-stack.md](docs/proposals/vault-2-dev-stack.md)): 2.2.2, with `vault-legacy` (1.21.4) for the 1.x matcher rules. The screenshots follow in their own PR.

## Ideas, not started

- [ ] **Connection probes** ([connection-probes.md](docs/proposals/connection-probes.md)). Check that database, LDAP and HTTP credentials stored in Vault still work.
