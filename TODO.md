# TODO

Open items left over from the proposals in [docs/proposals](docs/proposals/). Each says where it came from. Finished work is in the [CHANGELOG](CHANGELOG.md).

## Promotion and governance

From [promotion-governance.md](docs/proposals/promotion-governance.md).

- [ ] **Approvals for access plans and undo plans.** Only sync plans take approvals today. A preset's `approvals` doesn't cover policy and role writes either.
- [ ] **Undo plans for Browse edits and imports.** Today undo plans are offered only after copies and sync plans are applied.
- [ ] **Approver groups and more than one approver.** Approvals are one person, compared by Vault entity.
- [ ] **`audience` in the UI.** A plan can name the installations that may apply it, but only through the API.
- [ ] **Require one kind of export protection.** Admins can require encryption, but not a particular kind (for example age keys only).

## Continuous drift

From [continuous-drift.md](docs/proposals/continuous-drift.md).

- [ ] **Try the GitHub Action on real GitHub** (`uses: welshstew/lockstep@v0.11.0`). It's tested locally, but has never run in a GitHub workflow.
- [ ] **Sign drift baselines** with the plan signing key, so a baseline file can't be edited unnoticed.
- [ ] **Scheduling inside the app** (phase 7). It was skipped: the chart's `driftCheck` CronJob and CI cover scheduled checks.

## Vault Enterprise and the dev stack

- [ ] **Licence expiry** ([vault-enterprise.md](docs/proposals/vault-enterprise.md)). This is blocked until there's an Enterprise licence to test with. Namespaces are done and tested on OpenBao.
- [ ] **Move the dev stack to Vault 2.x** ([vault-2-dev-stack.md](docs/proposals/vault-2-dev-stack.md)).

## Ideas, not started

- [ ] **Connection probes** ([connection-probes.md](docs/proposals/connection-probes.md)). Check that database, LDAP and HTTP credentials stored in Vault still work.
