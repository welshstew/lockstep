<!-- description: Promote HashiCorp Vault or OpenBao secrets from dev to prod with guardrails: a write policy per Vault, signed sync plans that travel between Lockstep installations, a second person's approval, and an undo plan. -->
# Promoting secrets from dev to prod with approvals

A secret change usually starts in a lower environment: a new key for a feature, a rotated URL, a value someone fixed in test. Getting it into production safely is a people problem as much as a technical one:
- the person who knows what should change often isn't allowed to write to prod;
- the person who is allowed shouldn't have to redo the work, or trust a copy-paste;
- someone else should look before it happens;
- and if it goes wrong, there should be a way back.

This guide sets up [Lockstep](https://getlockstep.cloud) so that changes are prepared in one place, checked by a second person and applied in another, with each step signed and audit-logged. Every part is optional: take the ones you need.

## The flow

1. **A developer compares** dev (or staging) with prod and stages the copies prod needs. They don't need write access to prod.
2. **They save a sync plan:** a signed file listing paths, keys, directions and the versions they saw. It holds no copied values.
3. **A reviewer approves it.** They open the plan, check it against both Vaults, and approve. The approval is signed into the file.
4. **A prod operator applies it.** Lockstep checks that nothing has changed since the plan was made, that the approval is valid, and writes with check-and-set.
5. **If it goes wrong,** an undo plan puts back what the apply replaced.

## 1. Decide what Lockstep may write, per Vault

Vault's policies decide what each person may do. On top of them, each Vault offered by Lockstep can have its own rules, so one installation can compare prod and write only to dev:

```json
[{"name": "Prod", "url": "https://vault.prod.example.com", "approvals": 1, "allow_destroy": false},
 {"name": "Dev", "url": "https://vault.dev.example.com", "write_paths": ["app-config/**"]}]
```

- **`"approvals": 1`** on Prod means it changes **only** through approved plans. Direct copies, Browse edits, imports and destroys are refused, and so are policy and role writes from the Policies tab, so the approval can't be gone round. The reviews still offer **Save as plan** and **Save as access plan**.
- **`writable: false`** makes a Vault compare-only. **`write_paths`** and **`deny_paths`** limit writes to some paths (`*` is one path segment, `**` any number), and **`allow_destroy: false`** turns off Destroy there.
- Typing a preset's address by hand doesn't get round its rules: they follow the Vault's address, and where several presets share one, the strictest wins.

Set this as `LOCKSTEP_PRESET_CONNECTIONS` (chart: `vaults`). Every refusal is audit-logged as `write.refused`. See [write policy per Vault](../configuration.md#write-policy-per-vault).

## 2. Save a sync plan

Sign in to dev on one side and prod on the other, and compare. Use a [comparison profile](build-a-comparison-profile.md) if the two are laid out differently: plans follow its path mappings and value rewrites.

Stage the copies prod needs, open **Review & apply…**, add a note saying why, and choose **Save as plan**. Lockstep downloads `lockstep-plan-<date>-<id>.json` and **Download report** gives the same as a Markdown table for a ticket or a pull request.

What the plan holds:
- each secret's source and target path, the keys added, updated or removed, and the versions of both sides when the plan was made;
- who made it, with their Vault entity ID and token accessor (identifiers a token can't choose);
- when it expires (7 days by default) and, optionally, which installations may apply it.

What it doesn't hold: **values**. Copied values are read from the source when the plan is applied. A value you typed yourself, such as a new password, is kept only as a check code: whoever applies the plan types it again, and Lockstep refuses one that doesn't match.

## 3. Let plans travel from dev's Lockstep to prod's

If dev and prod each have their own Lockstep, the plan has to be trusted by the one that applies it. Give the installation that makes plans an Ed25519 key pair:

```sh
lockstep plan-key
# LOCKSTEP_PLAN_SIGNING_KEY=…         (on dev's Lockstep, from a secret store)
# LOCKSTEP_PLAN_TRUSTED_KEYS=[…]      (on prod's Lockstep)
```

- **On dev's Lockstep:** `LOCKSTEP_PLAN_SIGNING_KEY` (chart `plans.signingKeySecret`) and a name, `LOCKSTEP_PLAN_ISSUER=dev-lockstep`.
- **On prod's Lockstep:** `LOCKSTEP_PLAN_TRUSTED_KEYS='[{"name": "dev-lockstep", "key": "<public key>"}]'` (chart `plans.trustedKeys`).

Prod's Lockstep then verifies plans from dev's, and refuses one signed by a key it doesn't trust, one that has expired, or one whose audience doesn't name it. A single installation needs none of this. See [plans between installations](../configuration.md#plans-between-installations).

## 4. Have someone else approve it

Turn approvals on for the Vaults that need them (`"approvals": 1` on the preset, as above), or for every plan applied on an installation with `LOCKSTEP_PLAN_APPROVALS=1` (chart `plans.approvals`).

The reviewer opens the plan in **Sync plans**, signs in to both Vaults (read access is enough), and chooses **Check plan**. Lockstep reads both sides now and shows exactly what would change. If it looks right, **Approve** adds a signed approval to the file and downloads `…-approved.json` to pass on.

- **Who counts:** someone whose Vault entity differs from the plan's creator on every Vault the plan writes. Entities are compared, not display names, so signing in under another name doesn't help.
- **How many, and who:** `"approvals": 2` (up to 5) asks for that many different people. `"approver_policies": ["lockstep-approver"]` on the preset, or `LOCKSTEP_PLAN_APPROVER_POLICIES`, lets only people holding one of those Vault policies approve. Attach the policy to a Vault identity group (say `prod-approvers`) and group membership decides who can approve. A root token has no entity and can't approve.
- **An approval can't change the plan.** It sits outside the plan's signature, which stays as it was, and an edited approval doesn't count.
- The audit log records `plan.approve` with the approver's entity IDs. See [four-eyes approvals](../configuration.md#four-eyes-approvals).

## 5. Apply it

The prod operator opens the approved file in **Sync plans**, signs in to both Vaults with write access to the targets, and chooses **Check plan**, then **Apply plan**.

- **If any source or target changed** since the plan was made, nothing is written, and the plan has to be made again from a fresh comparison.
- **Every write uses check-and-set.** If something changes in the moment between the check and a write, applying stops there and says **Partially applied: N of M written**, naming the secret it stopped at.
- Each write is audit-logged with the plan's ID (`sync.apply`), never with values.

## 6. If it goes wrong: undo

Under the plan's result, **Make an undo plan** downloads a signed file that puts back what the apply did. It holds no values either: it records the version each secret had before, and Lockstep reads that version back from Vault's history when you apply it.

Open it in **Sync plans**, **Check undo plan**, then **Apply undo plan**. Where approvals are required, an undo plan needs one too: someone else checks it and chooses **Approve**, as for the plan it undoes. A secret someone has written since the apply, or whose old version has been deleted or destroyed, is left alone and reported. See [undo an apply](../usage.md#undo-an-apply).

## Policies and roles too

The same flow works for access: someone prepares policy or role changes in **Policies** and chooses **Save as access plan**, a reviewer opens it with **Policies → Open an access plan…** and chooses **Approve**, and an admin applies the approved file. On a Vault with `"approvals": 1`, that's the only way policies and roles change from Lockstep.

## What this isn't

Approvals are a check against mistakes, not a compliance control: up to five other people, chosen by Vault policy. For a full change-management process, keep the plan's Markdown report in your ticket or pull request, and use Vault's own audit log alongside Lockstep's.

## Next steps

- [Syncing Vault KV secrets between environments safely](sync-vault-secrets-between-environments.md): the rules every copy follows
- [Detecting secret drift between Vault environments in CI](detect-vault-secret-drift-in-ci.md): find what needs promoting before anyone asks
- [Configuration](../configuration.md#write-policy-per-vault): every setting used here
- [Try the live demo](https://demo.getlockstep.cloud): `alice` can write, `bob` is read-only. Both use the password `password`.
