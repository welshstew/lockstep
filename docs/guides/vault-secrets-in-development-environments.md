<!-- description: Lockstep's main use case: keeping Vault KV secrets in step across development, test and preview environments, standing up new ones, and cleaning up after them. -->
# Lockstep for development environments

Lockstep was built for development teams first. Production Vaults usually have pipelines, change control and few people allowed to touch them. Development environments are different: several of them (dev, test, integration, a preview per branch, a local Vault on each laptop), many people writing to them, and secrets that drift apart a little every week. Most "works in dev, fails in test" problems with secrets come from that drift.

This guide covers the jobs Lockstep does in those environments, and which feature to use for each.

## Find out why one environment behaves differently

A service starts in dev and fails in test. The code is the same, so the difference is usually configuration: a key missing in test, a URL still pointing at the old database, `5432` stored as a string in one place and a number in the other.

1. Connect the dev Vault on the left and the test Vault on the right (or two mounts or prefixes in one Vault).
2. Press **Compare**. Each secret shows as *Equal*, *Different*, *Left only* or *Right only*. Values stay hidden: you see that `db/password` differs without anyone's password on screen.
3. Open a secret to see which keys differ and when each one last changed on each side. **Show values** reveals them for the secrets you open, if you need to.

If your environments use different layouts (`services/*/dev/**` and `services/*/test/**`), a [comparison profile](build-a-comparison-profile.md) pairs the paths up and ignores the keys that are *meant* to differ, such as hostnames. Then only real drift is left.

## Bring an environment back in step

Once you can see the differences, fix them from the same screen:

- **← / →** copies a key or a whole secret to the other side. **all to right →** on a folder, or on everything matching the filter, copies a whole service's secrets in one go.
- **Edit** puts a value in place, starting from the other side's. Use it for values that should be *similar* but not the same, like a test-specific URL.
- **Delete** removes a key that shouldn't be there any more.

Everything goes through one review that shows exactly what each target secret will get. Writes use check-and-set, so if a teammate changed the same secret in the meantime, you get a conflict instead of overwriting their work. Every write is audit-logged without values, so you can tell afterwards who changed what in a shared dev Vault.

## Stand up a new environment from an existing one

A new test environment, a branch preview or a new developer's local Vault usually needs "the same secrets as dev, with dev replaced by test".

1. **Export** the dev mount (or just a prefix) to an encrypted file from the **Export & import** tab, leaving out paths and keys that shouldn't travel, such as personal tokens.
2. **Import** it into the new Vault with rules: replace `dev` with `test` in paths and values, add a prefix, change case. The preview shows every secret and key before anything is written.
3. Compare the two afterwards to check the result.

The [export and import guide](export-import-vault-secrets.md) walks through it. The same export works as a snapshot: compare a Vault against it later to see what changed since.

For a local Vault in dev mode (for example in a Compose file), import the team's export at startup, and you have realistic secrets without anyone pasting them into a `.env` file.

## Clean up afterwards

Development environments pile up secrets: services that were renamed, test data from a spike, a whole preview environment that's been merged.

- **Make the target match the file** on an import soft-deletes secrets the file doesn't have, so a test environment can be reset to exactly what dev exports. `vault kv undelete` brings them back.
- **Destroy** removes a secret for good: every version and its metadata. **Destroy all on left / right** does it for every secret shown, so filter to a prefix (`preview-123/`), check the list and destroy it. You have to type a confirmation phrase first, and there's no undo, so export first if you might need it.

A server admin can turn destroying off with `LOCKSTEP_ALLOW_DESTROY=false`; Vault's own policies still decide who may destroy what.

## Catch problems before they reach production

- **Drift checks in CI.** `lockstep compare` exits with 1 when two environments differ. Run it with a read-only token, for example after each deploy to test, to find out early that staging is missing a key that test has. See [detecting drift in CI](detect-vault-secret-drift-in-ci.md).
- **Certificate expiry.** Development certificates expire too, often unnoticed until something breaks. The **Certificate expiry** tab lists every certificate in a mount, including ones inside keystores, by time to expiry.
- **Sync plans for the last step.** When a change has been tried in dev and needs to go further, save the reviewed changes as a [sync plan](sync-vault-secrets-between-environments.md). Someone with write access to the next environment checks it and applies it. If anything changed since the plan was made, nothing is written.

## A suggested setup

- Run Lockstep where your developers can reach your development Vaults: the [Helm chart](../kubernetes.md) for a shared cluster, or the container image locally.
- Let people sign in with their own identity (OIDC, LDAP or userpass) so Vault policies, and the audit log, apply per person.
- Keep a shared [comparison profile](build-a-comparison-profile.md) per pair of environments, so everybody sees the same differences.
- Give production read-only access at most, and send any changes there through sync plans or your normal pipeline.
