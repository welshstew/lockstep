<!-- description: Compare KV v2 secrets between two HashiCorp Vault clusters, mounts or environments: the vault CLI approach and its limits, then Lockstep. -->
# How to compare secrets between two HashiCorp Vault clusters

Sooner or later you need to know how two Vaults differ. Staging and production drift apart. A migration to a new cluster needs checking. A disaster-recovery copy has to match the primary. Or someone asks whether the `payments` secrets are the same everywhere.

Vault has no built-in way to compare one KV v2 secrets engine with another. This guide covers the do-it-yourself approach and its limits, then how to do it with [Lockstep](https://getlockstep.cloud), an open-source tool built for this job.

## Comparing by hand with the vault CLI

For a single secret, the `vault` CLI and `jq` are enough:

```sh
diff \
  <(VAULT_ADDR=https://vault-prod.example.com vault kv get -format=json -mount=app-config payments/db | jq -S .data.data) \
  <(VAULT_ADDR=https://vault-staging.example.com vault kv get -format=json -mount=app-config payments/db | jq -S .data.data)
```

`jq -S` sorts the keys, so only real differences show. It also keeps the types, so a port stored as `5432` on one side and `"5432"` on the other shows up as a difference.

It gets harder as soon as you need more than one secret:
- **No recursive listing.** `vault kv list` shows one folder at a time, so you have to walk the tree yourself and handle folders you're not allowed to list.
- **Values everywhere.** The diff prints secret values to your terminal, and whatever you pipe it into: logs, CI output, a ticket.
- **Two tokens.** Two clusters usually mean two logins, and a script that keeps track of which token goes with which address.
- **Missing isn't the same as forbidden.** A secret your token can't read looks exactly like one that doesn't exist. A script that copies "missing" secrets can overwrite something it never saw.
- **Different layouts.** If production keeps `services/billing/prod/db` and staging keeps `services/billing/staging/db`, a plain path-by-path diff pairs nothing.

## Comparing with Lockstep

Lockstep compares two KV v2 locations in one go: two clusters, two mounts in one Vault, or two path prefixes. It reads both sides, compares the values in one place, and reports a status for every secret and every key, without showing any values unless you ask.

### In the browser

Run it with Helm or Docker (see [Install](https://getlockstep.cloud/#install)), or try the [live demo](https://demo.getlockstep.cloud):
1. Connect each side to its Vault. It supports token, userpass, LDAP, OIDC, or a Kubernetes service account.
2. Pick a mount and, optionally, a prefix on each side.
3. Press **Compare**.

Every secret gets one status:

| Status | Meaning |
|---|---|
| **Equal** | Same keys, same values (key order and versions don't count) |
| **Different** | At least one key differs. Expanding the row shows which ones, including type changes like `5432` vs `"5432"` |
| **Left only** / **Right only** | The secret exists on one side only |
| **No access** | You can't list or read it on at least one side. It's never shown as one-sided, so nobody copies over something they couldn't see |

Values stay hidden until you turn on **Show values**, and then only for the secrets you open. The browser receives only a status per key.

### On the command line

The same comparison runs from a terminal with the [`lockstep` CLI](../cli.md), which logs in the way the `vault` CLI does:

```sh
pipx install "git+https://github.com/welshstew/lockstep@v0.3.0#subdirectory=backend"

lockstep compare \
  --left-addr https://vault-prod.example.com --left-name prod \
  --right-addr https://vault-staging.example.com --right-name staging \
  --mount app-config -o report.yaml
```

It prints a summary of what differs and writes a YAML report. The report has no values, but for every secret it gives both sides' versions, a link to the secret in the Vault UI, and the exact `vault kv get` command to look at it. That makes it easy to hand to someone else as a list of what needs checking.

### When the two sides aren't laid out the same

A **comparison profile** maps paths between environments, for example `services/*/prod/**` ⇄ `services/*/staging/**`. It can also ignore keys that are meant to differ, such as a `host` that's different in each environment. Ignored differences still show, marked *ignored*, but they don't make a secret *Different*. Profiles work in the web UI and with `lockstep compare --profile`. See [Comparison profiles](../usage.md#comparison-profiles).

## Permissions

Comparing needs read-only access: `list` and `read` on the mount's metadata, and `read` on its data. The [security guide](../security.md#vault-policies) has a ready-made policy. Lockstep never needs more than the person or role using it already has.

## Next steps

- [Syncing secrets between Vault environments safely](sync-vault-secrets-between-environments.md)
- [Detecting secret drift between Vault environments in CI](detect-vault-secret-drift-in-ci.md)
- [Try the live demo](https://demo.getlockstep.cloud): sign in as `alice` / `password` on both sides, choose `app-config`, then press Compare.
