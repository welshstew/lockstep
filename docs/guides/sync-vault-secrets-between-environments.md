<!-- description: Sync Vault KV v2 secrets between environments without overwriting newer changes: check-and-set writes, no deletes, reviews and sync plans. -->
# Syncing Vault KV secrets between environments safely

Copying secrets from one Vault to another sounds simple: read here, write there. Most incidents with secrets don't come from the copy itself, though. They come from what it overwrote:
- a value someone had just rotated
- a key that existed only on the target
- a secret the person copying couldn't even see

This guide covers what can go wrong when you sync KV v2 secrets between environments or clusters, and how [Lockstep](https://getlockstep.cloud) avoids each problem.

## What can go wrong

- **Overwriting a newer change.** You compare on Monday and copy on Tuesday. Meanwhile someone rotated the target's password, and your copy puts the old one back.
- **Losing target-only keys.** Writing a whole secret replaces every key in it. If the target had an extra key, it's gone.
- **Copying blind.** A script treats "can't read" as "doesn't exist" and writes over data it never saw.
- **Values passing through too many hands.** Exporting secrets to a file to review or move them leaves copies on laptops, in tickets and in chat.
- **No record.** Afterwards nobody can say who changed what, or why.

## Rules that make a sync safe

Lockstep applies the same rules to every copy, from the web UI or the command line:
1. **Review first.** You stage copies key by key or secret by secret, in either direction. A review shows exactly what each target gets: which keys are added or updated, the version change, and whether you're allowed to write there.
2. **Check-and-set on every write.** Each write tells Vault which version it expects to replace (KV v2 `cas`). If the target changed since you compared, Vault rejects the write and Lockstep reports a conflict instead of overwriting.
3. **Merge, never delete.** Copied keys are merged into the target's current data. Keys that exist only on the target stay, and Lockstep never deletes a secret.
4. **Values read fresh from the source.** When you apply, Lockstep reads the source again and writes what's there. Copied values never pass through the browser or through a file. (To set a value yourself, such as a rotated password, use an **override**: it goes through the same review and check-and-set write.)
5. **Audit log without values.** Every write is logged with who made it, from where to where, the versions and the outcome, but never the values.
6. **"No access" is not "missing".** A secret you can't read on either side can't be copied.

## Three ways to apply a sync

### 1. Directly, in the web UI

Compare, stage copies with ← and →, review, then **Apply**. This suits someone who can read both sides and write to the target.

### 2. As a sync plan, for someone else to apply

Often the person who spots the differences isn't allowed to write to production. In the review, **Save as plan** downloads a signed file that holds paths, keys, directions and versions, never values. It also serves as a report of what needs updating, and from where.

Anyone with write access to the targets opens the plan in Lockstep, checks it against both Vaults, and applies it. **If anything in it changed since the plan was made, nothing is written**, and the plan has to be made again. See [Sync plans](../usage.md#sync-plans).

### 3. From the command line

`lockstep compare -o report.yaml` writes a YAML report of the differences. You set an action on the keys or secrets to copy, and `lockstep apply` carries them out:

```yaml
- path: payments/db
  status: different
  keys:
  - key: password
    status: different
    action: copy-to-right   # was: skip
```

```sh
lockstep apply report.yaml --dry-run   # what would be written
lockstep apply report.yaml             # asks before each key
```

Apply asks before writing each key. Any secret whose source or target changed since the report is skipped, and the rest go ahead. See [Command line](../cli.md).

## Environments with different layouts

When production keeps `services/billing/prod/db` and staging keeps `services/billing/staging/db`, a **comparison profile** pairs them with a mapping like `services/*/prod/**` ⇄ `services/*/staging/**`. Copies follow the mapping, so copying a production-only secret to staging writes it under the staging path. If two paths would map onto the same target, Lockstep refuses rather than guessing.

## Permissions

The person or role applying a sync needs `create` and `update` on the target's data path, and read access on the source. Lockstep checks this (`sys/capabilities-self`) before it writes, and the review shows when a target can't be written. Example policies are in the [security guide](../security.md#vault-policies).

## Next steps

- [How to compare secrets between two HashiCorp Vault clusters](compare-hashicorp-vault-clusters.md)
- [Detecting secret drift between Vault environments in CI](detect-vault-secret-drift-in-ci.md)
- [Try the live demo](https://demo.getlockstep.cloud): `alice` can write, `bob` is read-only. Both use the password `password`.
