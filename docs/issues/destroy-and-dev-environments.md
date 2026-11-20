# Destroying secrets, and development environments

Feedback collected 2026-11-20. Each item has what was reported, then what was done about it.

## 1. Deleting a secret leaves a blank version

> Delete at the moment just creates a new version of the secret with a blank key and value.

Removing every key of a secret (for example **Delete everywhere** on its only key) wrote a new, empty version.

- [x] When a change would leave no keys, the latest version is soft-deleted instead of writing an empty one. The review says *Target vN is deleted* and lists the removed keys; `vault kv undelete` brings it back.

## 2. Destroy a secret

> Add the option to destroy secrets. When destroying a secret ensure the user gets a confirm dialog and must enter some text before confirming the destroy.

- [x] **Destroy on left… / right…** at the bottom of an expanded secret permanently deletes every version and the metadata on that side (`DELETE <mount>/metadata/<path>`).
- [x] A dialog lists the secret, warns that it can't be undone (and suggests exporting first), and enables **Destroy permanently** only once the secret's path has been typed.
- [x] The secret is checked against the version you compared; if it was written since, it isn't destroyed. Every attempt is audit-logged (`"event": "destroy"`), without values.
- [x] `POST /api/destroy`, and `LOCKSTEP_ALLOW_DESTROY` (chart `allowDestroy`, default on) to turn it off server-wide.

## 3. Destroy all on left / right

> Add a feature of destroy all on left / destroy all on right. Also require a user text input confirm dialog with warning.

- [x] **Destroy all on left (N)… / right (N)…** above the results act on every secret shown that exists on that side, so the status chips and the filter decide what's included.
- [x] The same dialog lists every secret, and needs `destroy N secrets` typed.

## 4. Document development environments as the main use case

> Add documentation to say how lockstep helps in development environments which is its primary use case.

- [x] New guide, [Lockstep for development environments](../guides/vault-secrets-in-development-environments.md), listed first on the site.
- [x] README and website say so up front.
