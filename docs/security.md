<!-- description: Lockstep's security model: what it sees, stores, logs and writes, example read-only and copy Vault policies, and the signed, scanned supply chain. -->
# Security model

## What the tool holds

| Data | Where | For how long |
|---|---|---|
| Plan signing key | `LOCKSTEP_PLAN_SIGNING_KEY` (optional), from the environment or a Secret; never sent to browsers | As long as you keep it; plans it signed stop verifying elsewhere when its public key is removed from their trusted list |
| Vault tokens | Encrypted, httpOnly, `SameSite=Lax` session cookie (Fernet: AES-128-CBC + HMAC-SHA256; key derived from `LOCKSTEP_SESSION_KEY`) | Until the session (8 h by default) or the token expires; removed on *Sign out* |
| Pending OIDC login | Same cookie | Single use, at most 10 minutes |
| Secret values | Server memory, during one request | Dropped as each secret is compared or copied |
| Passwords (userpass/LDAP, keystores) | Server memory, during one request | Not stored, not logged |

There is no database and no server-side session store. The browser can't read or alter the cookie's contents.

## What the browser receives

- **Compare** returns statuses, versions, timestamps and value *types*, never values.
- **Profile suggestions** (**Read both sides**) return paths, counts, and words that already appear in a path or are common environment names (`dev`, `prod`…), never any other part of a value.
- **Values** are returned only by explicit reads: *Show values* for a secret you expand, value-tool previews and downloads. Every `/api` response has `Cache-Control: no-store`.
- **Keystore private keys** are never downloadable.

## Exports hold values

A [secret-engine export](usage.md#6-export-and-import) is the one thing Lockstep produces that contains values in bulk. The server builds it with the user's own token (so it holds only what they can read), sends it to their browser as a download, and keeps nothing.

- **Encrypted by default** with AES-256-GCM and a random 256-bit one-time key. The key is shown once and never stored or logged. The readable header (Vault name, mount, prefix, count) is authenticated.
- **Plain exports** are refused unless an admin allows them (`LOCKSTEP_EXPORT_MODE=any`, or a preset's `"export": "any"`), and even then need an explicit choice and come with a warning. `off` turns exporting off, for the server or for one Vault.
- **Audit:** every export is logged (`"event": "export"`), never with values or the key.
- **Opening an export** sends the file (and key) to the server, which decrypts it and returns the contents to the page. The page holds them in memory only: never in browser storage, and gone on reload. The CLI writes export files and key files readable by their owner only.

## What the tool writes

Only **Apply** in the review dialog and **Import** write, and only:

- values **read again from the source Vault** at that moment, never copied values from the browser. A comparison profile's rewrites (`prod` ⇄ `staging`) are applied on the way, and the review marks each rewritten key
- or values you typed as an [override](usage.md#override-values), or from an export file you [import](usage.md#6-export-and-import) or copy from
- with KV v2 **check-and-set** against the version you compared, so concurrent edits become conflicts
- **adding or updating keys.** Keys are removed only when you ask: a key you [**Delete**](usage.md#delete-keys) in the compare view (a new version without it; older versions keep it; removing every key soft-deletes the latest version instead), or, on an import with *Make the target match the file*, keys and secrets the file doesn't have (secrets are soft-deleted).

**Browse** writes follow the same rules: check-and-set against the version you loaded, removing every key soft-deletes instead of writing an empty version, and every write is audit-logged without values.

**Share once** (Browse) hands values over as a Vault response-wrapping token: Lockstep reads them and passes them straight to `sys/wrapping/wrap`, stores nothing, and logs the key names and the token's accessor, never the values or the token. A token opens once and expires after at most 24 hours.

**Read-only servers:** `LOCKSTEP_READ_ONLY=true` makes Lockstep look-only, whatever Vault's policies allow: the UI hides every write and the API refuses them (403). **Per Vault**, a preset's [write policy](configuration.md#write-policy-per-vault) makes one Vault read-only (`writable: false`), or limits writes to some paths (`write_paths`, `deny_paths`) and turns off Destroy there. Refusals are audit-logged as `write.refused`. **Copy** in Browse can be turned off with `LOCKSTEP_ALLOW_CLIPBOARD=false`.

**Policies and roles** written from the Policies tab go through the same kind of review. `root` and `default` can't be touched, and each item is re-read and skipped if it changed since the review. Writes and deletes are audit-logged with hashes, never policy text. `LOCKSTEP_POLICY_APPLY=off` leaves Lockstep to building and exporting.

**AppRole secret IDs** issued from Lockstep are only ever returned wrapped in a single-use token (Vault response wrapping); Lockstep never sees them unwrapped and logs only the wrapping accessor.

**Destroying** is the one action that can't be undone: [**Destroy**](usage.md#destroy-secrets) permanently deletes every version and the metadata of the secrets you chose, on one side, after you type a confirmation phrase. Each is checked against the version you compared first. It needs the `delete` capability on `<mount>/metadata/…`, and `LOCKSTEP_ALLOW_DESTROY=false` turns it off for everyone.

Every attempted write and destroy is [audit-logged](usage.md#audit-log), without values. The [server log](configuration.md#logging) records requests, sign-ins and Vault errors: paths and identities, never values, tokens, passwords, bodies or query strings. Tokens the tool created (userpass, LDAP, OIDC, Kubernetes) are revoked on *Sign out*; pasted tokens are left alone.

## Web protections

- **CSRF:** every state-changing `/api` call must send `X-Requested-With: lockstep`. A cross-site form can't set it, and a cross-origin script would need a CORS preflight the server never approves. That's on top of `SameSite=Lax` cookies.
- **OIDC:** the `state` must match the pending login (constant-time comparison); the pending login is single use and expires.
- **SSRF:** custom addresses are off by default (`LOCKSTEP_ALLOW_CUSTOM_CONNECTIONS=false`), so the server only calls the Vaults you configured. With them on:
  - an address must be exactly `scheme://host[:port]`, with no user name, path, query or fragment;
  - `LOCKSTEP_CUSTOM_URL_PATTERNS` is matched against that normalised origin;
  - the host is resolved, and refused if any address it resolves to is private, loopback or link-local, unless `LOCKSTEP_CUSTOM_ALLOW_PRIVATE=true`;
  - the connection goes to the address that was checked, so a DNS answer can't change between the check and the call;
  - redirects from a custom Vault pass the same checks.

  Preset URLs are never sent to browsers.
- **Untrusted content:** SVG previews are rendered as images (no script execution). Downloads are sent as `application/octet-stream` with `nosniff`.

## The command line

`lockstep compare`, `apply`, `export` and `import` use your own Vault tokens on your own machine. Nothing goes through a Lockstep server.
- **Tokens:** read from the environment, a token file or `~/.vault-token`, never from arguments. A token the CLI makes by logging in (userpass/LDAP) is revoked when the command ends. It never stores tokens.
- **Reports:** hold paths, key names, versions and what kind of value each key holds, never values. They aren't signed, because the person running `apply` writes with their own permissions and confirms each key. Treat a report from someone else like any change request: read it before you apply it, for example with `--dry-run`.
- **Writes:** `apply` follows the web app's rules. It reads the source fresh, writes with check-and-set, never deletes, and appends audit lines to `--audit-log` if you give it a file.
- **Values on screen:** they only appear with `--show-values`.

## Kubernetes service account sign-in

This lets users act as the **tool's** identity rather than their own. It's off by default and can be pinned to specific roles. Read [the trade-offs](authentication.md#its-the-tools-identity-not-yours) before enabling it.

## Vault policies

The [Policies](usage.md#7-policies) tab is read-only. To explain policies by name it needs `list` and `read` on `sys/policies/acl` (or just `read` on the named ones). Without them, **My token's policies** still works: Vault answers through `sys/capabilities-self`, which the default policy allows.


The tool needs only what each person or role is meant to do. Example policies, with `app-config` as the mount:

```hcl
# Compare (read-only)
path "app-config/metadata"   { capabilities = ["list"] }
path "app-config/metadata/*" { capabilities = ["read", "list"] }   # tree, versions, "last changed"
path "app-config/data/*"     { capabilities = ["read"] }           # values (and older versions)
path "sys/mounts"            { capabilities = ["read"] }           # optional: full mount list
```

```hcl
# Also copy into this mount
path "app-config/data/*"     { capabilities = ["read", "create", "update"] }
```

```hcl
# Also soft-delete (removing every key, imports that match the file) and destroy
path "app-config/data/*"     { capabilities = ["read", "create", "update", "delete"] }
path "app-config/metadata/*" { capabilities = ["read", "list", "delete"] }   # delete here = destroy
```

Leave `delete` on `metadata/*` out of policies for people who shouldn't destroy secrets, or turn destroying off for everyone with `LOCKSTEP_ALLOW_DESTROY=false`.

The default policy already allows `sys/internal/ui/mounts` (mount list fallback), `sys/capabilities-self` (permission checks in the copy review) and token self-lookup and revocation.

## Supply chain

- **Base images:** the app runs on **Red Hat Hardened Images**: distroless, non-root (65532), no shell or package manager. It works with a read-only root filesystem and all capabilities dropped. The system `pip` is removed from the runtime image.
- **Pinning and signatures:** every base and scanner image is pinned by multi-arch digest. Red Hat images are **signature-verified with cosign** on every scan.
- **Scanning:** each pull request runs Grype and Trivy (image and repository files), pip-audit, npm audit, bandit and gitleaks. It fails on fixable HIGH/CRITICAL findings, and accepted risks must carry an expiry date. See [development](development.md#security-scanning).
