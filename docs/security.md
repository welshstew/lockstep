<!-- description: Lockstep's security model: what it sees, stores, logs and writes, example read-only and copy Vault policies, and the signed, scanned supply chain. -->
# Security model

## What the tool holds

| Data | Where | For how long |
|---|---|---|
| Vault tokens | Encrypted, httpOnly, `SameSite=Lax` session cookie (Fernet: AES-128-CBC + HMAC-SHA256; key derived from `LOCKSTEP_SESSION_KEY`) | Until the session (8 h by default) or the token expires; removed on *Sign out* |
| Pending OIDC login | Same cookie | Single use, at most 10 minutes |
| Secret values | Server memory, during one request | Dropped as each secret is compared or copied |
| Passwords (userpass/LDAP, keystores) | Server memory, during one request | Not stored, not logged |

There is no database and no server-side session store. The browser can't read or alter the cookie's contents.

## What the browser receives

- **Compare** returns statuses, versions, timestamps and value *types*, never values.
- **Values** are returned only by explicit reads: *Show values* for a secret you expand, value-tool previews and downloads. Every `/api` response has `Cache-Control: no-store`.
- **Keystore private keys** are never downloadable.

## What the tool writes

Only **Apply** in the review dialog writes, and only:

- values **read again from the source Vault** at that moment (never values from the browser)
- with KV v2 **check-and-set** against the version you compared, so concurrent edits become conflicts
- **adding or updating keys.** Nothing is ever deleted.

Every attempted write is [audit-logged](usage.md#audit-log), without values. Tokens the tool created (userpass, LDAP, OIDC, Kubernetes) are revoked on *Sign out*; pasted tokens are left alone.

## Web protections

- **CSRF:** every state-changing `/api` call must send `X-Requested-With: lockstep`. A cross-site form can't set it, and a cross-origin script would need a CORS preflight the server never approves. That's on top of `SameSite=Lax` cookies.
- **OIDC:** the `state` must match the pending login (constant-time comparison); the pending login is single use and expires.
- **SSRF:** with `LOCKSTEP_ALLOW_CUSTOM_CONNECTIONS=false`, the server only calls the Vaults you configured. With custom addresses allowed, `LOCKSTEP_CUSTOM_URL_PATTERNS` limits which hosts it will call. Preset URLs are never sent to browsers.
- **Untrusted content:** SVG previews are rendered as images (no script execution). Downloads are sent as `application/octet-stream` with `nosniff`.

## The command line

`lockstep compare` and `lockstep apply` use your own Vault tokens on your own machine. Nothing goes through a Lockstep server.
- **Tokens:** read from the environment, a token file or `~/.vault-token`, never from arguments. A token the CLI makes by logging in (userpass/LDAP) is revoked when the command ends. It never stores tokens.
- **Reports:** hold paths, key names, versions and what kind of value each key holds, never values. They aren't signed, because the person running `apply` writes with their own permissions and confirms each key. Treat a report from someone else like any change request: read it before you apply it, for example with `--dry-run`.
- **Writes:** `apply` follows the web app's rules. It reads the source fresh, writes with check-and-set, never deletes, and appends audit lines to `--audit-log` if you give it a file.
- **Values on screen:** they only appear with `--show-values`.

## Kubernetes service account sign-in

This lets users act as the **tool's** identity rather than their own. It's off by default and can be pinned to specific roles. Read [the trade-offs](authentication.md#its-the-tools-identity-not-yours) before enabling it.

## Vault policies

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

The default policy already allows `sys/internal/ui/mounts` (mount list fallback), `sys/capabilities-self` (permission checks in the copy review) and token self-lookup and revocation.

## Supply chain

- **Base images:** the app runs on **Red Hat Hardened Images**: distroless, non-root (65532), no shell or package manager. It works with a read-only root filesystem and all capabilities dropped. The system `pip` is removed from the runtime image.
- **Pinning and signatures:** every base and scanner image is pinned by multi-arch digest. Red Hat images are **signature-verified with cosign** on every scan.
- **Scanning:** each pull request runs Grype and Trivy (image and repository files), pip-audit, npm audit, bandit and gitleaks. It fails on fixable HIGH/CRITICAL findings, and accepted risks must carry an expiry date. See [development](development.md#security-scanning).
