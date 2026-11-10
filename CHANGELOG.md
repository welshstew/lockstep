# Changelog

All notable changes to Lockstep. Versions follow [Semantic Versioning](https://semver.org/);
the image, the Helm chart and the app share one version.

## [Unreleased]

## [0.3.0] - 2026-11-10

### Added

- **Secret-engine export and import:** the **Export & import** tab (and `lockstep export` / `lockstep import`) exports a mount or prefix with its values to a JSON file ([schema](https://getlockstep.cloud/schemas/lockstep-export-v1.json)), leaving out paths and keys you choose, encrypted by default with AES-256-GCM and a one-time key shown once. Imports apply rules first: leave out paths and keys, then transforms (replace text, add a prefix or suffix, change case) on values, key names or paths, saved and loaded as JSON ([schema](https://getlockstep.cloud/schemas/lockstep-import-rules-v1.json)). The preview shows what would change; the write merges with check-and-set and never deletes. Exports are audit-logged; `LOCKSTEP_EXPORT_MODE` (`any` / `encrypted` / `off`, chart value `exportMode`) controls them.
- **Compare against an export file:** either side can be an opened export instead of a Vault: compare, show values, and copy from the file into a Vault (never into the file).
- **Build a profile by picking:** after a comparison, **Pick what to ignore…** adds *Ignore* buttons to secrets (the secret, or its folder) and to differing keys (here, or everywhere). Picks show straight away, can be tried with **Compare with these rules**, and **Save as profile…** opens the editor with them filled in, as a new profile or added to the selected personal one.
- **Keystore password finder:** when the inspector opens a locked PKCS#12/JKS/JCEKS keystore, it looks for the password in the keystore's top-level folder: keys and secrets named like passwords, ranked by closeness and shared name words (`certs.p12` → `CERT_PASSWORD`), each tried on the server. Ones that open it are offered with **Use**; values are never returned. The certificate expiry scan uses the same ranking for keystores no sibling key opens.
- **Override values:** set values yourself on one side or both (**Override left / right / both** in an expanded secret) instead of copying the other side's. Typed values can be text or JSON, can add new keys, and go through the same review and check-and-set write as copies; they can be combined with copies into the same secret. Override values are never stored or logged (the audit log names the keys) and can't go into a sync plan.
- **JWT sign-in:** connect with Vault's JWT auth method by pasting a JWT (an ID token or a CI job's OIDC token), with an optional role and mount. The CLI takes it from `LOCKSTEP_LEFT_JWT` / `--left-jwt-file` with `--left-auth jwt`. Tokens from a JWT login are revoked on sign-out, like other logins.
- **Editor support for CLI reports:** reports point to a published JSON Schema (`https://getlockstep.cloud/schemas/lockstep-report-v1.json`, also printed by `lockstep schema`). In VS Code with the YAML extension, and other editors using the YAML language server, `action:` values autocomplete with descriptions and typos are flagged while you edit.
- The value inspector notes that JKS and JCEKS keystores use weak, format-mandated SHA-1 (and MD5/Triple DES) protection, and gives the `keytool` command to convert them to PKCS#12.

### Changed

- Comparison profile picks strike through only the key name, not the *Ignore* buttons next to it; import transforms fit on one line.
- New guides on getlockstep.cloud: [exporting, importing and migrating secrets](https://getlockstep.cloud/guides/export-import-vault-secrets/), [building a comparison profile](https://getlockstep.cloud/guides/build-a-comparison-profile/) and [logging in with JWT from CI](https://getlockstep.cloud/guides/vault-jwt-login-from-ci/). The drift-detection guide now uses the built-in JWT login.

## [0.2.0] - 2026-11-09

### Added

- **Command line:** `lockstep compare` writes a YAML report of the differences, with no values. For each secret it gives both sides' versions, a Vault UI link and a `vault kv get` command. `lockstep apply` carries out the actions you set in the report: it asks before each key (or `--yes`, `--dry-run`), reads values fresh from the source, and skips any secret that changed since the report. It logs in like the `vault` CLI (`VAULT_ADDR`, `VAULT_TOKEN`, `~/.vault-token`, per-side overrides, userpass/LDAP prompts) and returns diff-style exit codes for CI. It's in the Python package and the container image.

## [0.1.0] - 2026-11-09

First public release.

### Added

- **Compare** KV v2 secrets engines across two Vaults, or two mounts or prefixes in one Vault. Values are compared on the server and only shown on request; secrets you can't read show as *No access*, never as one-sided.
- **Copy** keys or whole secrets in either direction after a review, with KV v2 check-and-set (no overwriting a target changed since the comparison), nothing ever deleted, and every write audit-logged without values.
- **Sync plans:** save a reviewed set of copies as a signed file with no values (and a Markdown report); someone with write access checks and applies it later. If anything in it changed, nothing is written.
- **Comparison profiles:** path mappings (`services/*/prod/**` ⇄ `services/*/staging/**`) and ignored keys or paths, shared by the server or kept per browser.
- **Value tools:** base64, PEM/DER, X.509 certificates and chains (validated), PKCS#12, JKS/JCEKS, keys, CSRs, images, archives; side-by-side certificate comparison and downloads.
- **Certificate expiry dashboard** across one or both mounts, including certificates inside keystores, with CSV export.
- **Last-updated metadata** per secret and per key, never part of the comparison.
- **Sign-in** with token, userpass, LDAP, OIDC (redirect flow) or the pod's Kubernetes service account.
- **Helm chart:** hardened defaults, session key kept across upgrades, Ingress, NetworkPolicy, PodDisruptionBudget, Kubernetes auth, shared profiles; validated by a schema and tested in k3s.
- Runs on Red Hat Hardened Images (distroless, non-root). Every change is scanned (CVEs, secrets, misconfigurations, base image signatures) and tested end to end in a browser.

[0.3.0]: https://github.com/welshstew/lockstep/releases/tag/v0.3.0
[0.2.0]: https://github.com/welshstew/lockstep/releases/tag/v0.2.0
[0.1.0]: https://github.com/welshstew/lockstep/releases/tag/v0.1.0
