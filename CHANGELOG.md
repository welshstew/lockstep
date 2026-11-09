# Changelog

All notable changes to Lockstep. Versions follow [Semantic Versioning](https://semver.org/);
the image, the Helm chart and the app share one version.

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

[0.2.0]: https://github.com/welshstew/lockstep/releases/tag/v0.2.0
[0.1.0]: https://github.com/welshstew/lockstep/releases/tag/v0.1.0
