# Lockstep

**Compare, inspect and sync KV secrets across HashiCorp Vault and OpenBao clusters.**

[![security-scan](https://github.com/welshstew/lockstep/actions/workflows/security.yml/badge.svg)](https://github.com/welshstew/lockstep/actions/workflows/security.yml)
[![e2e](https://github.com/welshstew/lockstep/actions/workflows/e2e.yml/badge.svg)](https://github.com/welshstew/lockstep/actions/workflows/e2e.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Website:** [getlockstep.cloud](https://getlockstep.cloud) · **Try it:** [demo.getlockstep.cloud](https://demo.getlockstep.cloud), a public demo with two throwaway Vaults and two OpenBaos (sign in as `alice` / `password`; data resets every hour).

Compare **KV v2 secrets engines** across HashiCorp Vault clusters, or across two mounts in the same Vault. Works with **OpenBao** too, including Vault on one side and OpenBao on the other, for checking a migration. See exactly which values differ, without displaying them. Copy selected keys between the two sides safely, with a reviewed changeset.

**Made for development environments.** Lockstep's main job is keeping dev, test, integration and preview environments in step: finding the missing key or stale URL behind "works in dev, fails in test", copying or editing values to fix it, standing up a new environment from an existing one with export and import, and cleaning up afterwards. Production can be compared read-only, with changes sent through sync plans. See [Lockstep for development environments](docs/guides/vault-secrets-in-development-environments.md).

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/02-compare-dark.png">
  <img alt="Two Vaults compared side by side: secrets listed with Different, Left only, Right only and No access statuses, values masked" src="docs/images/02-compare-light.png">
</picture>

## Features

- **Browse a Vault.** The tab Lockstep opens on: a folder tree of a KV v2 mount, values masked until shown, copy and inspect, versions with diffs, roll back, delete and undelete. Edit in place and save with check-and-set, or stage several edits for one review. Every write is audit-logged.
- **Compare anything to anything.** Two Vaults, two mounts, or two path prefixes. Each side has its own connection, mount and prefix.
- **Values are compared on the server and never shown unless you ask.** The browser receives only a status per key (equal / different / left only / right only / no access). **Show values** reveals them, only for the secrets you open.
- **Only values count.** Versions, timestamps and the order of keys inside JSON are ignored. `5432` vs `"5432"` is flagged as a *type* difference.
- **Comparison profiles.** Pair paths that differ between environments (`services/*/prod/**` ⇄ `services/*/staging/**`, or a renamed application's old and new folder), read environment words in values as their counterpart (`test` ⇄ `dev`), and ignore keys or paths that are meant to differ. Copies follow the mapping and the rewrites. **Read both sides** suggests the rules from what's in the two Vaults and explains each one. Profiles can be shared by the team (server) or personal (browser, export/import).
- **Honest about permissions.** Secrets you can't list or read show as **No access**, never as "only on the other side", so nobody overwrites what they couldn't see.
- **Copy with ← / →** per key or per secret. A review shows exactly what each target gets. Writes use KV v2 **check-and-set**: a target changed by someone else since you compared becomes a conflict, not an overwrite. Nothing is deleted unless you ask (**Delete** on a key). Every write is **audit-logged** (without values).
- **Clean up for good.** **Destroy** a secret on one side, or every secret shown with **Destroy all on left / right**: every version and its metadata, after typing a confirmation phrase. Checked against the version you compared and audit-logged; can be turned off server-wide.
- **Sync plans.** Save a reviewed set of changes as a signed file (paths, keys and versions; never copied values) that doubles as a report of what needs updating from where. Someone with write access opens it, checks it and applies it. If anything in it changed since it was made, nothing is written and the plan has to be made again. Read-only users can prepare plans.
- **Command line too.** `lockstep compare` writes a YAML report of the differences (no values), with each secret's Vault UI link and `vault kv get` command. Set an action on the keys to change, and `lockstep apply` makes the copies, asking before each key is written. Logs in like the `vault` CLI, and works as a drift check in CI (exit code 1 on differences). See [Command line](docs/cli.md).
- **Export and import a secret engine.** Export a mount with its values to a file, encrypted with a one-time key, leaving out what you choose. Compare a Vault against an export, copy from it, or import it into another Vault with rules and transforms (`application-dev-env` → `application-test-env`), previewed and written with check-and-set. In the UI and the CLI (`lockstep export`, `lockstep import`).
- **Certificate expiry dashboard.** Scan one or both sides' mounts for every certificate (PEM, DER, base64, PKCS#12, JKS/JCEKS; keystores opened with the password stored beside them) and see what expires when, optionally with every certificate your PKI engines issued. Only certificate details come back, never values. **Issue a development certificate** from a PKI role, to download or store in a new secret.
- **Explain Vault policies.** See what a policy, or your own token, allows on every secret of a mount: see names, read, write, delete, destroy, history, with the rule and line behind each answer and warnings for common mistakes (KV v2 paths without `data/`, literal wildcards, risky grants). Matching follows Vault's own rules and is tested against Vault. Also `lockstep policy explain`.
- **Build policies without the confusing parts.** Write "who can do what, where" and get the right KV v2 paths, or let Lockstep suggest policies from your `<app>/<env>/…` layout (or your own pattern). Preview them on real secrets, then hand an admin a zip with HCL, an `apply.sh` that diffs first, and optional Terraform or OpenTofu.
- **Auth roles.** Kubernetes, JWT/OIDC and AppRole roles in plain terms (AppRole secret IDs issued wrapped in a single-use token): what a role's policies allow on real secrets, risky settings flagged, which roles grant a policy, roles compared across Vaults, and new ones built from GitLab CI, GitHub Actions or Kubernetes templates for the admin bundle.
- **Compare policies across Vaults.** Every ACL policy on two clusters compared by meaning, not text, with name mappings (`*-dev` ⇄ `*-prod`) and path rewrites from policy profiles, and what a pair allows on each side's mount. `lockstep policy compare` catches access drift in CI.
- **Value tools.** Each value is identified by its content: base64, PEM, DER, **X.509 certificates and chains** (validated link by link), **PKCS#12**, **JKS / JCEKS** keystores, keys, CSRs, images, ZIP/JAR, PDF… Inspect one or both sides, compare certificates field by field, preview images, download files.
- **Last-updated metadata.** When each secret was written and when each key last changed (worked out from KV v2 versions), never part of the comparison.
- **Sign in your way.** Token, userpass, LDAP, **OIDC redirect** (the same flow as the Vault UI), **JWT**, or the pod's **Kubernetes service account** with a mount and role you choose.
- **Configuration drift.** Two Vaults' versions, secrets engines and auth methods compared side by side, tuning and auth configuration included (secrets left out). `lockstep config compare` makes it a CI check.
- **Developer tools.** A **Transit playground** (encrypt, decrypt, rewrap, sign, verify, HMAC), **database credentials** generated from a role, and **leases** to browse, renew or revoke, all with your own sign-in.
- **Read-only mode.** `LOCKSTEP_READ_ONLY` turns Lockstep into a look-only tool: browse, compare, export and explain, but never write.
- **Built to run on Kubernetes.** Stateless (sessions live in an encrypted cookie), configured only through environment variables, runs on **Red Hat Hardened Images** (distroless, non-root), scanned in CI.

## Screenshots

| | |
|---|---|
| **Connect.** Each side discovers the login methods its Vault offers (OIDC preselected).<br><picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/01-connect-dark.png"><img alt="Connect screen" src="docs/images/01-connect-light.png"></picture> | **Key detail and copying.** Values shown on request, per-key last change, a staged copy (→) with the target value outlined.<br><picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/03-detail-and-copy-dark.png"><img alt="Expanded secret with a staged copy" src="docs/images/03-detail-and-copy-light.png"></picture> |
| **Review before writing.** Per target secret: keys added or updated, version change, permission and conflict checks.<br><picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/04-review-dark.png"><img alt="Review dialog" src="docs/images/04-review-light.png"></picture> | **What each value is**, even while masked: keystores, certificates, expiry.<br><picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/05-badges-dark.png"><img alt="Value type badges" src="docs/images/05-badges-light.png"></picture> |
| **Comparison profiles.** Map `prod` paths to `staging` paths, ignore keys meant to differ (here `host`); copies follow the mapping.<br><picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/09-profile-dark.png"><img alt="A profile pairing prod and staging paths, with an ignored key" src="docs/images/09-profile-light.png"></picture> | **Profile builder.** Reads both sides and suggests mappings for renamed folders and rewrites for environment words, then explains the profile against what's there.<br><picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/30-profile-explained-dark.png"><img alt="Profile editor with suggested rules and an explanation of what the profile does" src="docs/images/30-profile-explained-light.png"></picture> |
| **Inspect both sides.** A PKCS#12 opened with its sibling password key; certificates compared field by field.<br><picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/06-inspect-pkcs12-dark.png"><img alt="PKCS#12 inspector, both sides" src="docs/images/06-inspect-pkcs12-light.png"></picture> | **Certificate chains**, validated link by link against the trust anchors you choose.<br><picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/07-certificate-chain-dark.png"><img alt="Certificate chain validation" src="docs/images/07-certificate-chain-light.png"></picture> |
| **Certificate expiry dashboard.** Every certificate in both mounts, including inside keystores, by time to expiry; filter, inspect, export CSV.<br><picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/11-expiry-dark.png"><img alt="Certificate expiry dashboard" src="docs/images/11-expiry-light.png"></picture> | **Sync plans.** A saved plan, opened and checked against both Vaults before anyone applies it.<br><picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/12-sync-plan-dark.png"><img alt="A sync plan checked in the Sync plans tab" src="docs/images/12-sync-plan-light.png"></picture> |
| **Export and import.** An encrypted export with its one-time key, shown once.<br><picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/16-export-dark.png"><img alt="Encrypted export with its one-time key" src="docs/images/16-export-light.png"></picture> | **Import with rules.** Rewrite paths and values (prod → staging), preview, then write with check-and-set.<br><picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/17-import-dark.png"><img alt="Import preview with transforms" src="docs/images/17-import-light.png"></picture> |
| **Pick what to ignore.** Click Ignore on secrets, folders and keys, check the effect, save it as a profile.<br><picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/15-pick-ignore-dark.png"><img alt="Ignore mode with picked rules" src="docs/images/15-pick-ignore-light.png"></picture> | **Override values.** Type new values for one side or both; reviewed and written like a copy.<br><picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/13-override-dark.png"><img alt="Override editor for one side" src="docs/images/13-override-light.png"></picture> |
| **Keystore password finder.** The password lives in another folder: candidates are tried on the server, never shown.<br><picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/14-password-finder-dark.png"><img alt="Password finder offering the key that opens the keystore" src="docs/images/14-password-finder-light.png"></picture> | **Explain policies.** What a policy allows on each secret, the rule behind a denied one, and a likely mistake.<br><picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/18-policies-dark.png"><img alt="Policies tab: a grid of secrets by capability with the deciding rules" src="docs/images/18-policies-light.png"></picture> |
| **Compare policies across Vaults.** By meaning, with `*-dev` ⇄ `*-prod` pairing; sides collapsed to account summaries.<br><picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/19-policy-compare-dark.png"><img alt="Policies of two Vaults compared with a profile" src="docs/images/19-policy-compare-light.png"></picture> | **Browse.** A folder tree, one value shown, and an edit waiting to be saved with check-and-set.<br><picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/20-browse-dark.png"><img alt="Browse tab with a tree and a secret being edited" src="docs/images/20-browse-light.png"></picture> |
| **Suggest policies.** From the detected `{app}/{env}/**` layout, with the reason; your own patterns work too.<br><picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/21-policy-build-dark.png"><img alt="Suggested policies from the layout" src="docs/images/21-policy-build-light.png"></picture> | **Auth roles.** A JWT role in plain terms, a warning, and what it can do on real secrets.<br><picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/22-roles-dark.png"><img alt="A JWT role explained" src="docs/images/22-roles-light.png"></picture> |
| **Configuration drift.** Two Vaults' engines, auth methods, and engine roles and keys side by side.<br><picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/23-config-dark.png"><img alt="Two Vaults' configuration compared" src="docs/images/23-config-light.png"></picture> | **Access plans.** Policy changes someone without the rights prepared, checked against Vault now before an admin applies them.<br><picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/28-access-plan-dark.png"><img alt="An access plan opened for review" src="docs/images/28-access-plan-light.png"></picture> |
| **Transit playground.** Encrypt, decrypt, sign and verify with a Transit key while you build an integration.<br><picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/24-transit-dark.png"><img alt="A value encrypted with a Transit key" src="docs/images/24-transit-light.png"></picture> | **Database credentials.** Short-lived credentials from a database role, masked until shown, revocable at once.<br><picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/25-database-dark.png"><img alt="Credentials generated from a database role" src="docs/images/25-database-light.png"></picture> |
| **Leases.** Browse leases by path with their expiry; renew or revoke.<br><picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/26-leases-dark.png"><img alt="Leases of userpass logins with their expiry" src="docs/images/26-leases-light.png"></picture> | **Development certificates.** Issue one from a PKI role, download it or store it in a secret.<br><picture><source media="(prefers-color-scheme: dark)" srcset="docs/images/27-pki-issue-dark.png"><img alt="A certificate issued from a PKI role" src="docs/images/27-pki-issue-light.png"></picture> |

## Quick start (local, with two demo Vaults)

Requires Podman (or Docker) with Compose.

```sh
make up          # = podman compose up --build -d
open http://localhost:8080
```

This starts two dev-mode Vaults filled with demo data, Dex as an OIDC provider, and the tool. Sign in with **OIDC** as `alice@example.com` / `password`, or with **Username** `alice` / `password`, on both sides. Pick `app-config` on each side and press **Compare**. The [development guide](docs/development.md) lists every demo user, mount and fixture.

`make up-k8s` also starts a small **k3s** cluster, so you can try [Kubernetes auth](docs/authentication.md#kubernetes-service-account) locally.

## Deploy

```sh
helm upgrade --install lockstep oci://ghcr.io/welshstew/charts/lockstep --version 0.10.0 \
  -n lockstep --create-namespace -f my-values.yaml
```

Or run the container anywhere: `ghcr.io/welshstew/lockstep:0.10.0` (amd64 and arm64, signed with cosign, with an SBOM and build provenance; see [releases](https://github.com/welshstew/lockstep/releases)).

For the command line, install from GitHub (it isn't on PyPI yet) or use the same image with `--entrypoint lockstep`. See [Command line: install](docs/cli.md#install):

```sh
pipx install "git+https://github.com/welshstew/lockstep@v0.10.0#subdirectory=backend"
```

A hardened chart: non-root, read-only filesystem, a session key kept across upgrades, optional Ingress, NetworkPolicy and Kubernetes auth. See [Deploying on Kubernetes](docs/kubernetes.md) and the [chart README](charts/lockstep/README.md).

## Documentation

| Guide | Contents |
|---|---|
| [Using the tool](docs/usage.md) | Comparing, statuses and permissions, copying values, value tools, timestamps |
| [Command line](docs/cli.md) | `lockstep compare` reports and `lockstep apply`: install, logging in, the report format, exit codes |
| [Authentication](docs/authentication.md) | Token, userpass/LDAP, OIDC redirect, JWT, **Kubernetes service account**: app settings *and* the Vault-side setup for each |
| [Configuration](docs/configuration.md) | Every `LOCKSTEP_*` setting |
| [Deploying on Kubernetes](docs/kubernetes.md) | The Helm chart, a deployment checklist, OIDC callback and Kubernetes auth in a cluster ([chart values](charts/lockstep/README.md)) |
| [Public demo](docs/demo.md) | Run the self-contained demo stack on a Docker host with Caddy and automatic HTTPS |
| [Security model](docs/security.md) | What the tool sees, stores, logs and writes; hardening and supply chain |
| [Development](docs/development.md) | Project layout, demo data, tests, k3s profile, screenshots, security scanning, CI |
| [API](docs/api.md) | HTTP endpoints |

## Status and roadmap

**Working:** comparison, copying, a command-line interface (reports and apply), value tools, last-updated metadata, comparison profiles (path mapping, value rewrites and ignore rules, suggested from both sides), a certificate expiry dashboard, all sign-in methods (token, userpass/LDAP, OIDC redirect, Kubernetes), a Helm chart tested in a real cluster, and in CI security scanning, chart checks and browser end-to-end tests.

**Possible next steps:**
1. **Four-eyes rule for sync plans:** optionally require the person applying a plan to be someone other than its creator (plans already record who made them)

## Licence

[MIT](LICENSE). Third-party components keep their own licences; see [NOTICE](NOTICE).

Contributions are welcome ([CONTRIBUTING.md](CONTRIBUTING.md)). Please report security issues privately ([SECURITY.md](SECURITY.md)).

---

*Lockstep is an independent project. It is not affiliated with, endorsed by or sponsored by HashiCorp or the OpenBao project. HashiCorp and Vault are trademarks of HashiCorp, Inc.*
