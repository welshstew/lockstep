# Gap analysis: Lockstep and the Vault web UI

**Status:** largely delivered in Lockstep 0.7.0. Waves 1, 4 and 5 (except Vault UI links) are built, wave 2 mostly, and wave 3 apart from a few items; [section 6](#6-where-things-stand) lists what's built and what's left · **Written:** 2026-11-21 · **Updated:** 2026-11-22 · **Owner:** unassigned

This compares what Lockstep can do with what the Vault web UI (the "Vault GUI") offers, lists the functions Lockstep doesn't cover, and proposes which gaps to fill, how, and in what order.

**Sources:**
- The Vault 2.x documentation and release notes as of 2026-11 (Vault 2.2.2 is the latest release), plus 1.20 and 1.21.
- The long-standing GUI features of Vault 1.x.
- Lockstep as of the `policy-build` branch, which includes Browse and policy builder phases 1–3. Lockstep's tests run against Vault 1.21.4.

Sections 2 and 3 are the analysis and proposal as written, before the work. The summary table in section 1 and section 6 describe Lockstep now.

Features marked **ENT** need Vault Enterprise.

---

## 1. Summary

Lockstep is not a general Vault console, and shouldn't become one. It's strongest where the Vault UI is weakest:
- comparing and syncing **two** Vaults (or mounts);
- KV v2 work with safety rails (check-and-set everywhere, reviews, audit without values, sync plans);
- value tools (certificates, keystores, the password finder);
- making policies understandable.

The Vault UI is broad: every secrets engine, auth methods, identity, operations and Enterprise features.

| Area | Vault UI | Lockstep today | Gap |
|---|---|---|---|
| KV v2 secrets | Full: create, edit, versions, metadata, custom metadata, patch, delete/undelete/destroy, JSON and YAML views, version diff | Browse, edit, versions and who made them, diff, roll back, metadata and custom metadata, `PATCH`, `subkeys`, YAML view, snippets, share once, delete/undelete/destroy, compare, copy, export/import, value tools | **Closed.** Comparing custom metadata is not built |
| KV v1, cubbyhole | Yes | No (KV v2 only, by decision) | Out of scope |
| Other secrets engines (PKI, database, transit, SSH, AWS, Azure, GCP, LDAP, Kubernetes, TOTP…) | Engine-specific pages: roles, issue/generate credentials, rotate, configure | PKI: issue, issuers and roles, issued certificates in the expiry scan. Database: connections and roles, generate credentials. Transit playground. Roles and keys compared across Vaults (PKI, database, Transit, SSH, Kubernetes, AWS) | **Developer slices done.** Configuring engines stays in the Vault UI |
| Mounts | Enable, configure, tune, disable; secrets engine catalog | Every mount with type, version and tuning, compared across Vaults (and `lockstep config compare`) | **Closed** for read-only. Copying tuning across: not built |
| Auth methods and roles | Enable, configure, tune; userpass users; method-specific roles | Sign in with token, userpass, LDAP, OIDC, JWT, Kubernetes, with login MFA. Methods and their config compared. Kubernetes, JWT/OIDC and AppRole roles: explain, build, compare, apply; AppRole secret IDs issued wrapped | **Small:** userpass users, LDAP group mappings |
| Identity (entities, groups, aliases), MFA, OIDC provider, SCIM | Yes (SCIM, Agent registry **ENT**) | Groups listed and compared; Explain for an entity, group or token (through its accessor) | **Small:** editing group policies. The rest out of scope |
| Policies | ACL editor; visual policy editor (2.0); policy generator from a secret **ENT** (KV v2, PKI); RGP/EGP **ENT** | Explain (Vault-exact matching for 1.x and 2.2.2+), lint, build, suggest, compare, export with `apply.sh`/Terraform/OpenTofu, apply and delete from Lockstep, saved access plans | **Lockstep is ahead.** Missing: "Generate a policy for this folder" from Browse, Sentinel policies read-only |
| Leases | List, renew, revoke, revoke by prefix | Browse by path, renew, revoke selected leases | **Closed.** Revoke by prefix left out on purpose |
| Tools | Wrap, lookup, unwrap, rewrap, random, hash; API explorer; web REPL (browser CLI) | Share once and unwrap, random values, Transit playground | **Closed.** API explorer and REPL: link |
| Tokens | Copy, renew and revoke your own token; MFA TOTP self-enrollment | Sign out revokes tokens Lockstep made; policies and expiry shown | **Small:** renew, and "Try this policy" test tokens |
| Operations | Dashboard; seal/unseal; raft storage and snapshots; secret recovery from snapshots; replication **ENT**; license and client counts; plugins; namespaces **ENT**; secrets sync **ENT**; custom messages **ENT**; upgrade analyzer **ENT**; onboarding checklist | Overview per side in Configuration: version, seal, storage, HA, replication, with drift highlighted | **Mostly out of scope.** Namespaces (policy builder phase 7) and license expiry **ENT** not built |
| GUI conveniences | Dark mode (2.2), Terraform snippets in forms (2.2), YAML view, collapsible sidebar, feedback button | Light/dark/system switch, snippets (CLI, curl, Terraform) in Browse, YAML view, collapsible side cards | **Small:** links into the Vault UI |

**Where Lockstep already goes beyond the Vault UI:**
- two-sided comparison and copy, with check-and-set and reviews;
- sync plans and drift checks in CI;
- export and import with transforms;
- certificate and keystore inspection and expiry across a mount;
- explaining what a policy really allows on real secrets;
- suggesting policies from the layout;
- comparing policies across clusters;
- a read-only mode;
- per-key "last changed".

---

## 2. Detailed gaps

Each row has a recommendation:
- **Fill:** worth doing;
- **Read-only:** show it, don't change it;
- **Link:** send people to the Vault UI;
- **Out:** not Lockstep's job.

### 2.1 KV v2 (Lockstep's core)

| Vault UI | Lockstep | Recommendation |
|---|---|---|
| Edit metadata: `max_versions`, `cas_required`, `delete_version_after` | Shown in Browse, not editable | **Fill** (Browse phase 3) |
| Custom metadata (key/value labels on a secret) | Shown, not editable; not compared | **Fill:** edit in Browse; compare it as an option in Compare, ignored by default |
| Patch (change some keys without a full write) | Writes the whole secret with check-and-set, keeping other keys | **Fill, internally:** use `PATCH` when the token has `patch` but not `update`. Lockstep's merge already gives the same result |
| Subkeys (key names without values) | Key names come from reading the data | **Fill:** use `subkeys/` when the token can't read values, so Browse can show key names to people who can only see structure |
| YAML view of a secret (2.2) | Text and JSON | **Fill:** a YAML/JSON toggle on the value panel and in exports |
| Version attribution: who created a version (1.21) | Times only | **Fill:** show "by alice" next to each version and in "last changed" |
| Create a secret from an older version | Roll back (writes the old data as a new version) | Covered |
| Copy path and CLI/API commands for a secret | Compare reports have `vault kv get` commands; the UI doesn't | **Fill:** a **Snippets** menu with `vault kv get/put/patch`, `curl` and Terraform `vault_kv_secret_v2` for the current secret or edit (no values unless shown) |
| Recover a secret from a snapshot (1.21 GUI; 2.2 in place) **ENT** | No | **Out:** an operator task |
| KV v1 | No | **Out** (decided) |

### 2.2 Other secrets engines

| Vault UI | Recommendation |
|---|---|
| **PKI:** issuers, keys, roles, issue and sign certificates, revoke, tidy, configure, cross-sign, ACME and external CA **ENT** | **Fill a developer slice:**<br>• **Issue a certificate** from a role, then download it or store it in a KV secret, with the inspector built in;<br>• a read-only list of issuers and roles;<br>• add `pki/certs` to the **Certificate expiry** dashboard, so Vault-issued certificates expire on the same timeline as those stored in KV.<br>Configuring PKI stays in the Vault UI or Terraform |
| **Database:** connections, dynamic and static roles, generate credentials, rotate root | **Fill read-only plus "Generate credentials"** for a role (shown once). **Compare** roles across Vaults (SQL statements, TTLs). Configure: **Link** |
| **Transit:** keys, encrypt, decrypt, sign, verify, hash, HMAC, rewrap, data keys, rotate, export | **Fill a small playground** for developers testing their integration: encrypt/decrypt and sign/verify with a key they can use; key list and configuration read-only. **Compare** key configuration across Vaults |
| **SSH, AWS, Azure, GCP, Kubernetes, LDAP, Terraform, TOTP, local accounts (2.0)**: roles, generate or rotate credentials | **Read-only + compare** of roles where it's cheap, through a generic "role" view (section 3.3). Generating credentials: only if teams ask |
| **Transform, KMIP, key management, secrets sync, secrets import** **ENT** | **Out** |
| **Secrets engine catalog** (enable a new engine) | **Out** for enabling. **Read-only:** list every mount, not just KV v2, with type, version and tuning (section 3.3) |

### 2.3 Access: auth methods, roles, identity

| Vault UI | Recommendation |
|---|---|
| Enable, configure, tune and disable auth methods | **Read-only + compare** across Vaults (config without secrets: client secrets and bind passwords are never returned or shown) |
| Kubernetes and JWT/OIDC roles | **Fill**: policy builder phase 4, already planned (list, explain, build, compare, export, apply) |
| AppRole roles, role IDs, secret IDs | **Fill (policy builder phase 6):** build and compare roles. **Issue a secret ID** shown once, or wrapped (section 2.5), which is very useful in dev environments |
| Userpass users, LDAP groups and users | **Fill (phase 6):** userpass users for dev Vaults (create, reset password, policies); LDAP group → policy mappings read-only + compare |
| Entities, groups, aliases, merging entities | **Fill partly:** groups carry policies, so **list, explain and compare** groups and their policies (phase 6), and edit group policies. Entities and aliases read-only, so Explain can work for "another user" (decided in the policy builder proposal). Merging: **Out** |
| MFA methods and login enforcement; TOTP self-enrollment (1.21) | **Out** for configuration. Lockstep's own login should **support MFA** when a Vault enforces it (section 3.6) |
| OIDC provider (Vault as an IdP), SCIM **ENT**, Agent registry **ENT** | **Out** |
| Leases: list, renew, revoke, revoke by prefix | **Fill (small):** list leases under a prefix, revoke one or a prefix after a typed confirmation. Useful only with dynamic secrets, so after section 2.2 |

### 2.4 Policies

| Vault UI | Lockstep | Recommendation |
|---|---|---|
| ACL policy editor, create and delete | Explain, build, suggest, compare, export | **Fill:** apply from Lockstep (policy builder phase 5) and delete with a typed confirmation |
| Visual policy editor (2.0): paths and permissions | Build with KV-aware choices, a live preview on real secrets, findings | Covered, and more specific to KV |
| Policy generator from a secret **ENT** (KV v2, PKI) | Suggest from the whole layout; Browse links to "Why can I…?" | **Fill:** "Generate a policy for this folder" in Browse, which opens Build prefilled. Free, unlike the Enterprise one. Add PKI paths when PKI support comes |
| RGP and EGP (Sentinel) **ENT** | No | **Read-only:** list them and show their text. Authoring: **Out** |
| Policies applied to "resultant ACL" (what the UI uses to hide menus) | Explain uses `sys/capabilities-self` when policies can't be read | Covered |

### 2.5 Tools and tokens

| Vault UI | Recommendation |
|---|---|
| Wrap, lookup, unwrap, rewrap | **Fill: share once.** In Browse, **Share…** wraps the shown values of a secret (or chosen keys) with a short TTL and gives a wrapping token, or a Lockstep link that unwraps it, to send to a colleague instead of pasting a password in chat. An **Unwrap** box opens one. Uses `sys/wrapping/*`; values never stored by Lockstep |
| Random bytes, hash | **Fill (tiny):** a "Generate value" button in the value editor (random password or bytes, from `sys/tools/random`) |
| API explorer, web REPL | **Link** to the Vault UI |
| Renew and revoke your token, copy your token | **Fill (small):** renew a connection's token, and show its policies and TTL (most of this is already in the side summary) |
| Create a short-lived child token with chosen policies | **Fill (policy builder):** "Try this policy": create a 15-minute token with a draft policy (needs policy apply) and sign in with it on the other side, to check access for real |

### 2.6 Operations and Enterprise

| Vault UI | Recommendation |
|---|---|
| Dashboard: version, seal status, mounts, replication, quick actions; onboarding checklist (2.2) | **Read-only overview per side:** version, seal and HA status, raft peers (if readable), replication mode, mounts and auth methods by type, license expiry **ENT**. Side by side for two Vaults, so version and configuration **drift between clusters** stands out |
| Seal and unseal, step-down, rekey, root token generation | **Out** (high risk, rare, operator-only) |
| Raft storage: peers, snapshots; secret recovery **ENT** | **Out** (read-only peer list in the overview at most) |
| Replication **ENT**, performance standbys, license, client counts, license utilization dashboard | **Read-only** status in the overview; everything else **Out** |
| Namespaces **ENT**, namespace onboarding (2.0) | Namespaces: a namespace picker per side. Lockstep already connects with a namespace; listing child namespaces is policy builder phase 7. Creating them: **Out** |
| Plugins: register and manage external plugins (2.0) | **Out** |
| Audit devices | Not in the Vault UI either. **Out** |
| Custom messages, upgrade analyzer **ENT**, feature spotlight, feedback | **Out** |

### 2.7 GUI conveniences

| Vault UI | Recommendation |
|---|---|
| Dark mode with a switch (2.2) | Lockstep follows the system. **Fill (tiny):** a light/dark/system switch |
| Terraform code snippets in forms (2.2) | Lockstep does it for policies. **Fill:** a snippets menu (CLI, curl, Terraform) for Browse edits (section 2.1), and later roles |
| Standardised, paginated lists with filters | Browse pages folders; most lists filter. Fine |

---

## 3. Proposal: how to fill the gaps

### 3.1 Principles

1. **Stay focused.** Lockstep is for teams working with KV secrets and the access around them, across environments. It doesn't try to cover what an operator does once a year in the Vault UI.
2. **Read-only and compare before write.** For anything beyond KV and policies, first show it and compare it across two Vaults; that's what Lockstep is uniquely good at. Writing comes later, only where developers need it.
3. **Same safety everywhere:**
   - a review or inline confirmation;
   - a version check where Vault offers one, a hash re-check where it doesn't;
   - typed confirmations for destructive actions;
   - audit lines without values;
   - `LOCKSTEP_READ_ONLY` respected;
   - CLI/API/Terraform snippets for every write, so people can do it their own way instead.
4. **Generic where possible.** One "configuration object" viewer and comparer (section 3.3) covers mounts, auth methods and many engines' roles, instead of a page per engine.
5. **Link out** to the Vault UI for anything else, at the right place (`/ui/vault/secrets/<mount>/…`), so Lockstep never leaves people stuck.

### 3.2 Wave 1: finish KV v2 (small, high value)

- Browse phase 3: edit metadata and custom metadata; respect `cas_required`.
- Custom metadata in Compare (off by default) and in exports.
- Who created each version (1.21's version attribution), in Browse and "last changed".
- `subkeys/` for people who may see structure but not values.
- Use `PATCH` when the token has `patch` but not `update`.
- A YAML/JSON toggle.
- A **Snippets** menu: `vault kv` commands, `curl` and Terraform for the shown secret or pending edit.
- **Share once:** response wrapping from Browse, and an Unwrap box. A random value generator in the editor.
- A light/dark/system theme switch.

### 3.3 Wave 2: configuration drift across Vaults (Lockstep's strength, read-only first)

A generic **Configuration** view:
- **Mounts:** every secrets engine with type, version, description and tuning (TTLs, audit settings, listing visibility, options).
- **Auth methods:** type, tuning and configuration (sensitive fields are never returned by Vault, and are left out).
- **Roles:** of Kubernetes, JWT/OIDC, AppRole, userpass (users), database, PKI, SSH, AWS, Azure, GCP and Kubernetes secrets engines.
- **Transit keys:** settings only.
- **Identity groups** with their policies.

How it works:
- Each object is fetched from its read endpoint, normalised (defaults and volatile fields left out), and compared across two Vaults with the same left/right UI as secrets and policies.
- Profiles pair names that differ (`*-dev` ⇄ `*-prod`), as policy profiles do.
- `lockstep config compare` gives CI a drift check for whole clusters.
- Writing (copying a role or mount tuning across) comes later through the same review and plans as policies, after policy builder phase 5 proves the pattern.

### 3.4 Wave 3: access for developers (the policy builder's remaining phases)

- Phase 4: Kubernetes and JWT/OIDC roles (planned).
- Phase 5: apply policies and roles from Lockstep, delete with a typed confirmation, saved plans (planned).
- Phase 6: AppRole (roles, secret IDs shown once or wrapped), userpass users, identity groups (policies), entities read-only for "explain another user", and leases (list and revoke under a prefix).
- **Try this policy:** a short-lived token with a draft policy, to check access for real.
- **Generate a policy for this folder** from Browse.
- Phase 7: namespaces.

### 3.5 Wave 4: developer slices of other engines

- **PKI:**
  - issue a certificate from a role, to download or store in KV;
  - issuers and roles read-only;
  - `pki/certs` in the expiry dashboard.
- **Database:** generate credentials for a role (shown once); connections and roles read-only.
- **Transit:** an encrypt/decrypt and sign/verify playground; keys read-only.

Each one is small, task-shaped ("I need a dev certificate", "I need DB credentials to debug"), and uses the existing value tools.

### 3.6 Wave 5: overview and sign-in

- A read-only **Overview** per side, both side by side: version, seal and HA status, replication, mounts and auth methods, and license expiry **ENT**. Version drift between clusters highlighted.
- **Login MFA:** when a Vault enforces login MFA (TOTP, Duo, Okta, PingID), a login returns an `mfa_requirement` instead of a token. Lockstep doesn't handle that step today, so sign-in can't complete on those Vaults. Support it (`sys/mfa/validate`) so Lockstep works there.
- **Links into the Vault UI** from every object Lockstep shows.

### 3.7 Explicitly out of scope

- Seal and unseal, rekey and root generation, step-down.
- Raft membership, snapshots and recovery.
- Replication management and licensing.
- Plugin registration, audit devices, MFA configuration, the OIDC provider, SCIM, Sentinel authoring.
- Secrets sync and import, Transform, KMIP, key management.
- Namespace creation, custom messages, client-count billing.
- The API explorer and web REPL (link to them).
- KV v1 and cubbyhole.

---

## 4. Priorities and effort

| Item | Value for Lockstep's users | Effort | Suggested order | Status |
|---|---|---|---|---|
| Policy matcher on Vault 2.x (below) | Correctness | S | **Now** | Built |
| Wave 1: KV completeness, snippets, share once | High | S–M | 1 | Built |
| Policy builder phases 4–5 (roles, apply) | High | M–L | 2 | Built, with saved access plans |
| Wave 2: configuration view and drift compare | High (unique) | M | 3 | Built, except name profiles and copying across |
| Login MFA | Medium (blocks some Vaults entirely) | S–M | 3 | Built |
| Policy builder phase 6 (AppRole, users, groups, leases), try-this-policy | Medium | M | 4 | AppRole, groups, leases built; userpass users and try-this-policy not started |
| Wave 4: PKI, database, transit slices | Medium | M | 5 | Built |
| Wave 5: overview | Medium | S | 5 | Built, except Vault UI links |
| Policy builder phase 7 (namespaces) | Medium (Enterprise users) | M | 6 | Not started (needs an Enterprise Vault to test) |

**Correctness first: Vault 2.x policy changes.** Vault 2.2.2 changed policy evaluation:
- explicit `deny` rules now match case-insensitively;
- paths that differ only by a trailing slash now match consistently.

Lockstep's policy matcher was verified against Vault 1.21.4, so on 2.2.2 its answers could differ in those edge cases. **Done:** the matcher now implements both behaviours, chosen by the Vault's version, and the tests check it against 1.21.4 and 2.2.2. The policy builder proposal already decided to check against the latest Vault on a schedule. This makes it urgent:
- add Vault 2.x to the matching test and CI (`hashicorp/vault:2.2`);
- teach the matcher both behaviours, chosen by the Vault version it talks to (`sys/seal-status` reports it);
- consider moving the dev stack to 2.x.

---

## 5. Decisions and open questions

**Decided while building:**
- **Generic configuration view or engine pages?** Both, split by job. Configuration drift uses a generic view with raw field names, normalised so equal setups compare equal; engine roles and keys are compared the same way. Developer tasks (issue a certificate, generate credentials, try Transit) get small task-shaped tools.
- **Share once:** both. **Share…** gives a wrapping token for `vault unwrap`, and Lockstep's **Unwrap** dialog opens one for someone without the CLI. Lockstep never stores the values.
- **Credential generation (PKI, database):** Lockstep generates them with the signed-in user's own token:
  - the secret parts are shown once;
  - it's audit-logged with the serial or lease ID, never the secret;
  - it's refused in read-only mode;
  - database credentials can be revoked straight away.

**Still open:**
- **How far towards operations:** today there's a read-only overview. Do some teams want Lockstep to replace the Vault UI for day-to-day KV and access work, with no Vault UI exposed at all?
- **Enterprise:** namespaces come next (policy builder phase 7). Do Sentinel policies (read-only) or replication status matter to Lockstep's users?

---

## 6. Where things stand

**Built** (Lockstep 0.7.0):
- **KV v2 (wave 1):**
  - who made each version, editable metadata and custom metadata;
  - share once and unwrap;
  - snippets (CLI, curl, Terraform), random values, the theme switch;
  - `subkeys` for structure-only access, `PATCH` for patch-only tokens, the YAML view.
- **Configuration (wave 2):**
  - an overview per side;
  - secrets engines, auth methods and their configuration compared;
  - roles and keys of PKI, database, Transit, SSH, Kubernetes and AWS engines compared;
  - `lockstep config compare` for CI.
- **Access (wave 3):**
  - Kubernetes, JWT/OIDC and AppRole roles (explain, build, compare, apply, delete), with AppRole secret IDs issued wrapped;
  - identity groups compared, and Explain for an entity, group or token;
  - policies applied and deleted from Lockstep, with saved access plans for someone with the rights;
  - leases browsed, renewed and revoked.
- **Developer slices (wave 4):**
  - PKI: issue a certificate, see issuers and roles, and include issued certificates in the expiry dashboard;
  - database: connections and roles, and generated credentials;
  - the Transit playground.
- **Sign-in and overview (wave 5):** login MFA in the web UI and CLI, and the overview.
- **Correctness:** the policy matcher follows Vault 2.2.2+ as well as 1.x.

**Left:**
- **Try this policy:** a short-lived token with a draft policy, to check access for real.
- **Generate a policy for this folder,** from Browse.
- **Userpass users:** read, compare, create and reset passwords on dev Vaults. Also LDAP group mappings, read-only and compared.
- **Group policies:** editing them.
- **Configuration:**
  - profiles that pair names that differ between Vaults;
  - copying a role or mount tuning to the other side, through the access review and plans;
  - Azure, GCP and LDAP engine roles;
  - comparing custom metadata as an option.
- **Links into the Vault UI** from objects Lockstep shows.
- **Tokens:** renew a connection's token.
- **Namespaces (policy builder phase 7) ENT:** needs an Enterprise Vault to test against. License expiry ENT in the overview goes with it.
- **Keeping up with Vault releases:**
  - a scheduled CI job that checks the matcher against each new Vault release (`vault-latest` is pinned by hand today);
  - possibly moving the dev stack to Vault 2.x.
