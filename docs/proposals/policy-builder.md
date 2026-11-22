# Proposal: policies and roles ("policy builder")

**Status:** phases 1 (explain and lint), 2 (compare across Vaults), 3 (build, suggest, export), 4 (Kubernetes and JWT/OIDC roles) and 5 (apply from Lockstep, saved access plans) built; phase 6 partly built (AppRole); phase 7 (namespaces) not started · **Written:** 2026-11-21 · **Updated:** 2026-11-21 with decisions (section 8); all questions settled · **Owner:** unassigned

Vault's access control is powerful but hard to get right. A policy is a list of paths and capabilities. The paths for KV v2 aren't the paths people see in the UI. Wildcards behave in ways that surprise people, and a policy does nothing until a role or group points at it. The Vault UI shows policies as raw text and roles as long forms, with no way to see what they add up to.

This proposal adds a **Policies** area to Lockstep for four jobs:
- **explain** a policy against a real secrets engine;
- **build** policies and roles from plain choices, with suggestions from how the secrets are laid out;
- **compare** policies and roles across two Vaults;
- **apply** them, with the same review, checks and audit log as copying secrets, or **export** them as files for an admin.

Kubernetes and JWT/OIDC roles come first.

---

## 1. Goals and non-goals

**Goals**
- Make it obvious what a policy allows: per secret, in plain words, on the real tree of a mount.
- Let people describe access as "who can do what, where", and generate correct Vault policies from that, KV v2 paths included.
- Suggest a sensible set of policies from the shape of a secrets engine (`<app>/<env>/…`).
- Create and edit **Kubernetes** and **JWT/OIDC** auth roles that use those policies, with the common mistakes caught.
- Compare policies and roles between two Vaults (dev and prod, old cluster and new), and copy them across with rewrites (`prod` → `staging`).
- Apply from Lockstep with a diff and review, or hand an admin a bundle of files that does the same.

**Non-goals**
- Replacing Terraform or another source of truth. Lockstep can *produce* Terraform; it doesn't manage state.
- Every Vault feature on day one. These come later, or are only kept as text when they're found:
  - Sentinel and EGP/RGP policies (Enterprise);
  - control groups;
  - `allowed_parameters`, `denied_parameters` and `required_parameters`;
  - policies for secrets engines other than KV v2.
- Root-level administration: Lockstep never edits the `root` or `default` policies, and doesn't manage tokens, auth mounts or secrets engines.

---

## 2. What it would look like

A new **Policies** tab, next to *Compare*, *Certificate expiry*, *Sync plans* and *Export & import*. It has four views.

### 2.1 Explain: what does this policy allow?

Pick a connection and a KV v2 mount, then open an existing policy, paste one, or start a new one. Lockstep lists the mount (as Compare does) and shows what the policy allows on every secret:

```
Policy: payments-dev     on  Vault A · app-config                 [ HCL | Rules ]

                               see names  read  write  delete  destroy  history
  payments/dev/db                  ✓        ✓     ✓      ✓       –        ✓
  payments/dev/api                 ✓        ✓     ✓      ✓       –        ✓
  payments/test/db                 ✓        ✓     –      –       –        ✓
  payments/prod/db                 ✓        –     –      –       –        –
  shared/certs/ca                  –        –     –      –       –        –   no rule matches

  Rule used for the selected secret:  path "app-config/data/payments/dev/*"  (2nd of 6)
  ⚠ "app-config/metadata/*" allows listing the whole mount: names of every secret are visible
```

- Each cell says **which rule** decided it, because the most specific match wins and that's where people get lost.
- **Several policies at once** shows the union of what they allow, with `deny` winning, as Vault does. The set can come from:
  - a role;
  - **the signed-in token**, which is always possible (`auth/token/lookup-self`);
  - **another token or an identity** (an entity, or a group with its member entities): its own policies plus those of its groups. Reading these needs `auth/token/lookup` or read access under `identity/`.

  When the signed-in user lacks a right, Explain says exactly which one is missing (for example "can't read `identity/group/id/…`: group policies aren't included") and shows what it could work out, marked incomplete. It never presents a partial set as the whole answer.
- **Lint warnings:**
  - KV v2 paths without `data/` or `metadata/`;
  - `*` used where `+` was meant;
  - `list` granted on `data/`, where it does nothing;
  - rules that never match anything in this mount;
  - rules hidden by a more specific one;
  - broad grants (`*` at the mount root, `sudo`, anything under `sys/`).
- **Templated paths** such as `{{identity.entity.name}}` are shown as templated, and can be tried with a value you type.

This view is read-only and useful from day one, which is why it's the first phase.

### 2.2 Build: who can do what, where

Rules are written as access to folders of secrets, not as Vault paths:

```
Policy: payments-dev                         Mount: app-config

  Where                  See names  Read  Write  Delete  Destroy  History
  payments/dev/**           [x]      [x]   [x]    [x]     [ ]      [x]
  payments/test/**          [x]      [x]   [ ]    [ ]     [ ]      [x]
  payments/prod/**          [x]      [ ]   [ ]    [ ]     [ ]      [ ]
  + Add rule      Advanced: edit Vault paths and capabilities directly

  ── Generated HCL ─────────────────────────────────────────────
  path "app-config/data/payments/dev/*"      { capabilities = ["create", "read", "update", "patch", "delete"] }
  path "app-config/metadata/payments/dev/*"  { capabilities = ["list", "read"] }
  path "app-config/delete/payments/dev/*"    { capabilities = ["update"] }
  path "app-config/undelete/payments/dev/*"  { capabilities = ["update"] }
  ...
```

How the plain choices map to KV v2 paths (the part people usually get wrong):

| Choice | Vault paths and capabilities |
|---|---|
| See names | `list` on `<mount>/metadata/<folder>` and below |
| Read | `read` on `<mount>/data/…` |
| Write | `create`, `update`, `patch` on `<mount>/data/…` |
| Delete (soft) | `delete` on `<mount>/data/…`, `update` on `<mount>/delete/…` and `<mount>/undelete/…` |
| Destroy | `update` on `<mount>/destroy/…`, `delete` on `<mount>/metadata/…` |
| History | `read` on `<mount>/metadata/…` (versions, dates, Lockstep's "last changed") |

The **Explain** matrix updates as you edit, so you see the effect on real secrets before saving. **Advanced** gives the raw paths and capabilities, so anything Vault supports is still possible; Lockstep keeps rules it can't show as choices as text, untouched.

### 2.3 Suggest: policies from the layout

Lockstep looks for structure in the tree. It finds levels whose values repeat across branches with few distinct values (`dev|test|staging|prod`: environments), and the levels above them (apps or teams). A [comparison profile](../usage.md#comparison-profiles)'s mappings (`services/*/prod/**` ⇄ `services/*/staging/**`) are used as hints when one is selected.

```
Detected layout:  <app>/<env>/<secret>      apps: payments, orders, search
                                            envs: dev, test, prod
                  shared/**                 (no pattern: 4 secrets)

Suggested policies                                                      [ Use selected ]
  [x] <app>-developer   read+write <app>/dev/**, read <app>/test/**, names only in prod   ×3
  [x] <app>-<env>-app   read <app>/<env>/**: for the app's Kubernetes or CI role          ×9
  [ ] app-config-read   read everything, no writes: auditors and drift checks in CI
  [ ] app-config-admin  everything except destroy
```

- Suggestions are **starting points**. Each opens in the builder, and nothing is created until you save.
- **Your own patterns.** You can describe how you want suggestions shaped, instead of relying on detection. A suggestion pattern has a layout, names, rules and the roles to go with them:

  ```yaml
  # A suggestion pattern (also stored as JSON, shared by the server or kept per browser)
  name: per-app-and-env
  layout: "{app}/{env}/**"            # what each level of the tree means
  values: { env: [dev, test, prod] }  # optional: limit or order the detected values
  policies:
    - name: "{app}-{env}-app"
      rules:
        - { where: "{app}/{env}/**", can: [read, history] }
    - name: "{app}-developer"
      rules:
        - { where: "{app}/dev/**",  can: [names, read, write, delete, history] }
        - { where: "{app}/test/**", can: [names, read, history] }
        - { where: "{app}/prod/**", can: [names] }
  roles:
    - kind: kubernetes
      mount: kubernetes
      name: "{app}-{env}"
      service_accounts: ["{app}"]
      namespaces: ["{app}-{env}"]
      policies: ["{app}-{env}-app"]
    - kind: jwt
      mount: gitlab
      name: "{app}-{env}-deploy"
      template: gitlab-ci
      bound_claims: { project_path: "mygroup/{app}", ref: "main" }
      policies: ["{app}-{env}-app"]
  ```

  Lockstep matches the layout against the tree, fills in `{app}` and `{env}` for every match, and shows the resulting policies and roles as suggestions. Built-in patterns cover common layouts. Teams can share theirs the same way as profiles: from the server (`LOCKSTEP_POLICY_PATTERNS`) or kept in the browser, exported and imported as JSON.
- A pattern can also produce the **policy profile** for comparing its environments, such as `{app}-dev` ⇄ `{app}-prod` with `/dev/` → `/prod/` rewrites, ready to use in **Compare** (section 2.5):

  ```yaml
  compare:
    pair: { env: [dev, prod] }        # one policy profile: dev on the left, prod on the right
  ```
- Suggestions include the **matching roles**, not just policies: for example an `<app>-<env>` Kubernetes role bound to service account `<app>` in namespace `<app>-<env>`, and a CI role for deployments. Each one is a starting point and can be left out.
- The suggester explains why it picked a level ("`dev`, `test` and `prod` appear under every app") and lets you correct it: "level 2 is the environment", "ignore `shared/`".

### 2.4 Roles: Kubernetes and JWT/OIDC

Roles attach policies to identities. Lockstep lists the auth mounts of each type (`sys/auth`) and their roles, and gives each type a form that explains its fields.

**Kubernetes** (`auth/<mount>/role/<name>`):
- the service account names and namespaces it's bound to (`bound_service_account_names`, `bound_service_account_namespaces`);
- the audience, the alias name source, and token policies and TTLs.

**JWT / OIDC** (`auth/<mount>/role/<name>`):
- the role type (`jwt` or `oidc`), `user_claim`, `bound_audiences`, `bound_subject`, `bound_claims` (with glob matching) and `groups_claim`;
- the redirect URIs for OIDC, and token policies and TTLs;
- templates for common issuers, which fill in the claims:
  - **GitLab CI**: `project_path`, `ref`, `ref_protected`;
  - **GitHub Actions**: `repository`, `ref`, `environment`;
  - **Kubernetes service account issuer**;
  - **Dex / Keycloak / Entra ID** groups.

Checks and warnings:
- a JWT role with no bound claims or subject (anyone with a token from that issuer could log in);
- `*` in bound service-account names or namespaces;
- policies the role names that don't exist on that Vault;
- very long TTLs.

From a policy, **Who gets this?** lists every role (in the supported mounts) that grants it. From a role, the Explain view shows what it allows overall.

### 2.5 Compare across Vaults

The same left/right layout as secrets, for policies and roles:

```
Policies         ◧ Vault A (dev)          Vault B (prod) ◨
  payments-dev       present                  –                Left only
  payments-app       6 rules                  6 rules          Equal
  orders-app         5 rules                  5 rules          Different: 1 rule
  ci-drift-check     present                  present          Equal (formatting differs)

Kubernetes roles   auth/kubernetes          auth/k8s-prod
  payments           same SA, ns differs      payments-prod    Different: bound_service_account_namespaces
```

- **Policies are compared by meaning, not text.** Each one is parsed into rules (path → capabilities), so comments, whitespace, order and how capabilities are listed don't count. When a policy can't be parsed, it falls back to a text diff and says so.
- **Roles are compared field by field.** Defaults Vault fills in are left out, so a role written with and without `token_ttl = 0` is equal.
- **Policy profiles,** separate from comparison profiles: name mappings (pair `*-dev` with `*-prod`), rewrites inside policies and roles (`/dev/` → `/prod/`, namespace `payments-dev` → `payments`) applied before comparing, and policies or roles to ignore. The import rules' transforms (replace, prefix, suffix, case) are reused. Users write their own and keep them in the browser, or share them from the server (`LOCKSTEP_POLICY_PROFILES`); they export and import as JSON, with a published schema, like comparison profiles.
- **Effective access compare:** for a matched pair, the Explain matrix on both sides at once. *Same policy, but in prod it also matches `payments/prod/legacy/*`.*
- **Copy** a policy or role to the other side, after the rewrites, through the apply review below.

### 2.6 Apply, or export for an admin

Changes are **staged**, as with secrets, then reviewed together:

```
Review: 3 policies, 2 roles on Vault B (prod)

  policy  payments-app      update   + path "app-config/data/payments/prod/*"  [read]
                                     - path "app-config/data/payments/*"       [read]
  policy  orders-app        new
  role    kubernetes/orders new      policies: orders-app · sa: orders · ns: orders
  role    jwt/gitlab-deploy update   bound_claims.ref: "main" → "main|release/*"

  ⚠ payments-app is used by 2 roles and 1 identity group: their tokens change on next login/renew
  [ Apply ]   [ Save as plan… ]   [ Download for an admin… ]
```

- **Diff against what's in Vault now.** A policy write replaces the whole policy, so the review shows exactly what's added and removed.
- **"Changed since you loaded it".** Vault has no check-and-set for policies or roles. Lockstep keeps a hash of what it read, and re-reads just before writing. If something changed, nothing is written for that item, and you're asked to load it again. The gap between the re-read and the write is small but real; the docs will say so.
- **Order:** policies are written before the roles that use them. Deleting is a separate, explicit action that's never staged by a copy.
- **Audit log:** every write or delete is logged with who, where, what (policy name, role name, a hash of the content) and the outcome.
- **Permissions:**
  - policies need `create`/`update` on `sys/policies/acl/<name>`;
  - roles need `create`/`update` on `auth/<mount>/role/<name>`;
  - reading needs `list`/`read` on the same paths.

  The review checks this with `sys/capabilities-self`, as it does for secrets. People without these permissions can still build and export.
- **Saved plans:** **Save as plan…** writes a signed plan, like a sync plan, for someone with admin rights to check and apply in Lockstep. Nothing in it is secret, so it can go in a ticket.

**Download for an admin…** produces a zip:

```
lockstep-policies-2026-11-21/
  README.md                  what this changes, generated from the review
  policies/payments-app.hcl
  policies/orders-app.hcl
  roles/kubernetes/orders.json
  roles/jwt/gitlab-deploy.json
  apply.sh                   vault CLI: VAULT_ADDR/VAULT_TOKEN, --dry-run, stops on the first error
  terraform/                 optional: vault_policy, vault_kubernetes_auth_backend_role, vault_jwt_auth_backend_role
```

### 2.7 Which output for an admin

**Recommendation: HCL plus `apply.sh` by default, with Terraform as an option you tick.**

- **HCL + a `vault` CLI script** works everywhere, needs nothing but the CLI, and reads like what an admin would type themselves. Each step is one `vault policy write` or `vault write auth/…/role/…`. `--dry-run` prints the steps and the diff against the live Vault without writing. Those are the files that go in a change ticket or a Git repo.
- **Terraform** is the right choice where Vault is already managed with Terraform. There, applying from Lockstep, or with the script, would be undone by the next `terraform apply`. Lockstep generates resource blocks with the same content and an `import` block for anything that already exists, so the team can adopt it into state. It doesn't run Terraform or touch state. You choose:
  - **the tool:** Terraform (`hashicorp/vault` from the Terraform registry) or OpenTofu (the same provider from the OpenTofu registry, with OpenTofu's syntax and features where they differ);
  - **the provider version:** the output always pins one (`required_providers` with `version = "~> X.Y"`). Lockstep offers the versions it was tested with, the newest by default, and you can pick an older one if your team is on it;
  - **layout:** one file per policy and role, or one file, and whether to include the `import` blocks.
- **Applying from Lockstep** is best for development Vaults and for teams without another source of truth. A server setting, `LOCKSTEP_POLICY_APPLY` (`on` / `plans-only` / `off`), lets an admin keep Lockstep to building and exporting where Terraform owns Vault.

---

## 3. How it works inside

### 3.1 Matching paths like Vault does

Explain and Compare need to know which rule Vault would use for a path. Vault has no API to test a policy without saving it, so Lockstep reimplements its matching:
- exact paths, `*` at the end (prefix match) and `+` (exactly one segment);
- when several rules match, Vault's documented priority decides:
  1. the first wildcard comes later in the path;
  2. no trailing `*`;
  3. fewer `+` segments;
  4. a longer path;
  5. lexicographic order last.
- across several policies, capabilities are combined and `deny` wins.

This must match Vault exactly, or the matrix would mislead people. It's checked against a real Vault (section 7). Where the simulation is unsure (templated paths, parameter constraints), the cell says so instead of guessing.

### 3.2 Parsing policies

Policies are HCL (or JSON). Lockstep parses them into rules, keeps unknown blocks and fields as they are, and writes HCL back in a stable format. A policy edited in Lockstep only changes where you changed it. If the parser can't read a policy, it's shown as text, can still be compared as text, and can't be edited as rules.

### 3.3 The tree

Explain and Suggest use the same tree listing as Compare: `LOCKSTEP_MAX_TREE_SECRETS`, with no-access folders reported as such. No values are read: only the names of secrets matter.

### 3.4 APIs used

| What | Vault API |
|---|---|
| List / read / write / delete policies | `LIST`, `GET`, `PUT`, `DELETE` `sys/policies/acl[/<name>]` |
| Find auth mounts | `GET sys/auth` (or `sys/internal/ui/mounts` when that's all the token may read) |
| Kubernetes and JWT/OIDC roles | `LIST auth/<mount>/role`, `GET`/`POST`/`DELETE auth/<mount>/role/<name>` |
| Permission checks | `POST sys/capabilities-self` |
| Which roles use a policy | listing roles in the supported mounts; identity groups later |

### 3.5 Lockstep API and CLI (sketch)

- **Web API:**
  - `POST /api/policies/explain` with a policy set and a side; it returns the matrix;
  - `/api/policies/suggest`;
  - `/api/policies/compare`;
  - `/api/policies/preview` and `/api/policies/apply`, like sync;
  - `/api/policies/export`, which returns the zip.
- **CLI:**
  - `lockstep policy explain <name> --mount app-config`;
  - `lockstep policy suggest --mount app-config`;
  - `lockstep policy compare`, with diff-style exit codes for drift checks between clusters;
  - `lockstep policy export`.

---

## 4. Security and safety

- **Least surprise:**
  - `root` and `default` are never edited;
  - deleting a policy or role is always a separate, explicit action, never part of a copy;
  - nothing is written without the review.
- **Broad grants are called out** in Build, Review and Compare:
  - `*` on a mount root;
  - `sudo`;
  - anything under `sys/`, `auth/` or `identity/`;
  - destroy rights;
  - JWT roles without bound claims.
- **Escalation:** someone who may write policies can already grant themselves anything. Lockstep doesn't change that, but it makes it visible:
  - the review flags changes to policies that the signed-in token holds itself;
  - the audit log records them.
- **No secret values** are needed or read by any of this. Exports and plans contain policies and role settings only. OIDC client secrets are left out: they belong to the auth mount's config, which Lockstep doesn't touch.
- **Configuration:** `LOCKSTEP_POLICY_APPLY` (`on` / `plans-only` / `off`, chart value `policyApply`). Vault's own policies still decide who may write.

---

## 5. Pros and cons

**For**
- It tackles a real pain point. Explain alone, the matrix with the deciding rule, answers "why can't my app read this?" in seconds.
- It reuses what Lockstep has:
  - the tree listing and the left/right compare;
  - profiles and import transforms;
  - the review, staged changes and signed plans;
  - the audit log and the CLI exit codes.
- It fits the development-environment focus. Each new app or environment needs policies and roles, and suggestions make that consistent across dev, test and prod.
- Comparing policies across clusters catches access drift as well as secret drift.

**Against**
- **Correctness is everything.** A simulator that disagrees with Vault would be worse than none. This needs a strong test suite against a real Vault, kept up with Vault releases.
- **Bigger scope.** Policies and roles are a second product area next to secrets. Each auth method adds forms, defaults and comparisons to maintain.
- **Ownership conflicts.** Where Terraform manages Vault, applying from Lockstep creates drift. That's why there's the setting and the Terraform export.
- **No check-and-set** for policies and roles in Vault: Lockstep can narrow the race, not close it.

---

## 6. Possible phases

1. **Explain and lint** (read-only): parse policies, match paths like Vault, the matrix on a real tree, the deciding rule, warnings, several policies at once. Also `lockstep policy explain`.
2. **Compare policies across Vaults:** meaning-based diff, name mappings, rewrites, the effective-access compare. Also `lockstep policy compare` for CI.
3. **Build and suggest → export:** the builder with KV v2 mapping, layout detection, the HCL + `apply.sh` bundle, optional Terraform.
4. **Kubernetes and JWT/OIDC roles:** list, explain, build (with issuer templates), compare, export, and "who gets this policy".
5. **Apply from Lockstep:** staging, review with diffs, the hash re-check, audit, saved plans, `LOCKSTEP_POLICY_APPLY`.
6. **More identities:** LDAP groups, identity groups and aliases, AppRole, userpass users, and parameter constraints.
7. **Namespaces (Vault Enterprise), last:** policies and roles per namespace, a namespace picker on each side, and comparing across namespaces (`team-a` in one cluster against `team-a` in another, or two namespaces in one). Wanted, but left until the rest is solid, because it touches every view.

Phases 1 and 2 are useful on their own, and settle the hardest part, the matching, before anything can write.

---

## 7. How to test it

- **Matching against Vault itself.** For each test policy:
  - generated and hand-written, including tricky cases: overlapping `*` and `+`, `deny`, priority ties, several policies;
  - write it to the dev Vault and create a token with it;
  - ask Vault for the capabilities on many paths (`sys/capabilities`);
  - check Lockstep's matrix gives exactly the same answers.

  Run in CI against the Vault version in the compose stack on every change, and against the latest Vault release on a schedule. Older Vault versions aren't tested.
- **Round trips:** parse → write → parse gives the same rules. Policies edited in Lockstep keep comments and unknown blocks.
- **Suggestions** on seeded layouts: `<app>/<env>/…`, `<env>/<app>/…`, flat, and mixed with no pattern.
- **Roles:** create Kubernetes and JWT roles in the dev Vaults (the compose stack already has Dex and k3s), log in with them, and check the token's policies.
- **Browser tests:**
  - explain a policy;
  - build one from a suggestion;
  - compare across Vault A and Vault B;
  - apply, and see the "changed since you loaded it" conflict;
  - download the bundle and run `apply.sh --dry-run` against a dev Vault.

---

## 8. Decisions

Settled on 2026-11-21:

| Question | Decision |
|---|---|
| Policy profiles: part of comparison profiles, or separate? | **Separate.** Users write and share their own policy profiles (section 2.5) |
| How far should suggestions go? | **Policies and the matching Kubernetes and CI roles.** Users can also give their own **suggestion patterns** for how suggestions are shaped (section 2.3) |
| Explain for other tokens and identities? | **Yes.** It combines the token's or identity's policies, and says which rights the signed-in user is missing when it can't see everything (section 2.1) |
| Terraform or OpenTofu? Pin the provider? | **Both, the user picks.** The output always pins a provider version, chosen from the tested ones (section 2.7) |
| Namespaces? | **Yes, as the last phase** (phase 7) |
| Can a suggestion pattern produce a policy profile? | **Yes.** A pattern can also generate the policy profile for comparing its environments (section 2.3) |
| Which Vault versions to check the matching against? | **The latest release**, on a schedule, as well as the compose stack's version on every change (section 7) |
| Kubernetes and JWT/OIDC roles first? | **Yes** |
| Apply from Lockstep, or files only? | **Apply from Lockstep, with export for an admin as an option.** HCL plus `apply.sh` by default, Terraform or OpenTofu optional |
