# Proposal: continuous drift detection

**Status:** phases 1–6 implemented (2026-11-26), signed baselines and waivers (§8a, 2026-11-27); decisions made (§10) · **Written:** 2026-11-25 · **Decided:** 2026-11-25 · **Owner:** unassigned

Lockstep is a tool you **run**: someone signs in, compares and acts. Teams that rely on environments matching also want a **control**, something that notices drift without anyone looking. The CLI already does most of the work: `lockstep compare` writes a JSON or YAML report and exits like `diff` (0 same, 1 different, 2 couldn't compare). This proposal adds the pieces around it, cheapest first. In-app scheduling comes last and only if needed.

It also collects the coverage additions from the review that fit "compare environments": KV v1, more configuration drift, and an environment matrix.

---

## 1. Goals and non-goals

**Goals**
- Fail a pipeline, or raise an alert, on **new** drift only.
- Give security and platform teams reports in the formats their tools already read.
- Show, for many environments at once, which one is the odd one out.

**Non-goals**
- A monitoring system. Lockstep emits results; Prometheus, Alertmanager, CI and chat tools do the alerting.
- Storing values. Baselines and history hold statuses and hashes of statuses, never values or value hashes.

---

## 2. CLI: baselines, formats, waivers

- **Baseline:** `lockstep compare … --baseline drift.json --fail-on new`. A baseline is a previous report, statuses only.
  - `--fail-on`: `any` (today), `new` (only differences not in the baseline), or `changed` (new or resolved).
  - `lockstep baseline update` writes a fresh one. A baseline can be signed with the plan key ([promotion governance](promotion-governance.md) §2) so a pipeline can tell it hasn't been edited.
- **Formats:** `--format json|yaml|sarif|junit|markdown|csv`. SARIF puts drift in GitHub's code-scanning view and JUnit in any CI's test tab. Markdown is for PR comments, CSV for people who don't read YAML.
- **Waivers:** `waivers.yaml` lists accepted differences, each with `path`, `key`, `owner`, `reason` and `expires`. An expired waiver fails the run. This is the same idea as the accepted-risk list in the security scan.

## 3. Kubernetes CronJob recipe

A documented, chart-optional `CronJob`:
- runs `lockstep compare` with Kubernetes auth;
- writes the report to a ConfigMap or object storage;
- pushes three gauges to a Pushgateway: `lockstep_drift_keys{left,right,mount,status}`, `lockstep_compare_success`, and `lockstep_compare_duration_seconds`.

An Alertmanager rule example goes in the docs. This gets teams continuous checks without any server-side scheduling.

## 4. CI integrations

- **A GitHub Action and a GitLab CI component:** sign in with Vault JWT/OIDC auth (the CI's own identity token), run a compare against a checked-in baseline, upload SARIF, and comment a Markdown summary on the PR.
- **A least-privilege example policy:** `list` plus `read` on metadata and data for the compared paths only.
- **Policy and config as code:**
  - `lockstep policy diff --dir ./policies` compares HCL files in Git with the live Vault's policies, using the existing parser and comparison.
  - `lockstep config diff --file vault-config.yaml` does the same for mounts and auth.

  Teams that manage Vault with Terraform or plain files get "Git says X, Vault says Y" without running `terraform plan`.

## 5. Server metrics

- `/metrics` (`LOCKSTEP_METRICS=on`, off by default) in Prometheus format:
  - requests by route and status, and their latency;
  - Vault calls by host and status, and their latency;
  - active sessions;
  - rate-limit refusals.

  Labels never include paths or identities.
- **OpenTelemetry traces,** optional, using the request ID that the server log already has.

## 6. Coverage that fits the mission

- **KV v1, read-only.** List and compare KV v1 mounts. Copy *from* KV v1 *into* KV v2 (never write v1). That makes Lockstep useful in the migrations where KV v1 still lingers. KV v1 was out of scope; this reverses that only for reading (decided, §10.2).
- **Namespaces.** Presets and connections already take a namespace. Add:
  - a namespace picker that lists the child namespaces;
  - comparing the same path across namespaces;
  - the policy builder's phase 7.

  OpenBao 2.3+ has namespaces, so this can be tested without an Enterprise licence.
- **More configuration drift** in the Configuration tab:
  - audit devices, with a warning when a side has none;
  - password policies, token roles, quotas;
  - MFA methods and enforcement;
  - the plugin catalog;
  - identity groups and aliases, compared by name rather than cluster-specific IDs.

  Enterprise-only items (Sentinel, replication, licence expiry) stay read-only and best-effort until an Enterprise licence is available for testing. Features that OpenBao also has, namespaces above all, are tested against OpenBao only (§10.3).
- **Engines Lockstep doesn't model yet** (TOTP, Consul, Nomad, RabbitMQ, transform…): a generic read-only adapter that lists objects and compares their fields, with the explicit sensitive-field handling from [trust fixes](trust-fixes.md) 2. It says when a list is cut off (today, at 200 objects without saying so).

## 7. Environment matrix

Compare one baseline (say, prod) with *n* environments (dev, test, staging, previews) on the same mount layout, using each pair's comparison profile.

The result is a grid: rows are secrets and keys, columns are environments, and each cell says equal, different, missing or not compared. It's sorted so the **odd one out** is first: a key that differs in only one environment is the likeliest mistake.

This is the dev-environment use case at a glance, and it reuses the pairwise engine as it is.

## 8. Small UX additions

- **Permalinks:** the URL carries the Vault preset, mount, prefix, profile and path (never values or connection IDs). Opening it signs in and runs that comparison.
- **Progress and Cancel** for big comparisons, and the concurrency per side as a setting.
- **An HTML report:** the Results view saved as one file, statuses only.
- **Accessibility:** keyboard navigation for the tree and dialogs, checked with axe in the browser tests.

---

## 8a. Signed baselines and waivers

*Added 2026-11-27, with the decisions in §10.*

**The problem.** A drift check passes when every difference is in the baseline or waived. Both are plain files in the repository, so anyone who can push can add a line and hide new drift. Signing means that changing what's accepted needs the signing key, not just write access to the repository.

**Signing.**
- `lockstep baseline update FILE --sign` writes the baseline and signs it. `lockstep baseline sign FILE` signs an existing one, for example after its change was reviewed.
- `lockstep waivers sign FILE` signs a waivers file. The signature goes at the end of the file, so comments and the layout of the waivers above stay as they are.
- The key is the plan signing key: `LOCKSTEP_PLAN_SIGNING_KEY`, an Ed25519 key that `lockstep plan-key` makes. Signing without it is refused, because there's no meaningful HMAC fallback outside a server.
- The file gains `issuer` (name and key ID) and `signature`. The signature covers the parsed content and the issuer. For waivers, a comment or re-indenting doesn't break it, but any change to a waiver does.

**Checking.**
- `lockstep compare --baseline … --waivers …` checks a signed file against `LOCKSTEP_PLAN_TRUSTED_KEYS`, plus the key's own public half when the signing key is set.
- If the file was edited, is signed by a key that isn't trusted, or has a signature it can't read, the run exits 2 ("couldn't compare"). It never passes quietly.
- If no trusted keys are set, a signed file is used and reported as not checked.
- `--require-signed` also refuses unsigned files, and needs trusted keys. Without it, unsigned files work as before, so existing pipelines don't break.
- The summary names the signer.

**Where it applies.**
- `compare`, and `lockstep matrix` for each environment's `accepted:` file, with the same `--require-signed`.
- The GitHub Action gains two inputs: `require-signed`, and `trusted-keys` (a variable, not a secret: they're public keys).
- The chart's `driftCheck` gains `requireSigned`, and passes `plans.trustedKeys`, never the signing key.
- The Matrix tab: the server checks a signed accepted-drift file against its own trusted keys. It refuses an edited one and shows the signer.

**How to set it up.** The job that checks drift gets only the public key. The private key stays with whoever approves baseline changes, for example a protected CI job that runs after review, or an admin's machine. If the checking job could sign, a signature would prove nothing.

---

## 9. Phases

1. CLI `--baseline`, `--fail-on` and `--format sarif|junit|markdown|csv` (§2). This is the foundation for everything else. **Done:** with waivers and JSON too. Signed baselines and waivers followed once the plan key existed (§8a, 2026-11-27).
2. The CronJob recipe and Pushgateway metrics (§3), and `/metrics` (§5). **Done:** the chart's `driftCheck` CronJob and [drift monitoring](../drift-monitoring.md). The report goes to the job log, not a ConfigMap. The server counts sign-ins instead of active sessions, because a stateless server can't see sessions. OpenTelemetry traces wait for demand.
3. The GitHub Action (§4), and policy diff against a directory. **Done:** `action.yml` and `lockstep policy diff --dir`. The least-privilege policy was already in the security guide. A GitLab CI component and `config diff --file` wait for demand. The GitLab path is the CLI, as in the [CI guide](../guides/detect-vault-secret-drift-in-ci.md).
4. KV v1 read-only, and the namespace picker (§6). **Done:** KV v1 in Compare and the CLI (copy from it into KV v2; writes refused in the Vault client), and a namespace picker that opens a child namespace with the same sign-in. The policy builder's phase 7 is left for its own proposal.
5. Environment matrix (§7). **Done:** the Matrix tab and `lockstep matrix FILE`. Each environment is compared with the baseline, which is read once. Comparing environments with each other (to show that dev and test agree with each other but not with prod) would take another comparison per pair, so it waits for demand.
6. Configuration drift additions and the generic adapter (§6). **Done:** a System settings section (audit devices with the no-audit warning, password policies, token roles, quotas, MFA methods and enforcements, registered plugins, identity entities by name and alias) and generic engine objects, with cut-off lists named. Identity groups were already compared in Policies. Sentinel, replication and licence details stay out until an Enterprise licence is available for testing.
7. In-app scheduled comparisons with webhooks, only if 1–3 leave a gap.

## 10. Decisions (2026-11-25)

1. **Both an interactive tool and a drift monitor, CLI first.** Phases 1–3 come first. The CLI and CronJob path gives a monitor without a scheduler or database in the server, which keeps the server stateless (sessions in cookies, nothing stored). In-app scheduling (phase 7) would end that and needs storage, so it waits for demand.
2. **KV v1: read-only.** Compare KV v1 mounts, and copy from KV v1 into KV v2. Lockstep never writes to KV v1.
3. **Enterprise features are tested on OpenBao only** while no Vault Enterprise licence is available. Where OpenBao has the feature (namespaces), the tests run against the local OpenBao. Where it doesn't (Sentinel, replication, licence expiry), the feature stays read-only and best-effort, and is documented as untested.
4. **Signed baselines and waivers (2026-11-27):**
   - Both are signed, with one `--require-signed` covering them.
   - It's opt-in for now: it can become the default for a run with trusted keys at the next minor release.
   - They're signed with the plan key, not a separate one: one fewer secret, and the trust lists already exist.
