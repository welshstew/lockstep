# Changelog

All notable changes to Lockstep. Versions follow [Semantic Versioning](https://semver.org/);
the image, the Helm chart and the app share one version.

## [Unreleased]

### Added

- **A self-test of the published GitHub Action** (`.github/workflows/action-selftest.yml`): `welshstew/lockstep@v0.12.0` against two throwaway Vault dev servers in the job, logged in with the job's own OIDC token, with a signed baseline. It must report exactly the new drift and upload SARIF, and must refuse the baseline once it's edited. It runs when the action changes, or on demand.

## [0.12.0] - 2026-11-27

Governance and drift checks you can trust more: several approvers chosen by Vault policy, plans limited to named installations from the UI, rules for how exports are protected, and signed drift baselines and waivers. The Matrix takes an export file as its baseline and accepted drift per environment, Browse and the Matrix get a Connections list, and the dev and demo stacks run Vault 2.2.2.

**Upgrading from 0.11:** nothing to change. New settings are off or permissive by default, unsigned baselines work as before, and old `#/browse/left/…` links still open. For contributors: the test profile's `vault-latest` (`VAULT_LATEST_IMAGE`) is now `vault-legacy`, and `VAULT_IMAGE` sets the dev Vaults' image.

### Added

- **Signed drift baselines and waivers:**
  - Signing uses the plan key (`LOCKSTEP_PLAN_SIGNING_KEY`): `lockstep baseline update --sign`, `lockstep baseline sign FILE` and `lockstep waivers sign FILE`.
  - `compare` checks a signed file against `LOCKSTEP_PLAN_TRUSTED_KEYS`, and exits 2 if it was edited or signed by an untrusted key. `--require-signed` refuses unsigned files too.
  - The rest follow suit:
    - `lockstep matrix` checks `accepted:` files, and takes `--require-signed`.
    - The Matrix tab checks a signed accepted-drift file and shows its signer.
    - The GitHub Action gains the `trusted-keys` and `require-signed` inputs.
    - The chart's `driftCheck` gains `requireSigned` and `waiversSignature`, and passes `plans.trustedKeys` to the job.
  - Unsigned files work as before. Design: [continuous drift §8a](docs/proposals/continuous-drift.md).
- **Choose how exports are protected:** `LOCKSTEP_EXPORT_PROTECTION` (chart `exportProtection`) and a preset's `export_protection` (chart `vaults[].exportProtection`) limit encrypted exports to some ways: `key`, `passphrase`, `age` or `teams` (only the age keys of the configured teams). The Export panel greys out the others and the server refuses them. Connections and `/api/config` list what's allowed (`export_protection`).
- **Only for, when saving a plan:** a sync or access plan can be limited to named Lockstep installations (its `audience`) from the UI, not only the API. The field suggests this installation's name and the ones it trusts, and points out a name it doesn't know. An opened access plan says who it's for. `POST /api/access/plans` takes `audience`, and `/api/config` lists `plan_servers` (`self` and `trusted`).
- **Several approvers, and approver groups:** `approvals` (a preset's, or `LOCKSTEP_PLAN_APPROVALS`) now goes up to 5, counted by Vault entity: approving twice is refused, and a repeated approval counts once. `LOCKSTEP_PLAN_APPROVER_POLICIES` and a preset's `approver_policies` let only someone holding one of those Vault policies approve, including policies granted through an identity group. The approver's policies are recorded in the signed approval, so installations a plan travels to check the same thing; approvals given where none were required don't count where they are. Chart: `plans.approverPolicies` and `vaults[].approverPolicies`. The check's `approvals` gains `approver_policies`.
- **Undo plans after Browse edits and imports:** **Make an undo plan** is offered after a Browse save, after an applied review of staged Browse edits, and after an import (including what `delete_missing` soft-deleted). Browse writes and rollbacks are put back, a secret the edit created is soft-deleted, and a soft-deleted latest version is undeleted; undeletes, destroys and deletes of older versions can't be undone.
- **Approvals for access plans and undo plans:** `LOCKSTEP_PLAN_APPROVALS` and a preset's `approvals` now cover every kind of plan. An access plan is approved from **Policies → Open an access plan…**, and an undo plan in **Sync plans**, the same way as a sync plan. On a preset with `approvals`, policy, role, group, tuning and engine writes from the Policies tab are refused too, so the Vault changes only through approved plans; **Save as access plan** still works. The `plan.approve` audit event names the kind of plan. API: `POST /api/access/plans/approve`, `POST /api/undo/approve`; the checks return `approvals`.
- **Matrix from an export file, with accepted drift:** the Matrix's baseline can be an export file (**Open an export file…** in its baseline list), such as last release's export, and each environment can take a drift baseline (`base.json`, from `lockstep baseline update` or a drift check) as **Accepted drift**. Accepted differences are shown, marked `*`, but don't count as odd and are listed last; differences no longer there are counted as resolved. `lockstep matrix` takes `accepted:` per environment, and exits 0 when only accepted drift is left. API: `POST /api/matrix` takes an export as `baseline`, and `accepted` / `accepted_name` per environment.
- **A release baseline for the environment matrix:** the seed adds `apps-baseline` to Vault A, the last release of the `apps` applications as in prod. The shared profiles **Release ↔ test: apps** and **Release ↔ dev: apps (ELP rename)** compare it with test and dev in the **Matrix**, so dev's changes since the release come first and the rename disappears. `dev/matrix/apps.yaml` runs the same matrix with `lockstep matrix`. The [rename guide](docs/guides/compare-environments-after-a-rename.md) walks through it.

### Changed

- **The dev and demo stacks run Vault 2.2.2** (pinned by digest), up from 1.21.4. The test profile's `vault-latest` became `vault-legacy` (Vault 1.21.4, `VAULT_LEGACY_ADDR`, `root-legacy`), so the policy matcher's 1.x rules are still checked against a real Vault. The weekly `vault-release` workflow now runs the whole stack on the newest release through `VAULT_IMAGE`. Lockstep itself is unchanged and still supports Vault 1.x. Backend, browser, OpenBao and Kubernetes tests pass on 2.2.2.
- **Demo drift page:** each card's strip is now a fixed 12 hours, one slot per run, so it keeps its length and slides along. It has a time axis, and pointing at a mark shows when that run was and what it found. A full-width screenshot shows the `apps` pair's comparison in Lockstep, and each card links its own under **See this comparison in Lockstep**.
- **A Connections list on Browse and Matrix:** these two tabs show every signed-in connection in one list across the page, with **Sign in to** for another, instead of the left and right cards. Browse explores the one you pick, its mount and prefix under it; switching is one click, and until you pick one it starts on a side's mount as before. Its jump buttons (**Compare this folder…** and the others) put the folder on the left side. The Matrix's baseline is picked in the matrix (any connection or export file; it starts as the left side's), and **Open in Compare** puts the baseline on the left and the environment on the right. Compare and the other tabs keep their side cards. Browse links drop the side: `#/browse/<mount>/<path>`; older links with `left/` or `right/` still open.
- **Tabs scroll when they don't fit:** on a narrower window the top bar's tabs no longer push the page wider; arrows at either end scroll them, and the chosen tab stays in view.

### Documentation

- **[Running the demo locally](docs/guides/run-the-lockstep-demo-locally.md):** start the demo with Podman Compose, the seed job and the demo users, reset the data, run a drift check from the image, and use OpenBao as Vault B. Linked from the README, the landing page and its guides.
- **Demo drift page:** each pair's card has **View base.json**, the baseline the check runs against, to expand or download; the page now refreshes after each run instead of every minute, so an open baseline stays open. The [drift guide](docs/guides/detect-vault-secret-drift-in-ci.md) shows an example baseline.

## [0.11.0] - 2026-11-27

Drift checks in CI and on a schedule, an environment matrix, and promotion with guardrails: a write policy per Vault, signed plans that travel between installations, approvals and undo. Exports can be encrypted with a passphrase or age keys, and stream.

**Upgrading from 0.10:** two defaults changed.
- `LOCKSTEP_EXPORT_MODE` is now `encrypted` (chart `exportMode`): set `any`, or a preset's `"export": "any"`, to allow plain exports again.
- `LOCKSTEP_ALLOW_CUSTOM_CONNECTIONS` is now `false` (the chart's default already was): set `true` to let users type a Vault address.

### Added

- **`vault kv get` output as an export:** a comparison side, the Import panel and `lockstep import` read `vault kv get -format=json` output: one file (its name is the path), a folder of them (**Open a folder of vault kv get files…**, or `lockstep import FOLDER`), or one JSON object of path to output. KV v2 versions and times are kept, KV v1 works too, and deleted or destroyed secrets are listed as not exported. API: `POST /api/exports/from-kv-get`. Phase 6 of [promotion and governance](docs/proposals/promotion-governance.md).
- **Exports protected by a passphrase or age keys:** besides the one-time key, **Protect the file with** offers a passphrase (Argon2id, then AES-256-GCM) and age public keys. An age export holds a standard age file, so whoever has a matching key opens it in Lockstep or with `age -d`, and no key has to be passed around. `LOCKSTEP_EXPORT_RECIPIENTS` (chart `exportRecipients`) names teams to pick from. CLI: `lockstep export --passphrase`, `-r age1…`, `-R keys.txt`; `lockstep import --key-file` takes the passphrase or an age identity file. One-time-key files are unchanged; the new kinds are export version 2. The audit log records how each export was encrypted. Phase 6 of [promotion and governance](docs/proposals/promotion-governance.md).
- **Four-eyes approvals for sync plans** (optional): `LOCKSTEP_PLAN_APPROVALS=1`, or `"approvals": 1` on one preset, makes plans need an approval from someone whose Vault entity differs from the creator's. They choose **Approve** in **Sync plans** after **Check plan**, and the approval is signed into the file without changing the plan. On a preset that asks for it, secrets change only through approved plans: direct copies, Browse edits, imports and destroys there are refused. Audit event `plan.approve`. Chart: `plans.approvals`, `vaults[].approvals`. Phase 5 of [promotion and governance](docs/proposals/promotion-governance.md).
- **Undo plans:** after copies or a plan are applied, **Make an undo plan** downloads a signed file that puts back what was written. Opened in **Sync plans**, it reads each secret's old version from Vault's KV history and writes it again with check-and-set, soft-deletes secrets the apply created, and undeletes ones it soft-deleted. Lockstep never keeps old values. A secret written again since the apply, or whose old version was deleted or destroyed, isn't undone, and applying stops at the first that fails. Apply results now name each target's connection, mount and path. Phase 4 of [promotion and governance](docs/proposals/promotion-governance.md).
- **Plans that travel between installations:** with `LOCKSTEP_PLAN_SIGNING_KEY` (an Ed25519 key; `lockstep plan-key` makes one), sync and access plans are signed with it, and any Lockstep that lists the public key in `LOCKSTEP_PLAN_TRUSTED_KEYS` can verify and apply them. A plan made on dev can then be applied on prod, and rotating the session key no longer invalidates plans. New plans (version 2) record their issuer, expire after 7 days (`LOCKSTEP_PLAN_TTL_HOURS`), can name the installations that may apply them (`audience`), and record the creator's Vault entity ID and token accessor as well as the display name. Audit events now carry the actor's entity ID and accessor. Without a key pair, plans are signed as before. Chart: `plans.*`. Phase 3 of [promotion and governance](docs/proposals/promotion-governance.md).
- **A write policy per Vault:** a preset can be read-only (`writable: false`), limit writes to some paths (`write_paths`, with `*` and `**`), protect others (`deny_paths`), and turn off Destroy (`allow_destroy: false`). One Lockstep can then compare prod and write only to dev. The API refuses what the rules forbid, on top of Vault's own policies. The UI hides copy arrows, edits and Destroy toward a read-only Vault, and every refusal is audit-logged as `write.refused`. The rules follow the Vault's address, so typing it by hand doesn't get round them. Chart: `vaults[].writable`, `allowDestroy`, `writePaths`, `denyPaths`. Phase 1 of [promotion and governance](docs/proposals/promotion-governance.md).
- **More configuration compared:** the Configuration tab and `lockstep config compare` now compare system settings by name rather than cluster IDs: audit devices (with a warning when a Vault has none), password policies, token roles, rate-limit and lease-count quotas, MFA methods and login enforcements, registered plugins and their checksums, and identity entities with their aliases. Engines Lockstep doesn't model (TOTP, Consul, Nomad, RabbitMQ, Transform, Terraform, KMIP and any other plugin's `roles/`, `role/` or `keys/`) are compared generically, with secret fields left out. A list cut off at the limit is now named instead of silently shortened. Phase 6 of [continuous drift](docs/proposals/continuous-drift.md).
- **An environment matrix:** compare one baseline (say prod) with up to 12 environments at once, each under its own comparison profile, in the new **Matrix** tab or with `lockstep matrix environments.yaml`. The grid has a row per secret and key and a column per environment, and puts what differs in only one environment first. **Open in Compare** opens one pair side by side. The CLI writes the grid as text, JSON, YAML, Markdown or CSV, and exits like `compare`. The baseline is read once for all environments. Values are never shown. Phase 5 of [continuous drift](docs/proposals/continuous-drift.md).
- **KV v1, read-only:** KV v1 mounts are offered in the side picker (*KV v1, read-only*), and compared in the web UI and the CLI. You can copy from them into KV v2, for migrating off KV v1. Lockstep never writes KV v1. The Vault client refuses every write, edit, delete and metadata change on a KV v1 mount. Sync plans and `lockstep apply` toward one are refused with the reason, the results show no arrows into it, and the other tabs leave a KV v1 side out. Phase 4 of [continuous drift](docs/proposals/continuous-drift.md).
- **A namespace picker** (Vault Enterprise, OpenBao 2.3+): a side lists the child namespaces it can see and moves into one with the same sign-in, so comparing the same path across namespaces takes one sign-in. ↑ goes back up. Closing a namespace keeps the sign-in it came from, and signing out closes its namespaces too. Tested against OpenBao.
- **A GitHub Action** (`uses: welshstew/lockstep@v0.11.0`). It logs in to Vault with the job's OIDC token (or tokens from secrets), compares against a baseline, uploads SARIF to code scanning, and comments a summary on the pull request, updating it on later runs. It also writes the summary to the job's page and fails the step on new drift. Inputs never reach a shell script. Phase 3 of [continuous drift](docs/proposals/continuous-drift.md).
- **`lockstep policy diff --dir policies/`:** compares the HCL or JSON policy files kept in Git with a live Vault's policies, by meaning. It shows which policies differ (with the paths whose capabilities changed), which exist only in files, and which exist only in Vault. `--files-only`, `--ignore`, and a policy profile. Exit codes like `diff`.
- **`lockstep policy compare`** names a policy on one side only by itself, instead of `— ⇄ name`.
- **Scheduled drift checks:** the chart's `driftCheck` CronJob runs `lockstep compare` on a schedule, signed in as its own service account (or with a token from a Secret), with a baseline, waivers and a profile. `--pushgateway URL` pushes gauges to a Prometheus Pushgateway: `lockstep_drift_keys{status}`, `lockstep_drift_new_keys`, `lockstep_compare_success`, the duration and the last success time. A run that can't compare keeps the last counts. `-o drift.prom` writes the same gauges for node_exporter's textfile collector. [Drift monitoring](docs/drift-monitoring.md) has alert rules. Phase 2 of [continuous drift](docs/proposals/continuous-drift.md).
- **`/metrics`** (`LOCKSTEP_METRICS=on`, chart value `metrics.enabled`, off by default): Prometheus metrics for API requests and latency (by route template), calls to each Vault, sign-ins by method and outcome, and 429s. Labels never hold secret paths, users or tokens. `LOCKSTEP_METRICS_TOKEN` requires a bearer token, and `metrics.serviceMonitor` adds a ServiceMonitor.
- **`--left-auth kubernetes`** (and `--right-auth`) in the CLI: log in with the pod's service account token, for jobs running in a cluster.
- **Drift checks that fail only on new drift:** `lockstep baseline update drift.json` records what differs now (paths, keys and statuses, never values), and `lockstep compare --baseline drift.json` exits 1 only for drift that isn't in it. `--fail-on any|new|changed` picks what fails the run. `--waivers waivers.yaml` accepts single differences with an owner, a reason and an expiry date; an expired waiver fails the run. Phase 1 of [continuous drift](docs/proposals/continuous-drift.md).
- **Reports for other tools:** `-o` writes SARIF (GitHub code scanning), JUnit XML (CI test tabs), Markdown (pull request comments), CSV and JSON, chosen by the extension or `--format`, and can be repeated. None of them holds a value. The YAML and JSON reports mark each difference new, known or waived.
- **Not compared, a status of its own:** a key that can't be compared, such as a keystore whose password isn't in the secret, is now *not compared* with the reason, instead of *different*. A secret where nothing else differs gets the same status; the summary, filters, CLI output and report count it. Keystores are opened with a password stored next to them (a key named like `*pass*`, `*pin*` or `*secret*`) or Java's default, so most compare properly, and the reason says which key opened them. Certificates in one-line base64 now say which fields changed. `lockstep compare` exits 1 when a key is not compared, so a CI drift check doesn't pass on what it couldn't check.
- **Keystores compared by their entries:** a PKCS#12 that opens without a password, or a JKS or JCEKS, is compared as its aliases, certificates and keys, so saving it again (timestamps, MAC salt, entry order) no longer makes it different. Differences are named: entries on one side only, a changed certificate (with how it changed), or a different private key.
- **Pattern rewrites:** `{app}-test-db` ⇄ `{app}-dev-db` reads `billing-test-db` as `billing-dev-db`, and copies the other way read it back. A placeholder stands for one word.
- **The profile builder suggests unordered lists and volatile patterns:** keys whose items are in another order, and keys that differ only in a timestamp, date or UUID, with how many keys each makes equal or ignored.
- **Comparison profiles, three new rules:**
  - **Unordered lists:** a key, a field inside its JSON or YAML (`tls.sans`), or a text split on a separator (`a.com, b.com`) whose items are compared regardless of order. "same items in a different order" is equal; duplicates still count.
  - **Volatile patterns:** a regex for parts of a value that change on their own (timestamps, build numbers). Matches are blanked on both sides, and a key that differs only there is marked ignored, with the pattern as the reason. Patterns that match empty text or nest repeats are refused.
  - **Scoped rewrites:** a rewrite can be limited to keys (`*host*`) and secrets (`apps/**`), so `test` → `dev` never changes a word inside a password. Comparing, copying and sync plans all follow the limits.

- **Every key says why it has its status**, in Results and in the CLI report (`reason`), without showing values. For example: "different at `config.db.host`", "differs only in line endings", "different type: number on the left, text on the right", "equal after rewrite `test → dev`", "ignored by profile rule `log_level`". For a key holding JSON or YAML on both sides (an object, or text with one in it), `paths` names every field inside it that differs, `hosts[2]` style for list items. Past 8 levels or 1,000 fields, the value is compared whole from there and the reason says so.
- **Certificates, PEM and wrapped base64 compared by what they hold, on by default:** the same certificate, key or data with other line endings, line wrapping or spacing around the PEM blocks is now **equal**, with the reason saying so ("equal as certificates (same fingerprint; line endings differ)"). Two different certificates say which fields changed, and a renewal says "renewed: new validity". Differences a service could read differently still count, and the reason names them: the PEM label, PKCS#1 against PKCS#8, PEM against base64 DER, a chain's order, base64 padding and alphabet. A profile's new **Compared as text** rules (`exact_keys`) turn this off for the keys they name.
- **Ignore one field inside a value:** an ignored key in a comparison profile can name a `field` (`{"key": "config", "field": "db.password"}`, or `tls.*`). A difference there doesn't count, but any other field that differs still does. The profile editor has a *field* box for it.
- **Audit when values are shown** (`LOCKSTEP_AUDIT_REVEALS=on`, chart value `auditReveals`, off by default): every response that carries secret values adds one `secret.reveal` line to the audit log. That covers Browse **Show**, version diffs and edit previews with values, values shown in Compare, revealed sync and import previews, **Inspect** and its downloads, and unwrapping a shared secret. The line names the identity, Vault, mount, path, version and key names, with the request ID; never the values. See [audit log](docs/usage.md#audit-log).
- **Sign-in throttling, always on:** after 10 failed sign-ins in 5 minutes from one client address, or for one user name on a Vault, sign-in answers `429` with `Retry-After` until the oldest failure is 5 minutes old. Wrong passwords, tokens and second factors count, and a successful sign-in clears that user's count. A warning goes to the server log. Before, only the general per-client limit applied, and it's off by default. `LOCKSTEP_SIGNIN_MAX_FAILURES` (0 turns it off) and `LOCKSTEP_SIGNIN_WINDOW_SECONDS`.
- **Browser security headers from the app itself:** Content-Security-Policy (the app's own scripts only, `frame-ancestors 'none'`), `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy` and `Permissions-Policy` on every response, and `Strict-Transport-Security` when `LOCKSTEP_PUBLIC_URL` is `https`. Before, only the demo had them, from its proxy; a Helm or `docker run` install had none. See [configuration](docs/configuration.md#browser-security-headers).
- **`LOCKSTEP_API_DOCS`** (default `on`, chart value `apiDocs`): `off` hides the Swagger UI at `/api/docs` and `/api/openapi.json`. The public demo turns it off. FastAPI's ReDoc page at `/redoc`, which nothing linked to, is gone.
- **Server logging:** every line now has a UTC timestamp, level and request ID. Each API request gets one line (method, path, status, time, client). Also logged: what the server started with, sign-ins and sign-outs, and Vaults that can't be reached. `LOCKSTEP_LOG_LEVEL=debug` adds every call to a Vault, and `LOCKSTEP_LOG_FORMAT=json` writes one JSON object per line. Responses carry `X-Request-ID`, and an unexpected error answers 500 with that ID, logging the stack trace under it. Values, tokens, passwords, bodies and query strings are never logged. Chart values `logging.level` and `logging.format`. See [configuration](docs/configuration.md#logging).
- **Per-client API limit:** `LOCKSTEP_RATE_LIMIT_PER_MINUTE` (and `LOCKSTEP_RATE_LIMIT_BURST`) limit API requests per client address, answering `429` with `Retry-After` over the limit. Off by default; the public demo uses 180 a minute, so one client can't use up the app.

### Fixed

- **Vaults behind load balancers and proxies:** a redirect from an HA standby came back as an empty answer and failed later with a server error. Now a `307`/`308` is followed (at most twice) to the same Vault or another preset Vault, and anywhere else fails with a clear message, since the token goes with the request. A `LIST` refused by a proxy (`405`, or a `403` without Vault's error body) is asked again as `GET ?list=true`. Reads are retried twice on connection errors and `429`/`502`/`503`/`504`; writes never are. The timeout per Vault call is configurable: `LOCKSTEP_VAULT_TIMEOUT_SECONDS` (default 15), and `timeout_seconds` per preset.
- **Sync plans, while being applied:** a source that changed between the plan's check and its write was only a warning, and its newer value was copied. Now it's a conflict and nothing is written for that secret. Applying also stops at the first secret that isn't written, instead of carrying on: the rest are reported as **not attempted**, and the result says **Partially applied: N of M written** (or **Not applied**) and where it stopped. `docs/cli.md` no longer says a plan "is all or nothing", which was only true of the check.
- **Configuration comparison compared too little:** any field whose name contained words like `secret`, `password` or `credential` was dropped, so database and LDAP `password_policy`, database roles' `credential_type` and `credential_config`, and GCP's `secret_type` were never compared, and copying a database role left them out. Every `false` and `0` was dropped too, so a setting turned off on one side could show as unset, or not show at all. Now secret fields are named one by one and listed as **not compared** (their values still never leave the server); settings that only sound secret are compared and copied; and `false` or `0` is dropped only where it's the default. An unknown field whose name looks secret is still hidden, and marked as such.
- **Policy explainer on OpenBao:** OpenBao was matched with Vault's rules for its version number, so Explain, the policy builder's checks and policy comparison could give the wrong answer where rules with `*` and `+` overlap around a trailing slash. Lockstep now tells OpenBao from Vault and follows OpenBao's own order, including its `scan` capability. The random-policy tests that check Lockstep against the server's own answers now run against both test Vaults, so they cover OpenBao in the weekly OpenBao run. When the server's rules can't be told, Explain says so instead of assuming the newest Vault.

### Changed

- **Big exports stream:** an export is written as its secrets are read, never held whole. The web UI uses the new `POST /api/exports/stream` (NDJSON progress lines, then the result) and shows how many secrets it has read; a plain export streams to the browser as it's read, and an encrypted one is held only as compressed bytes until it's sealed. For 20,000 secrets the server's peak memory went from about 98 MB to about 2 MB. `lockstep export` writes a plain export straight to a temporary file (compact JSON now), renamed into place when complete. `POST /api/exports` still answers in one response. Phase 6 of [promotion and governance](docs/proposals/promotion-governance.md).
- **Breaking: exports are encrypted unless an admin allows plain ones.** `LOCKSTEP_EXPORT_MODE` now defaults to `encrypted` (it was `any`), and so does the chart's `exportMode`. Set `any` to allow plain exports again. A preset's new `export` setting (`any`, `encrypted` or `off`; chart `vaults[].exportMode`) replaces it for that Vault, so plain exports can be allowed from dev and exporting turned off for prod. The CLI isn't affected. The public demo keeps `any`. Phase 6 of [promotion and governance](docs/proposals/promotion-governance.md).
- **Typed values no longer go into sync plans.** A plan keeps a check code for each value typed by hand, made with the server's secret key, and whoever applies the plan types the values again in **Sync plans**. Lockstep refuses any that don't match what the creator typed, and nothing secret sits in the file. Saving such a plan no longer needs the *The plan file will hold the values I typed* box. Plans saved by earlier versions, which hold the values, still apply. API: `/api/plans/check` and `/apply` take `values`. Phase 2 of [promotion and governance](docs/proposals/promotion-governance.md).
- **Read both sides reads each secret once:** building a profile ran the whole comparison up to three times (as it is, with the suggested mappings, with the suggested rewrites), reading every secret on both sides each time. Now each listing, secret and metadata read reaches Vault once per request, and the later passes are worked out from memory. That's a third of the load on a big mount.
- **Breaking: custom Vault addresses are off by default.** `LOCKSTEP_ALLOW_CUSTOM_CONNECTIONS` now defaults to `false`, as the Helm chart already did, so a `docker run` install only calls its preset Vaults. Set it to `true` to let users type an address. With it on, an address is checked properly:
  - It must be exactly `scheme://host[:port]`. One with a user name, path, query or fragment is refused, so `https://vault.example.com@other-host` no longer gets past a loose pattern.
  - `LOCKSTEP_CUSTOM_URL_PATTERNS` is matched against that normalised origin, not the raw text.
  - The host is resolved and refused if any address it resolves to is private, loopback or link-local (`169.254.169.254` included). Set the new `LOCKSTEP_CUSTOM_ALLOW_PRIVATE=true` (chart value `customAllowPrivate`) for a Vault on an internal network.
  - Lockstep connects to the address it checked, on every request, so a DNS answer can't change in between.
  - Redirects from a custom Vault pass the same checks.

  The local compose stack turns both settings on, for its own containers. The CLI is unchanged: it runs as its user and calls any address.
- **Connection status dot:** a side that isn't signed in shows a hollow grey ring instead of the green "connected" dot.
- **Connection list:** each side's **Connection** list now offers every Vault the server is set up for under **Sign in to**, as well as the connections you're signed in to. Picking one opens the sign-in form on that Vault. On the demo, the two OpenBaos are now one click away instead of being hidden behind **New connection**.
- **CI:** a push that only changes Markdown or `docs/` skips the backend, browser and security workflows; a quick gitleaks-only workflow checks it for secrets instead. CI images have fixed names (`lockstep-ci/<service>:ci`), so each build replaces the last instead of keeping one per run. Each compose workflow starts by removing test setups that cancelled runs left behind (`scripts/ci-cleanup.sh`: `lockstep-*` projects idle for more than two hours, and unused per-run images).
- **Release pipeline:** the chart push shows Helm's output when it fails, and retries up to three times. Helm comes from Red Hat's hardened image (`registry.access.redhat.com/hi/helm`, same version 4.3.1) instead of Docker Hub, in CI, `make chart-check` and `make helm-test`.

## [0.10.1] - 2026-11-24

0.10.0 was tagged but never published (its release pipeline couldn't pull Red Hat's base images); everything it held is here.

### Added

- **Comparison profiles, value rewrites:** a profile can pair words between the sides, such as `test` ⇄ `dev` or an application's old and new name. Values are compared with each left word read as its right word, so `logs.test.internal` matches `logs.dev.internal` while a wrong host still shows as different. Whole words only, case-sensitive; certificates, keys and base64 data are never rewritten. Copies apply the rewrites in the copy's direction, and so do sync plans and `lockstep apply`. Keys that are equal only after a rewrite are marked **equal after rewrite**.
- **Profile builder:** **Read both sides** in the profile editor lists both sides' secrets and suggests rules, each with the reason: mappings for folders that look renamed (with a wildcard when an environment segment varies, such as `services/*/prod/**`), and rewrites for environment or folder words that make differing values equal. Suggestions only ever name words visible in paths or common environment names, never other parts of values. A **What this profile does** panel explains every rule against the secrets that are actually there, and **Preview the comparison** runs it before saving. API: `POST /api/compare/suggest`.
- **Demo data:** an `apps` mount where Vault A plays test and Vault B dev, after `enterprise-logging-app` was renamed `ELP` in dev, with two new shared profiles: **Test ↔ dev: apps (ELP rename)** and **Prod ↔ staging services (rewrites)**.
- **Guide:** [Comparing environments after an application is renamed](docs/guides/compare-environments-after-a-rename.md). [Building a comparison profile](docs/guides/build-a-comparison-profile.md) now starts from **Read both sides**, explains rewrites, and says when to map, rewrite or ignore.
- **Guide:** [Migrating from HashiCorp Vault to OpenBao, verified](docs/guides/migrate-vault-to-openbao.md). It covers checking what OpenBao lacks, copying each mount, proving every secret arrived, and comparing policies and configuration.
- **CI:** a weekly workflow runs every backend and browser test against OpenBao, both the pinned version and the newest release, and opens an issue when they fail.

### Changed

- **Docs and site:**
  - The landing page leads its profiles section with mappings, rewrites and **Read both sides**, and points to the rename example on the demo.
  - The CI, cluster-comparison, development and sync guides recommend rewrites over ignoring hostnames.
  - The CLI, security and Kubernetes docs cover rewrites and profile suggestions.
  - Link previews use a 1280×640 social image.
  - Install commands, image tags and the `cosign verify` example point at the current release, and `scripts/check-version.sh` now fails on a stale one.

### Fixed

- **Release and CI on GitHub:** the workflows log in to Red Hat's registry (repository secrets `RH_REGISTRY_USER` and `RH_REGISTRY_TOKEN`, from a Red Hat registry service account) before pulling the hardened base and scanner images, which GitHub's runners couldn't pull anonymously. Without the secrets, the login is skipped and pulls stay anonymous.
- **Configuration, auth methods:** fields in an auth method's configuration that only one server returns (OpenBao's `status` on JWT and OIDC) are listed as "not compared" instead of making the method *Different*.

## [0.9.0] - 2026-11-24

### Added

- **OpenBao:** tested against OpenBao 2.7, alone or with Vault on the other side (for checking a migration). `make test-openbao` runs every backend and browser test with OpenBao standing in for Vault B.
- **Configuration overview:** a **Product** row: Vault, Vault Enterprise or OpenBao. `lockstep config compare` names the product too.
- **Public demo:** OpenBao A and OpenBao B next to the two Vaults, seeded with the same data.
- **Namespaces, tested on OpenBao:** the dev and demo OpenBaos have namespaces (`team-a`, `team-a/apps`, and one only on each side) with their own users and drift, and tests compare across them. The connect form's **Namespace** field says it's for Vault Enterprise or OpenBao.

### Changed

- **Configuration:** a built-in plugin's version shows as `builtin` and no longer counts as a difference, so upgrading one cluster, or comparing Vault with OpenBao, doesn't mark every mount as different. Pinned external plugin versions are still compared.
- **Configuration, engine roles:** fields only one server returns (Vault and OpenBao, or two versions, add different ones), and PKI `signature_bits` left automatic on one side, are listed as "not compared" instead of making the role *Different*.
- **Choosing policies for roles, groups and users:** the role builder, **Edit policies** on an identity group and **New user** (userpass) list the Vault's existing policies to pick from, as many as you like, instead of a comma-separated text box. A policy that doesn't exist yet can still be added by name, and is marked "not on this Vault". `root` is never offered.

### Security

- **Image:** rebuilt on the latest Red Hat Hardened Python image, which fixes CVE-2026-102010 in libgcc and libstdc++. The scan passes with no exceptions.

## [0.8.0] - 2026-11-22

0.7.1 was prepared but never released; its fix is included here.

### Added

- **Try this policy for real:** the policy builder's **Try for real on …** writes the draft as a temporary policy, creates a two-minute token with only that policy, checks each rule's paths with Vault's own capabilities, then deletes both. It lists where Vault and Lockstep's matcher disagree. Audit-logged as `policy.try`. `POST /api/policies/try`.
- **Browse, Policy for this folder…:** starts the policy builder with a read policy for the folder you're in.
- **Identity groups' policies:** **Edit policies** on a group in Policies › Roles, through the access review and saved plans.
- **Userpass users and LDAP group mappings:** Policies › Roles lists a userpass mount's users and an LDAP auth mount's group mappings, and compares them across Vaults. With `LOCKSTEP_USER_WRITE=on` (chart value `userWrite`, off by default) you can create users and reset passwords on development Vaults; the generated password is shown once and never logged. `/api/authusers/…`.
- **Configuration, more engines:** Azure roles; GCP rolesets, static and impersonated accounts; LDAP secrets engine roles, static roles and library sets.
- **Configuration profiles:** pair mounts whose paths differ between Vaults (`kv-dev ⇄ kv-prod`), rewrite names and ignore mounts. Shared with `LOCKSTEP_CONFIG_PROFILES` (chart value `configProfiles`) or kept per browser; `lockstep config compare --profile`. `GET /api/config/profiles`.
- **Configuration, copy to the other side:** copy a mount's or auth method's tuning, or a PKI, database, SSH, Kubernetes, AWS, Azure or LDAP role (and Transit key settings), through the access review and saved plans. Secrets and credential-rotating objects are never copied. `POST /api/config/copy`.
- **Compare, custom metadata:** **Include custom metadata** (and `lockstep compare --custom-metadata`) also compares each secret's custom metadata; differences show on the secret and in the report.
- **Compare, path prefix:** when a side is limited to a path prefix (for example after Browse's **Compare this folder…**), a chip above the results says so, and **✕ Whole mount** compares the whole mount again. The prefix can also be cleared from its field, and from a collapsed side's summary.
- **Renew a connection's token:** **Renew** on a connection extends its token, up to its max TTL. `POST /api/connections/{id}/renew`.
- **CI:** a weekly workflow runs the policy matcher's tests against the newest Vault release and opens an issue when they disagree.
- **Proposal:** [moving the dev stack to Vault 2.x](docs/proposals/vault-2-dev-stack.md).

### Changed

- **A new look:** the view tabs sit in a sticky top bar, so switching views doesn't mean scrolling up past the connection cards. New fonts (self-hosted), colours matched to the landing page, sentence-case labels, and a theme switch with **Auto**.
- **Landing page:** the hero is a typeset comparison of two Vaults instead of a screenshot, and the feature cards are three short lists.

### Fixed

- **Helm chart:** Artifact Hub rejected 0.7.0's `artifacthub.io/changes` annotation, because descriptions containing `: ` weren't quoted. They are now, and `scripts/check-version.sh` parses the annotations so a release can't ship a bad one again.
- **Browse:** a key's Show, Inspect, Edit and Delete buttons were stacked one per line in 0.7.0; they're on one line again.

## [0.7.0] - 2026-11-22

### Added

- **Browse:** a new first tab, and the one Lockstep opens on, for exploring one side's KV v2 mount. It has:
  - a lazily loaded folder tree with permission marks, find by name, go to path and shareable links;
  - masked values with **Show**, **Copy** and **Inspect**, and per-key "last changed";
  - versions, with diffs, roll back, delete, undelete and destroy, and metadata.

  Edits (change, add and delete keys, new secrets) save after an inline confirmation, or collect with **Stage changes** for one review. Every write uses check-and-set and is audit-logged without values. `GET/POST /api/browse/…`. See the [proposal](docs/proposals/browse.md).
- **Read-only mode:** `LOCKSTEP_READ_ONLY=true` (chart value `readOnly`) hides and refuses every write.
- `LOCKSTEP_ALLOW_CLIPBOARD=false` (chart value `allowClipboard`) removes Browse's **Copy** button.
- **Proposal:** [Browse](docs/proposals/browse.md).
- **Browse, more of KV v2:**
  - who wrote (and deleted) each version;
  - **Edit metadata** (max versions, require check-and-set, delete versions after, custom metadata), checked against what you loaded;
  - **Share once**: values in a one-time Vault wrapping token, with **Open a shared token…** to read one;
  - **Snippets**: `vault kv`, `curl` and Terraform for a secret or your unsaved changes;
  - **Generate** a random value;
  - a light/dark/system theme switch.

  `POST /api/browse/metadata`, `/share`, `/unwrap`. Wave 1 of the [gap analysis](docs/proposals/vault-ui-gap-analysis.md).
- **Auth roles (Kubernetes, JWT/OIDC):** the Policies tab's **Roles**:
  - list a mount's roles in plain terms, with findings (unbound JWT roles, `*` service accounts or namespaces, no audience, plain-HTTP redirects, missing policies, long TTLs);
  - explain what a role's policies allow on a mount;
  - find which roles grant a policy;
  - compare roles across Vaults (with policy profiles);
  - build new ones from templates (Kubernetes, GitLab CI, GitHub Actions, Kubernetes via JWT, OIDC group).

  Roles join the admin bundle: `roles/<mount>/<name>.json`, `apply.sh`, and Terraform/OpenTofu resources with `import` blocks. `/api/roles/…`. Phase 4 of the [policy builder](docs/proposals/policy-builder.md).
- **Write policies and roles from Lockstep:** write built policies and roles, copy a policy to the other Vault from **Compare across Vaults** (with the profile's rewrites), and delete policies and roles after a typed confirmation. A review shows each item as new, change (with a diff against Vault), same or delete, with permission checks and a warning when you change a policy you hold yourself. Each item is re-read and skipped if it changed since the review. `root` and `default` are protected. Audit-logged with hashes. `POST /api/access/preview` and `/apply`; `LOCKSTEP_POLICY_APPLY=off` (chart value `policyApply`) turns writing off. Phase 5 of the [policy builder](docs/proposals/policy-builder.md).
- **Configuration drift across Vaults:** a new **Configuration** tab (and `lockstep config compare` for CI, with diff-style exit codes) compares two Vaults side by side:
  - an overview: version, seal, storage, HA and replication;
  - every secrets engine and auth method, field by field: type, plugin version, tuning, options, and auth method configuration with sensitive fields left out.

  Read-only. `GET /api/config/overview`, `POST /api/config/compare`. Wave 2 of the [gap analysis](docs/proposals/vault-ui-gap-analysis.md).
- **Login MFA:** signing in to a Vault that enforces login MFA now works. Lockstep asks for the passcode (TOTP), or waits for push approval (Duo, Okta, PingID), for username, LDAP, JWT and OIDC sign-ins. The CLI reads `LOCKSTEP_<SIDE>_MFA_CODE` or asks in a terminal. `GET/POST /api/connections/mfa`. Before this, such Vaults couldn't be used at all.
- **Browse, limited access and YAML:** key names through `subkeys/` when values can't be read; edits sent as a patch (`PATCH`, check-and-set) when you have `patch` but not `update` or `read`; a YAML view of the secret, with values masked unless shown.
- **Explain someone else, identity groups:** Explain works for an entity, an identity group or a token (by accessor). It combines their own, their groups' and parent groups' policies, shows where each came from, and names the rights you're missing. Identity groups are listed (policies, members), explained, compared across Vaults, and included in "which roles grant policy…". `GET /api/identity/groups`, `POST /api/identity/compare-groups`, `identity` in `/api/policies/explain`. Part of phase 6 of the [policy builder](docs/proposals/policy-builder.md).
- **AppRole:** AppRole roles join the Roles view, with these warnings:
  - no secret ID;
  - secret IDs that never expire;
  - unlimited uses from anywhere.

  They also join compare, the templates (a CI pipeline or app), the admin bundle (`vault_approle_auth_backend_role`) and writing. **Issue a secret ID…** hands one over wrapped in a one-time token, with the role ID. `POST /api/roles/secret-id`.
- **Issue development certificates:** **Certificate expiry → Issue a development certificate** issues one from a PKI role and shows the issuer, names and validity. It downloads the certificate, key and chain, or stores them in a new KV secret. Audit-logged with the serial, never the key. `/api/pki/mounts`, `/overview`, `/issue`. The dev stack has a `pki-dev` engine to try it. Wave 4 of the [gap analysis](docs/proposals/vault-ui-gap-analysis.md).
- **Tools tab, Transit playground:** encrypt, decrypt, rewrap, sign, verify and HMAC with a Transit key, with your own sign-in, and see each key's settings. `/api/transit/mounts`, `/keys`, `/run`. The dev stack seeds `transit/` keys. Wave 4 of the [gap analysis](docs/proposals/vault-ui-gap-analysis.md).
- **Certificate expiry: PKI-issued certificates.** **Include PKI-issued certificates** adds every non-revoked certificate the Vaults' PKI engines issued, and their issuing CAs, to the dashboard (`"include_pki": true`).
- **Tools → Leases:** browse leases by path with issue and expiry times, renew one, or revoke selected leases after a typed confirmation. Audit-logged. Works around the `default` policy hiding the top of the lease tree. `/api/leases`, `/lookup`, `/renew`, `/revoke`.
- **Tools → Database credentials:** a database engine's connections and roles (read-only), and short-lived credentials generated from a dynamic role. They stay masked until shown and can be revoked straight away. Audit-logged without the password. `/api/database/mounts`, `/overview`, `/creds`. The dev stack adds a PostgreSQL container (Red Hat Hardened Image).
- **Configuration: engine roles and keys.** For engines both Vaults have, their roles and keys are compared too: PKI roles; database connections, roles and static roles; Transit key settings; SSH, Kubernetes and AWS roles. Secrets and self-changing values are left out. In the tab, `engines` in `/api/config/compare`, and `lockstep config compare`. The dev seed gives Vault B's Transit `app-key` some drift.
- **Access plans:** **Save as access plan** writes policy and role changes to a signed file for someone with the rights. They open it in **Policies → Open an access plan…**, review it with diffs against Vault now (changes since are skipped) and apply it. Audit-logged with the plan ID. `/api/access/plans`, `/check`, `/apply`.
- **Public demo:** a PostgreSQL container behind Vault A's database engine (its password generated into the server's `.env`), so **Tools → Database credentials** works on the demo. Leases, PKI issuing and the Transit playground work there too; the hourly reset revokes what visitors create.
- **Screenshots** of the Tools tab (Transit, database credentials, leases), issuing a development certificate and an access plan, in the README and usage guide.
- **Analysis:** [Lockstep and the Vault web UI](docs/proposals/vault-ui-gap-analysis.md): what the Vault UI does that Lockstep doesn't, and a proposal for which gaps to fill and in what order.
- **Build and suggest policies:** the Policies tab's **Build & suggest** writes policies as "who can do what, where" (see names, read, write, delete, destroy, history on a folder or secret) and generates the right KV v2 paths, with a live preview on a real mount. It also suggests policies from the layout: it detects `<app>/<env>/…` and proposes developer, per-app-per-environment, read-only and admin policies, with the reason. Your own suggestion patterns (YAML/JSON, `LOCKSTEP_POLICY_PATTERNS` / chart `policyPatterns` to share them) can also produce the policy profile for comparing two environments. **Download for an admin** makes a zip with:
  - one `.hcl` file per policy and a README;
  - `apply.sh`, which diffs against Vault and has `--dry-run`;
  - optionally Terraform or OpenTofu, with a pinned `hashicorp/vault` provider and `import` blocks for policies that already exist.

  CLI: `lockstep policy suggest`, `lockstep policy export`, `lockstep schema suggest-pattern`. Phase 3 of the [policy builder](docs/proposals/policy-builder.md).
- **Compare policies across Vaults:** the Policies tab's **Compare across Vaults** compares every ACL policy on two Vaults by meaning (comments, whitespace, order and how capabilities are listed don't count), shows the paths whose capabilities differ and both texts, and compares what a pair allows on each side's mount, secret by secret. **Policy profiles** pair names (`*-dev` ⇄ `*-prod`), rewrite paths before comparing and leave policies out; keep your own in the browser (import and export as JSON) or share them with `LOCKSTEP_POLICY_PROFILES` (chart value `policyProfiles`). `lockstep policy compare` does the same in CI, with diff-style exit codes. Phase 2 of the [policy builder](docs/proposals/policy-builder.md).
- **Collapsible sides:** each side card collapses to one line with the signed-in account, sign-in method, Vault and namespace, policies, token expiry, and mount and prefix.
- **Policies tab (explain):** see what Vault ACL policies allow on every secret of a KV v2 mount, as plain columns (see names, read, write, delete, destroy, history), with the rule, policy and line behind each answer. Explain your own token's policies (falling back to `sys/capabilities-self` when you may not read them), policies by name, or a pasted policy. Findings flag mistakes Vault would refuse, KV v2 paths without `data/`/`metadata/`, literal wildcards, risky grants and unused rules, and the rights your sign-in is missing. Path matching follows Vault's own priority rules and is tested against Vault. `lockstep policy explain` does the same on the command line; `POST /api/policies/explain`. This is phase 1 of the [policy builder](docs/proposals/policy-builder.md).
- **Proposal:** [policy builder](docs/proposals/policy-builder.md): explain, build, suggest, compare and apply Vault policies and Kubernetes / JWT/OIDC roles, or export them for an admin. Not implemented; written down for discussion.

### Fixed

- **Policy matching follows Vault 2.2.2.** Vault 2.2.2 changed how ACL rules match:
  - exact rules ignore a trailing slash;
  - a list request weighs rules for both slash forms, with denies first;
  - `deny` rules also apply whatever the case.

  Lockstep's Explain and Compare access now read each Vault's version and match the way that version does, and say which rules they used. The tests compare Lockstep's answers with Vault's own on hundreds of random policies, against both the dev stack's Vault (1.21) and the latest release (2.2.2, a new `vault-latest` service in the test profile).

## [0.6.0] - 2026-11-20

### Added

- **Destroy secrets:** **Destroy on left… / right…** in an expanded secret, and **Destroy all on left… / right…** for every secret shown, permanently delete every version and the metadata (`vault kv metadata delete`) on that side. A dialog lists what goes and needs a typed confirmation phrase (the path, or `destroy N secrets`). Each secret is checked against the version you compared, and every attempt is audit-logged (`"event": "destroy"`). `POST /api/destroy`; turn it off with `LOCKSTEP_ALLOW_DESTROY=false` (chart value `allowDestroy`).
- **Guide:** [Lockstep for development environments](https://getlockstep.cloud/guides/vault-secrets-in-development-environments/), its main use case.

### Fixed

- Removing every key of a secret no longer writes an empty new version: the latest version is soft-deleted instead (`vault kv undelete` restores it).

## [0.5.0] - 2026-11-18

### Added

- **Edit values in place:** **Edit** under a value on either side turns it into a text field; with *Show values* on, it starts from the other side's value. A staged value replaces what that side shows, with **Edit** and **Undo**. **＋ Add to left / right / both** adds a new key. This replaces the separate override panel.
- **Delete keys:** **Delete** under a value, or **Delete everywhere** on a key, stages removing it; on apply the secret gets a new version without it (check-and-set, audit-logged). The sync API takes `"remove": [...]` on a change.
- **Bulk staging and grouping:** group results by folder or with staged secrets first; copy a whole folder, or everything matching the filter, in one go; **Expand all** / **Collapse all**.
- **Trim the review:** **×** takes a key out of the changes and **Remove** takes out a whole secret.
- **Plans can hold typed values:** a review with overrides can be saved as a plan once you acknowledge the file will contain those values (`"holds_values": true`). Copied values are still never in a plan.
- `POST /api/expiry/stream`: the certificate scan as NDJSON with progress, used by the web app.

### Fixed

- Big certificate scans no longer fail with "Unexpected token '<' … is not valid JSON": the scan streams progress, so proxies don't time it out, and a proxy's HTML error page now shows a readable message.
- **all keys to left / right** shows as pressed when every differing key has been staged one at a time.

## [0.4.0] - 2026-11-13

### Added

- **Imports can delete what isn't in the file:** **Make the target match the file** in the import panel (`lockstep import --delete-missing`) writes each imported secret with only the file's keys and soft-deletes secrets under the target's prefix that the file doesn't have (`vault kv undelete` restores them). Entries with `"keep": true` and no data protect a target secret: it's neither written nor deleted. The preview lists every removed key and deleted secret; deletes are checked against the version the preview saw and audit-logged with `"action": "delete"`.
- **Proposal:** [connection probes](docs/proposals/connection-probes.md), a design for checking that database, LDAP and HTTP credentials stored in Vault still work. Not implemented; written down for discussion.

### Security

- Rebuilt on updated Red Hat Hardened base images: Python 3.14.10 (CVE-2026-115791, CVE-2026-19552) and glibc 2.43-9.3 (CVE-2026-84243).

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

[0.11.0]: https://github.com/welshstew/lockstep/releases/tag/v0.11.0
[0.10.1]: https://github.com/welshstew/lockstep/releases/tag/v0.10.1
[0.9.0]: https://github.com/welshstew/lockstep/releases/tag/v0.9.0
[0.8.0]: https://github.com/welshstew/lockstep/releases/tag/v0.8.0
[0.7.0]: https://github.com/welshstew/lockstep/releases/tag/v0.7.0
[0.6.0]: https://github.com/welshstew/lockstep/releases/tag/v0.6.0
[0.5.0]: https://github.com/welshstew/lockstep/releases/tag/v0.5.0
[0.4.0]: https://github.com/welshstew/lockstep/releases/tag/v0.4.0
[0.3.0]: https://github.com/welshstew/lockstep/releases/tag/v0.3.0
[0.2.0]: https://github.com/welshstew/lockstep/releases/tag/v0.2.0
[0.1.0]: https://github.com/welshstew/lockstep/releases/tag/v0.1.0
