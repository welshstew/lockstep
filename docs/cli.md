<!-- description: The lockstep command line: compare two Vault KV v2 locations into a YAML report with Vault UI links and vault kv get commands, then apply it key by key. -->
# Command line

The `lockstep` command does what the web UI does, from a terminal or a CI job:

1. **`lockstep compare`** compares two KV v2 locations and writes a **report**: a YAML file
   listing every secret that differs, with no values in it. For each secret it gives both
   sides' versions, a link to the secret in the **Vault UI** and the **`vault kv get`**
   command to see its values.
2. You set an **action** on the keys or secrets you want to change.
3. **`lockstep apply`** carries out those actions. It reads the values fresh from the source
   and asks before writing each key.

Copies use the same rules as the web UI:
- A write is skipped if the target changed since the report was made (check-and-set).
- Keys that exist only on the target are kept.
- Nothing is deleted.

## Install

The CLI isn't on PyPI yet. You can install it from GitHub or run it from the container image.

### From GitHub (pipx or uv)

You need Python 3.13 or newer and `git`. The package is in the repository's `backend/` directory, so the URL ends in `#subdirectory=backend`.

With [pipx](https://pipx.pypa.io/), which installs the CLI into its own virtual environment and puts `lockstep` on your PATH:

```sh
# a release (recommended); the CLI is in v0.2.0 and later
pipx install "git+https://github.com/welshstew/lockstep@v0.12.0#subdirectory=backend"

# or the latest code on main
pipx install "git+https://github.com/welshstew/lockstep#subdirectory=backend"

lockstep --version
```

[uv](https://docs.astral.sh/uv/) works the same way:

```sh
uv tool install "git+https://github.com/welshstew/lockstep@v0.12.0#subdirectory=backend"
```

To move to another release, run the same command with the new tag and `--force` (`pipx install --force ...`, `uv tool install --force ...`). To remove the CLI, run `pipx uninstall lockstep` or `uv tool uninstall lockstep`.

If you'd rather use a plain virtual environment:

```sh
python3 -m venv ~/.venvs/lockstep
~/.venvs/lockstep/bin/pip install "git+https://github.com/welshstew/lockstep@v0.12.0#subdirectory=backend"
~/.venvs/lockstep/bin/lockstep --help
```

The package also contains the web app's server, so it installs FastAPI and Uvicorn as well. The CLI doesn't start a server.

### From the container image

Every release image (`ghcr.io/welshstew/lockstep`, v0.2.0 and later, for amd64 and arm64) contains the CLI. Its entrypoint starts the web app, so override it with `--entrypoint lockstep`:

```sh
docker run --rm -it --entrypoint lockstep \
  -e VAULT_ADDR -e VAULT_TOKEN \
  -v "$PWD:/work" -w /work \
  ghcr.io/welshstew/lockstep:0.12.0 \
  compare --mount app-config -o report.yaml
```

Podman works the same way: replace `docker` with `podman`. When you run it in a container:
- **Pass tokens through the environment.** `-e VAULT_TOKEN`, with no `=value`, copies the variable from your shell, so the token doesn't show up in the command line. To use the token from `vault login`, mount the file and point the CLI at it:

  ```sh
  -v ~/.vault-token:/run/vault-token:ro ... compare --left-token-file /run/vault-token ...
  ```
- **Mount a directory for the report.** The container runs as uid 65532, so the mounted directory must be writable by that user. On SELinux hosts, add `:Z` to the volume. If you can't do either, write the report to stdout instead with `-o - > report.yaml`, and to apply it pass it in with `-v "$PWD/report.yaml:/report.yaml:ro"`.
- **Keep `-it` for `apply`.** It asks before each write, which needs a terminal. In a pipeline, use `--yes` or `--dry-run` without `-it`.
- **Use the host network for a Vault on localhost.** `localhost` inside the container is the container itself, so add `--network host` (Linux) or use `host.docker.internal` / `host.containers.internal` as the address.

A shell alias makes the image feel like an installed command:

```sh
alias lockstep='docker run --rm -it --entrypoint lockstep -e VAULT_ADDR -e VAULT_TOKEN -e VAULT_NAMESPACE \
  -e LOCKSTEP_LEFT_TOKEN -e LOCKSTEP_RIGHT_TOKEN -v "$PWD:/work" -w /work ghcr.io/welshstew/lockstep:0.12.0'
```

## Logging in

The CLI logs in the way the `vault` CLI does, so `vault login` is usually all you need.
Each side looks for its settings in this order; the first one found wins.

| | Left side | Right side |
|---|---|---|
| Address | `--left-addr`, `LOCKSTEP_LEFT_ADDR`, `VAULT_ADDR` | `--right-addr`, `LOCKSTEP_RIGHT_ADDR`, the left side's address |
| Namespace | `--left-namespace`, `LOCKSTEP_LEFT_NAMESPACE`, `VAULT_NAMESPACE` | `--right-namespace`, `LOCKSTEP_RIGHT_NAMESPACE`, the left side's (same Vault), `VAULT_NAMESPACE` |
| Token | `LOCKSTEP_LEFT_TOKEN`, `--left-token-file`, `VAULT_TOKEN`, `~/.vault-token` | `LOCKSTEP_RIGHT_TOKEN`, `--right-token-file`, `VAULT_TOKEN`, `~/.vault-token` |

- **Userpass or LDAP:** `--left-auth userpass --left-user alice` asks for the password, or reads it from `LOCKSTEP_LEFT_PASSWORD`. Use `--left-auth-mount` if the method isn't mounted at its default path. The token that login creates is revoked when the command finishes.
- **Kubernetes:** `--left-auth kubernetes --left-role R` logs in with Vault's kubernetes auth method as the pod's service account, reading its token from `/var/run/secrets/kubernetes.io/serviceaccount/token` (or `--left-jwt-file`). `--left-auth-mount` defaults to `kubernetes`. The chart's [drift check](drift-monitoring.md) uses it.
- **JWT:** `--left-auth jwt` logs in with Vault's JWT auth method, using the JWT in `LOCKSTEP_LEFT_JWT` or the file given by `--left-jwt-file`, for example a CI job's OIDC token. `--left-role` picks the Vault role (default: the mount's `default_role`) and `--left-auth-mount` the mount (default: `jwt`). The token that login creates is revoked when the command finishes.

  ```sh
  # GitLab CI, with an id_tokens entry named VAULT_ID_TOKEN
  LOCKSTEP_LEFT_JWT=$VAULT_ID_TOKEN lockstep compare --left-auth jwt --left-role lockstep-ci …
  ```
- **OIDC and other methods:** run `vault login -method=oidc` first, and the CLI picks up the token from `~/.vault-token`. To use two different Vaults, give each side its own token, for example:

  ```sh
  LOCKSTEP_RIGHT_TOKEN=$(VAULT_ADDR=https://vault-b vault login -method=oidc -token-only)
  ```
- **Login MFA:** when a Vault asks for a second factor at login (TOTP, Duo, Okta, PingID), a passcode comes from `LOCKSTEP_LEFT_MFA_CODE` (or `LOCKSTEP_VAULT_MFA_CODE`, and so on), or the CLI asks for it in a terminal. For push methods it waits until you approve the request on your device.
- **Same Vault on both sides:** to compare two mounts or prefixes in one Vault, give only the left address. The right side then reuses the left side's connection.
- **TLS:** `--ca-cert` or `VAULT_CACERT`; `--tls-skip-verify` or `VAULT_SKIP_VERIFY` (insecure).

The CLI never takes tokens, JWTs or passwords as arguments, because arguments show up in `ps` and shell history.

## Compare

```sh
lockstep compare \
  --left-addr https://vault-prod.example.com --left-name prod \
  --right-addr https://vault-staging.example.com --right-name staging \
  --mount app-config --prefix services/billing \
  -o report.yaml
```

It prints a summary:

```
Left:  prod (https://vault-prod.example.com) app-config/services/billing
Right: staging (https://vault-staging.example.com) app-config/services/billing

  different   db                differs: password, port (type)
  left only   api
  right only  queue

5 secrets: 2 equal, 1 different, 1 left only, 1 right only.
Report written to report.yaml. Set actions in it, then run: lockstep apply report.yaml
```

| Option | |
|---|---|
| `--mount`, `--left-mount`, `--right-mount` | KV v2 mount on both sides, or on each side |
| `--prefix`, `--left-prefix`, `--right-prefix` | only compare under this path |
| `--profile FILE\|NAME` | a [comparison profile](usage.md): a YAML or JSON file (a profile exported from the web UI, or just its `mappings` / `rewrites` / `ignore_keys` / `ignore_paths`), or a name from `LOCKSTEP_PROFILES`. Its mounts and prefixes are used when you don't give them. |
| `--profile-name NAME` | which profile to use when the file holds several (the web UI's export can) |
| `--left-name`, `--right-name` | labels used in the report (default: the host) |
| `--left-ui-addr`, `--right-ui-addr` | the address people open the Vault UI at, if it differs from the API address the CLI uses |
| `-o FILE` | write the report (`-o -` writes it to stdout, and the summary goes to stderr). Repeat it to write several formats; the format follows the extension (see [Drift checks in CI](#drift-checks-in-ci)) |
| `--format` | `yaml`, `json`, `sarif`, `junit`, `markdown` or `csv` for every `-o`, instead of following the extension |
| `--baseline FILE`, `--fail-on`, `--waivers FILE`, `--require-signed` | a drift check that fails only on new drift, with signed files if you like: see [Drift checks in CI](#drift-checks-in-ci) |
| `--include-equal` | list equal secrets in the report too |
| `-q` | no summary |

**Exit codes**, like `diff`:
- 0: the two sides are the same.
- 1: there are differences, or keys that couldn't be compared (`not_compared`), so a drift check never passes on a keystore it couldn't open.
- 2: the comparison couldn't run.

This makes `lockstep compare -q` usable as a drift check in CI. To fail only on drift that wasn't there before, use a baseline.

**KV v1.** `--left-mount` or `--right-mount` can name a KV v1 mount: it's compared like KV v2, without versions. `lockstep apply` copies from it into KV v2, and refuses to write into it.

## Drift checks in CI

A pipeline that fails on every difference fails forever once one difference is accepted. A **baseline** records the drift you accept, so the run fails only on what's new:

```sh
# once, and again whenever you accept the drift as it is now
lockstep baseline update drift.json --left-addr … --right-addr … --mount app-config --prefix services/billing
git add drift.json

# in the pipeline: exit 1 only for drift that isn't in drift.json
lockstep compare --left-addr … --right-addr … --mount app-config --prefix services/billing \
  --baseline drift.json -o drift.sarif -o drift.md
```

- **The baseline** is JSON, sorted, with one entry per differing key (or per secret, for one on one side only): its path, key and status. No values, no versions, no hashes of values, so it's safe to commit, and its diff in a pull request shows which drift was accepted. `baseline update` takes the same options as `compare`. An earlier `compare -o` report works as a baseline too. A baseline for other mounts or prefixes is refused (exit 2) rather than making everything new.
- **`--fail-on`**:
  - `any`: any drift exits 1. The default without `--baseline`.
  - `new`: drift that isn't in the baseline, or is with another status (a key that was `left_only` and is now `different`). The default with `--baseline`.
  - `changed`: new drift, or drift in the baseline that's gone (resolved). Use it to make sure the baseline is kept up to date.
- **Waivers** accept one difference for a while, with who accepted it and why:

  ```yaml
  # waivers.yaml
  - path: billing/*        # secret path as in the report; * and ** globs work
    key: feature_flags     # leave out to waive the whole secret
    owner: team-billing
    reason: staging tries the new checkout flow
    expires: 2027-01-31
  ```

  `--waivers waivers.yaml` doesn't fail on what a waiver covers. An expired waiver fails the run until it's renewed or removed, and the summary names waivers that match nothing any more.
- **Signed baselines and waivers.** These commands sign with the plan key (`LOCKSTEP_PLAN_SIGNING_KEY`, from `lockstep plan-key`):
  - `baseline update … --sign` writes a signed baseline;
  - `baseline sign FILE` signs an existing one;
  - `waivers sign FILE` signs a waivers file.

  With `LOCKSTEP_PLAN_TRUSTED_KEYS` set, `compare` checks a signed file. An edited one, or one signed by a key that isn't trusted, exits 2. `--require-signed` refuses unsigned files too. `lockstep matrix --require-signed` does the same for the environments' `accepted:` files. See [sign the baseline](guides/detect-vault-secret-drift-in-ci.md#sign-the-baseline).

The summary adds a line like `Drift: 1 new, 4 known (in the baseline), 0 resolved.` and lists what's new. The YAML and JSON reports mark each key `drift: new`, `known` or `waived`, and add a `drift_check` section.

**Formats.** `-o` follows the extension, or `--format` sets it. None of them holds a value.

| Extension | Format | For |
|---|---|---|
| `.yaml`, `.yml` | the report | people, and `lockstep apply` |
| `.json` | the report as JSON | scripts; `lockstep apply` reads it too |
| `.sarif` | SARIF 2.1.0 | GitHub code scanning (`github/codeql-action/upload-sarif`) and other SARIF viewers. Drift that fails the run is an `error`, drift in the baseline a `note`, waived drift is suppressed with the waiver's reason. Each result's location is the right side's `mount/path`, and a fingerprint of the path and key lets the viewer follow it from run to run. |
| `.xml` | JUnit XML | any CI's test tab: one test case per secret, failed when it has drift that fails the run, skipped when its drift is known or waived |
| `.md` | Markdown | a pull request comment: counts, then a table with new drift first (at most 200 rows) |
| `.prom` | Prometheus text | node_exporter's textfile collector: the [drift gauges](drift-monitoring.md#pushgateway-gauges), with their labels. `--pushgateway URL` pushes them instead. |
| `.csv` | CSV | spreadsheets: one row per differing key. A cell that starts with `=`, `+`, `-` or `@` gets a leading `'`, so it's never run as a formula. |

## Environment matrix

`lockstep matrix FILE` compares one baseline, say prod, with several environments at once. Each environment is compared with the baseline under its own comparison profile, and the baseline is read only once. The result is a grid: a row per secret (is it there?) and per key (does it match?), a column per environment. Rows that differ in only one environment come first, because a key that differs in one place is the likeliest mistake. Rows where every environment differs come last: those are usually meant to differ, such as a password per environment.

```yaml
# environments.yaml
baseline:
  name: prod
  addr: https://vault.prod.example.com
  mount: app-config
  prefix: services
environments:                        # up to 12
  - name: staging
    addr: https://vault.staging.example.com
    profile: profiles/prod-staging.yaml   # relative to this file, or a $LOCKSTEP_PROFILES name
  - name: dev
    addr: https://vault.dev.example.com
    prefix: services-dev              # mount and prefix default to the baseline's
  - name: preview
    namespace: previews/pr-123        # no addr: the baseline's Vault
    accepted: drift/preview.base.json # optional: accepted drift for this pair (lockstep baseline update)
```

```console
$ lockstep matrix environments.yaml -o matrix.md
Baseline: prod (https://vault.prod.example.com) app-config/services
  staging (https://vault.staging.example.com) app-config/services
  dev (https://vault.dev.example.com) app-config/services-dev
  preview (https://vault.prod.example.com) app-config/services

                             staging  dev      preview
  billing · feature_flags    =        ≠        =
  payments                   =        =        missing
  db · password              ≠        ≠        ≠

= equal  ≠ different  missing: not in this environment  extra: only in this environment  ? not compared  · neither has it
```

- **Logins.** Each Vault logs in like the other commands: `LOCKSTEP_<NAME>_TOKEN`, with the name upper-cased and other characters turned into `_` (`LOCKSTEP_STAGING_TOKEN`), then `VAULT_TOKEN` or `~/.vault-token`. Or give an `auth:` block, either at the top of the file for every Vault or on one place: `{method: kubernetes, role: lockstep-drift}`, `{method: jwt, role: ci}` (the JWT from `LOCKSTEP_<NAME>_JWT` or `jwt_file`), `{method: userpass, user: alice}` (the password from `LOCKSTEP_<NAME>_PASSWORD`). Places on the same Vault and namespace with the same login share one sign-in. Tokens Lockstep minted by logging in are revoked at the end.
- **Profiles.** `profile` takes a profile file (or `profile_name` to pick one from a file holding several) or a `$LOCKSTEP_PROFILES` name. A profile's right mount and prefix apply when the environment doesn't set its own.
- **Accepted drift.** `accepted` names a drift baseline for that pair, relative to the file. What it lists with the same status is marked `*` (`(accepted)` in Markdown and CSV) and doesn't count: a matrix with only accepted drift exits 0. A baseline for other mounts or prefixes is refused (exit 2).
- **Output.** `-o` writes `.json`, `.yaml`, `.md` (a table for a pull request comment), `.csv` or `.txt`, and can be repeated. `--include-equal` lists the rows where everything matches too. None of them holds a value.
- **Exit codes.** 0: every environment matches the baseline. 1: something differs, or couldn't be told. 2: something couldn't be compared, such as a bad file, a failed login or an environment whose listing failed. That environment's column says why, and the outputs are still written.

The web UI's **Matrix** tab does the same with signed-in connections.

## The report

```yaml
lockstep_report: 1
created: '2026-11-09T11:19:48Z'
left:  {name: prod, addr: https://vault-prod.example.com, mount: app-config, prefix: services/billing, identity: oidc-alice}
right: {name: staging, addr: https://vault-staging.example.com, mount: app-config, prefix: services/billing, identity: oidc-alice}
summary: {equal: 2, different: 1, left_only: 1, right_only: 1, ...}
secrets:
- path: db
  status: different
  action: per-key  # per-key | skip | copy-to-right | copy-to-left
  left:
    path: services/billing/db
    state: present
    version: 4
    updated: '2026-11-02T09:12:44Z'
    ui: https://vault-prod.example.com/ui/vault/secrets/app-config/kv/services%2Fbilling%2Fdb/details
    cli: vault kv get -address=https://vault-prod.example.com -mount=app-config services/billing/db
  right:
    path: services/billing/db
    state: present
    version: 7
    ...
  equal_keys: 2
  keys:
  - key: password
    status: different
    action: skip  # skip | copy-to-right | copy-to-left
  - key: port
    status: different
    type_differs: true
    action: skip  # skip | copy-to-right | copy-to-left
  - key: keystore
    status: left_only
    left_holds: PKCS#12 keystore, expires in 41 days
    action: skip  # skip | copy-to-right | copy-to-left
```

Each `keys` entry is a key that isn't equal on both sides:
- `status` is `different`, `left_only`, `right_only` or `not_compared` (a keystore whose password isn't in the secret). `not_compared` keys can be copied like `different` ones. `not_compared` makes `compare` exit 1, like a difference; `no_access` doesn't.
- `type_differs` marks `5432` vs `"5432"`.
- `ignored` marks a difference that a profile rule ignores.
- `left_holds` / `right_holds` say what the value is (a certificate, a keystore and so on) without showing it.

When a profile maps paths, `left.path` and `right.path` differ, and copies follow the mapping. When it has rewrites (`prod` ⇄ `staging`), the report lists them under `rewrites`. Keys that are equal only once they're applied count as equal, and the summary says how many there are (`N keys equal once the profile's rewrites are applied`). If a side couldn't be read, its `state` is `no_access` or `error`, and that secret can't be copied.

### Setting actions

Actions can go on keys or on whole secrets.

**On a key:**
- `copy-to-right` writes the left side's value to the right side.
- `copy-to-left` writes the right side's value to the left side.
- `skip` leaves the key alone. This is the default.

You can mix directions within one secret.

**On a secret:**
- `copy-to-right` or `copy-to-left` copies **every** key the source has, including keys that are already equal.
- `skip` ignores the secret's key actions.
- `per-key` (the default) uses the actions set on its keys.

Don't set both a secret action and key actions on the same secret.

`lockstep apply` checks every action before it writes anything. If something can't work, it lists all of the problems and writes nothing. Examples:
- copying a key from a side that doesn't have it
- an action on a secret one side couldn't read
- a misspelt field or action

### Editor support

The report's first line points editors at its [JSON Schema](https://getlockstep.cloud/schemas/lockstep-report-v1.json):

```yaml
# yaml-language-server: $schema=https://getlockstep.cloud/schemas/lockstep-report-v1.json
```

In **VS Code** with Red Hat's [YAML extension](https://marketplace.visualstudio.com/items?itemName=redhat.vscode-yaml):
- `action:` values autocomplete, with a description of each.
- A misspelt field or action is underlined as you type.
- Hovering over a field explains it.

The same line works in other editors that use the YAML language server, such as Neovim, Helix and Zed. In **JetBrains** IDEs, map the schema URL to your report files under *Settings → Languages & Frameworks → Schemas and DTDs → JSON Schema Mappings*.

`lockstep schema` prints the schema, for offline use.

## Apply

```sh
lockstep apply report.yaml               # asks before writing each key
lockstep apply report.yaml --dry-run     # show what would be written, write nothing
lockstep apply report.yaml --yes         # write everything the report says, without asking
```

```
→ staging · app-config/services/billing/db   from prod · app-config/services/billing/db
  2 keys to write (v7 → v8):
    update password
  Write password? [y]es / [n]o / [a]ll / [q]uit: y
    update port  (type changes)
  Write port? [y]es / [n]o / [a]ll / [q]uit: n
  Written: v8 (1 key).
```

**Answers at each prompt:**
- `a` says yes to everything after it.
- `q` stops. Secrets already written stay written.

The keys you confirm for a secret are written together, as one new version.

**What apply checks**, for each secret:
- It reads the source again, and writes the value it reads, so values never pass through the report. If the report has `rewrites`, they're applied to that value in the direction of the copy (`prod` becomes `staging` on the way right), and the prompt marks the key `(words rewritten by the profile)`.
- **If the source or target changed since the report was made, the secret is skipped and reported.** The rest still go ahead. Compare again to pick up the changes.
- The write uses check-and-set, so a change made while you are answering prompts also makes it skip.
- The target needs write permission (`create` / `update`).

**Options:**

| Option | |
|---|---|
| `--show-values` | print each key's current and new value before asking. This prints secrets to your terminal. |
| `--audit-log FILE` | append one JSON line per write: who, where, versions, outcome, never values. This is the same format as the web app's audit log. Writes also show up in Vault's own audit device. |
| `--left-addr` and the other login options | the Vault addresses come from the report, but you can override them here, for example when this machine reaches Vault at a different address |

**Exit codes:**
- 0: done.
- 1: some secrets were skipped because they changed or couldn't be written.
- 2: nothing was applied (a bad report, a failed login and so on).

Without a terminal, apply can't ask questions, so it refuses to run unless you pass `--yes` or `--dry-run`.

## Export and import

`lockstep export` writes a [secret-engine export](usage.md#6-export-and-import) of one mount (or prefix), with values; `lockstep import` writes one into a mount. They act on one Vault, logged in like the other commands but with `--vault-*` options: `--vault-addr` (or `LOCKSTEP_VAULT_ADDR`, `VAULT_ADDR`), `--vault-auth userpass|ldap|jwt`, `--vault-user`, `--vault-token-file` and so on, falling back to `VAULT_TOKEN` and `~/.vault-token`.

```sh
# Encrypted with a one-time key, printed once (or written to --key-file, mode 600)
lockstep export --vault-addr https://vault-prod --mount app-config --prefix payments \
    --ignore-path 'legacy/**' --ignore-key 'password@services/**' -o payments.json --key-file payments.key

# Or with a passphrase (asked twice, or $LOCKSTEP_EXPORT_PASSPHRASE), or to age public keys
lockstep export --vault-addr https://vault-prod --mount app-config --prefix payments --passphrase -o payments.json
lockstep export --vault-addr https://vault-prod --mount app-config --prefix payments -R platform-team.txt -o payments.json

# Preview, then import into another Vault with rules
lockstep import payments.json --vault-addr https://vault-test --mount app-config --prefix payments \
    --key-file payments.key --rules rules.yaml --replace application-dev-env=application-test-env --dry-run
```

- **Export:** `--ignore-path GLOB` and `--ignore-key KEY[@PATH]` (repeatable) leave things out; `--profile` takes a comparison profile's ignore rules too. Instead of a one-time key, `--passphrase` encrypts with a passphrase (from `LOCKSTEP_EXPORT_PASSPHRASE`, or asked twice), and `-r AGE_KEY` / `-R FILE` (repeatable) encrypt to age public keys, which `age -d` can open too. `--no-encrypt` writes plain text (with a warning), and `-o -` writes to stdout. A plain export is written as it's read (compact JSON), into a temporary file that replaces the target only once it's complete; an encrypted one holds only the compressed export in memory. The export file is created readable by you only.
- **Import from the `vault` CLI:** the file can also be `vault kv get -format=json` output (one secret, its path the file name), a JSON object of `"path": output`, or a folder of such files, whose paths in the folder become the secret paths: `lockstep import ./dump --vault-addr … --mount app-config`.
- **Import:** what opens an encrypted file comes from `--key-file` (the key, the passphrase, or an age identity file, whichever the file needs), `LOCKSTEP_EXPORT_KEY` (`LOCKSTEP_EXPORT_PASSPHRASE` for a passphrase), or a prompt. `--rules FILE` reads import rules (YAML or JSON: `ignore_paths`, `ignore_keys`, `transforms`, the same file the web UI's **Save rules** writes; see `lockstep schema import-rules`). `--ignore-path`, `--ignore-key`, `--replace FIND=WITH` (values) and `--replace-path FIND=WITH` add to them. Text starting with `-` needs the `=` form: `--replace=-dev-=-test-`.
- **What import shows:** a preview: what the rules left out and changed, then per secret `new` or `update` with the keys (`--show-values` adds old and new values; it prints secrets). Then it asks once before writing, unless `--yes`. `--dry-run` stops after the preview.
- **How it writes:** like `apply`. Values are merged into each target secret with check-and-set against the version the preview saw; keys only on the target are kept and nothing is deleted. `--audit-log FILE` appends a JSON line per write.
- **`--delete-missing`:** make the target match the file. Imported secrets are written with only the file's keys (the preview shows other keys as `(remove)`), and secrets under `--prefix` that aren't in the file are soft-deleted (`delete` in the preview; `vault kv undelete` restores them). Entries with `"keep": true` and no data are left alone. See [deleting what isn't in the file](usage.md#deleting-what-isnt-in-the-file).
- **Exit codes:** 0 done (or nothing to do), 1 some secrets weren't written (changed meanwhile, no permission, or left out by a collision), 2 couldn't run.

`lockstep schema export` and `lockstep schema import-rules` print the files' JSON Schemas; `lockstep schema policy-profile` prints a policy profile's, and `lockstep schema suggest-pattern` a suggestion pattern's.

## Policies

`lockstep policy explain` shows what Vault ACL policies allow on every secret of a KV v2 mount: the same grid, findings and deciding rules as the web UI's [Policies](usage.md#7-policies) tab. It logs in with the `--vault-*` options, like `export`, and is read-only.

```sh
# Policies by name, from Vault
lockstep policy explain payments-dev default --vault-addr https://vault-dev --mount app-config --prefix payments

# A policy file you're writing (HCL or JSON); repeat --file for several
lockstep policy explain --file payments-dev.hcl --vault-addr https://vault-dev --mount app-config

# Your own token's policies, and why one secret is or isn't readable
lockstep policy explain --self --vault-addr https://vault-dev --mount app-config --why payments/api
```

```text
secret        See names  Read  Write  Delete  Destroy  History
payments/api      ✓       ✗      ✗      ✗        ·        ✓
payments/db       ✓       ✓      ✓      ·        ·        ✓
```

- ✓ allowed, · not allowed, ✗ refused by a `deny` rule. `--allowed-only` hides secrets where nothing is allowed.
- `--why PATH` lists, for one secret, the rule that decided each column, with its policy and line.
- `--json` prints the whole result.
- **Exit codes:** 0 explained, 1 a policy has an error Vault would refuse (or a named or `--file` policy couldn't be read or parsed), 2 couldn't run. That makes `--file` usable as a check in CI before `vault policy write`.

`lockstep policy compare` compares every policy on two Vaults by meaning, like the web UI's [Compare across Vaults](usage.md#compare-policies-across-vaults). It logs in with the `--left-*` and `--right-*` options, like `compare`.

```sh
lockstep policy compare --left-addr https://vault-dev --right-addr https://vault-prod \
    --map '*-dev=*-prod' --rewrite /dev/=/prod/

# or with a policy profile file (YAML or JSON; the web UI's Export mine writes one)
lockstep policy compare --left-addr https://vault-dev --right-addr https://vault-prod --profile dev-prod.yaml
```

```text
different   payments-dev ⇄ payments-prod
              path "app-config/data/payments/*"  [create, delete, read, update] → [read]
right only  orders-app

8 policies: 5 equal, 1 different, 1 left only, 1 right only.
```

- `--profile FILE|NAME`: a policy profile file (`mappings`, `rewrites`, `ignore`; `--profile-name` picks one from a list), or a name from `LOCKSTEP_POLICY_PROFILES`. `--map LEFT=RIGHT` and `--rewrite FIND=REPLACE` add to it.
- `--show-equal` lists equal policies too; `--json` prints the whole result, texts included.
- **Exit codes,** like `compare`: 0 the same, 1 differences (or a policy couldn't be read), 2 couldn't compare. Use it in CI to catch access drift between clusters.

`lockstep policy diff --dir DIR` compares the policy files kept in Git with a live Vault's policies, by the same meaning-aware comparison. It's "Git says X, Vault says Y" without `terraform plan`. A file's name without `.hcl` or `.json` is the policy's name. Files are found in subdirectories too, and two files for the same policy are refused. It logs in with the `--vault-*` options.

```sh
lockstep policy diff --dir ./policies --vault-addr https://vault-prod --ignore default
```

```text
different     payments-app
                path "app-config/data/payments/*"  [read] → [read, update]
only in files orders-app
only in Vault legacy-batch

14 policies: 11 equal, 1 different, 1 only in files, 1 only in Vault.
```

- **Comparing:** comments, whitespace, rule order, HCL against JSON, and how capabilities are listed don't count.
- **Options:**
  - `--files-only` leaves out the policies that exist only in Vault, for a directory that holds some of them.
  - `--ignore NAME` (`*` patterns, repeatable) leaves out more. `root` is always left out.
  - `--profile`, `--map FILE=VAULT` and `--rewrite` work as for `policy compare`, with the files as the left side.
  - `--show-equal` and `--json` work as for `policy compare`.
- **Exit codes:** 0 the same, 1 differences, 2 couldn't compare. The token needs `list` on `sys/policies/acl` and `read` on `sys/policies/acl/*`.

`lockstep policy suggest` suggests policies from a mount's layout, like the web UI's [Build & suggest](usage.md#build-and-suggest-policies), and prints them as HCL:

```sh
lockstep policy suggest --vault-addr https://vault-dev --mount app-config --prefix services
lockstep policy suggest --vault-addr https://vault-dev --mount app-config --pattern teams.yaml \
    --only billing-prod-app --bundle billing.zip --terraform --profile-out dev-prod.json
```

- `--pattern FILE` uses a suggestion pattern (YAML or JSON; `lockstep schema suggest-pattern`); `--only NAME` keeps some suggestions.
- `--profile-out FILE` writes the pattern's policy profile, for `lockstep policy compare --profile`.
- `--bundle ZIP` writes the admin bundle (HCL, `apply.sh`, README); `--terraform` or `--opentofu` add infrastructure code, `--provider '~> 4.0'` pins another provider version, `--tf-files` makes one `.tf` file per policy.

`lockstep policy export FILE.hcl… --bundle ZIP` makes the same bundle from policy files you have, named after the files. It needs no Vault.

## Configuration

`lockstep config compare` compares two Vaults' secrets engines and auth methods (type, plugin version, tuning, options, auth configuration), the roles and keys of engines both have (PKI, database, Transit, SSH, Kubernetes, AWS, Azure, GCP, LDAP, and others such as TOTP, Consul and Nomad generically), and system settings (audit devices, password policies, token roles, quotas, MFA methods and enforcements, registered plugins, identity entities), with sensitive fields left out, like the web UI's [Configuration](usage.md#8-configuration) tab. It logs in with the `--left-*` and `--right-*` options.

```sh
lockstep config compare --left-addr https://vault-staging --right-addr https://vault-prod
```

```text
Vault 1.21.4 ⇄ Vault 2.2.2  (versions differ)
different   secrets engine app-config/ (kv)
              config.max_lease_ttl: 3600 → 7200
left only   auth method k8s-staging/ (kubernetes)
different   password policy password-policy/app-passwords (password policy)
              policy: length = 20 rule "charset" { charset = "abcdefghijklmnopqrs… → length = 32 rule "charset" { charset = "abcdefghijklmnopqrs…
Warning (left): No audit device: requests to this Vault aren't logged.
```

Lists longer than Lockstep reads at once (200 engine objects, 500 system objects) are cut off and named in `Cut off (left): …` lines.

`--include-system` adds `sys/`, `identity/`, `cubbyhole/` and `token/`; `--show-equal` lists equal ones; `--json` prints everything. **Exit codes:** 0 the same, 1 differences, 2 couldn't compare.

`--profile FILE|NAME` uses a configuration profile, a YAML/JSON file or a name from `LOCKSTEP_CONFIG_PROFILES`, when the Vaults name things differently:

```yaml
name: staging vs prod
mappings:                         # mount paths, * allowed; a mount's roles and keys follow it
  - {left: kv-staging, right: kv-prod}
  - {left: "kubernetes-*", right: "k8s-*"}
rewrites:                         # on the left side's values, before comparing
  - {find: staging.example.com, replace: prod.example.com}
ignore: ["sandbox-*"]             # paths to leave out
```

## Reports and sync plans

A report and a web UI [sync plan](usage.md#sync-plans) are related, but they're used differently.

**A report:**
- is something you edit.
- is applied secret by secret: anything that went stale is skipped and the rest goes ahead.
- isn't signed. Whoever runs `apply` uses their own Vault permissions and confirms each write.

**A sync plan:**
- is signed by the server.
- is checked all or nothing: if any secret changed since the plan was made, nothing is written.
- stops at the first write that's refused while it's being applied (a secret that changed in that
  moment). The writes before it stay, and the result says "partially applied".

Neither one holds values.

`lockstep plan-key` prints a new Ed25519 key pair for signing plans that are made on one Lockstep server and applied on another. See [plans between installations](configuration.md#plans-between-installations).
