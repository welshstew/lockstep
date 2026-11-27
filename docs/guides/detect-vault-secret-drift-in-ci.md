<!-- description: Detect drift between two HashiCorp Vault environments in CI with the lockstep CLI: diff-style exit codes, a read-only token and no values in logs. -->
# Detecting secret drift between Vault environments in CI

Environments that are meant to match drift apart quietly. A key gets added in staging and never reaches production. A disaster-recovery cluster misses a rotation. A new region is set up from an old export. The first sign is often an outage.

This guide shows how to check for drift between two HashiCorp Vault KV v2 locations on a schedule or on every change, with the [Lockstep](https://getlockstep.cloud) command line. It needs no long-running service, and no values end up in your CI logs.

## How it works

`lockstep compare` exits like `diff`:

| Exit code | Meaning |
|---|---|
| `0` | The two sides are the same (keys and values; versions and key order don't count) |
| `1` | There are differences |
| `2` | The comparison couldn't run (login failed, unreachable Vault, bad options) |

A CI job that runs it fails when the environments have drifted. Its summary lists the secrets and key names that differ, never values. The YAML report (`-o`) adds versions, Vault UI links and `vault kv get` commands, so it's safe to keep as a build artifact.

## A read-only token

Drift detection only reads. Give the job its own policy with `list` and `read` on the mounts it compares, and nothing else. The [security guide](../security.md#vault-policies) has an example.

The best way to get a token is the pipeline's own identity token. With Vault's JWT auth method, `lockstep compare --left-auth jwt` exchanges it for a short-lived Vault token, so no long-lived secret has to be stored. [Logging in to Vault with JWT from CI](vault-jwt-login-from-ci.md) sets this up for GitHub Actions and GitLab. Otherwise the CLI picks up a token from `VAULT_TOKEN`. For two clusters with separate tokens, use `LOCKSTEP_LEFT_TOKEN` and `LOCKSTEP_RIGHT_TOKEN`.

## GitHub Actions

The Lockstep action does the whole job in one step:
- it logs in to Vault with the job's OIDC token;
- it compares, against a baseline if you give one;
- it uploads SARIF to code scanning;
- it comments a summary on the pull request, and updates that comment on later runs;
- it writes the summary to the job's page.

```yaml
name: vault-drift
on:
  pull_request:
    paths: [".lockstep/**"]
  schedule: [{cron: "0 6 * * 1-5"}]   # weekday mornings
  workflow_dispatch:

jobs:
  drift:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write          # the OIDC token Vault's JWT auth takes
      security-events: write   # SARIF upload (code scanning)
      pull-requests: write     # the PR comment
    steps:
      - uses: actions/checkout@v4
      - uses: welshstew/lockstep@v0.12.0
        with:
          left-addr: https://vault-prod.example.com
          left-name: prod
          right-addr: https://vault-staging.example.com
          right-name: staging
          mount: app-config
          role: lockstep-ci
          profile: .lockstep/prod-vs-staging.json
          baseline: .lockstep/drift.json
```

- **Logging in:** the action asks GitHub for an OIDC token with the audience `vault` (input `audience`). It logs in with it at `auth/jwt` (input `jwt-mount`) as `role`, with `left-role` and `right-role` when they differ. Bind the role to your repository with `bound_claims`, as in [logging in to Vault with JWT from CI](vault-jwt-login-from-ci.md). With `auth: token`, it uses `left-token` and `right-token` from your secrets instead. Tokens and JWTs are masked in the log and never passed to other steps.
- **The step fails** on drift that fails the check (exit 1), or when it couldn't compare (exit 2). `fail-on-drift: false` only reports. The outputs are `exit-code`, `new` (how many differences fail the check) and `report-dir`. The reports are `drift.yaml`, `drift.json`, `drift.sarif` and `drift.md`, so you can upload them with `actions/upload-artifact`.
- **Code scanning** shows drift as alerts on the right side's `mount/path`, and closes them when the drift is gone. Uploading needs code scanning to be available for the repository (public repositories, or GitHub Advanced Security). Without it, set `sarif: false`.
- **Pull requests from forks** get a read-only token, so the action can't comment there. The job summary still has the report.

### Without the action

The same check with the CLI, step by step:

```yaml
name: vault-drift
on:
  schedule: [{cron: "0 6 * * 1-5"}]   # weekday mornings
  workflow_dispatch:

jobs:
  drift:
    runs-on: ubuntu-latest
    permissions: {id-token: write, contents: read}
    steps:
      - name: Install the Lockstep CLI
        run: pipx install "git+https://github.com/welshstew/lockstep@v0.12.0#subdirectory=backend"

      - name: Get an ID token for Vault (JWT auth)
        run: |
          curl -sSf -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
            "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=vault" | jq -r .value > "$RUNNER_TEMP/vault.jwt"

      - name: Compare production with staging
        run: |
          lockstep compare \
            --left-addr  https://vault-prod.example.com    --left-name prod \
            --left-auth jwt  --left-jwt-file  "$RUNNER_TEMP/vault.jwt" --left-role  lockstep-ci \
            --right-addr https://vault-staging.example.com --right-name staging \
            --right-auth jwt --right-jwt-file "$RUNNER_TEMP/vault.jwt" --right-role lockstep-ci \
            --mount app-config --profile .lockstep/prod-vs-staging.json \
            -o drift.yaml

      - name: Keep the report (no values in it)
        if: failure()
        uses: actions/upload-artifact@v4
        with: {name: vault-drift-report, path: drift.yaml}
```

## Policies kept in Git

If your ACL policies live in a repository, `lockstep policy diff --dir policies/` compares them with what Vault has, by meaning. A job that runs it fails when someone changed a policy by hand. See [policy diff](../cli.md#policies).

## GitLab CI and other systems

Any runner with Python 3.13 or newer works the same way: install with `pipx`, get a token, run `lockstep compare`, and keep `drift.yaml` when the job fails. The CLI is also in the [container image](../cli.md#from-the-container-image) as `--entrypoint lockstep`. That image has no shell, so in CI systems that run your script inside the job image, install with pipx instead.

## Ignore what's meant to differ

Environments differ on purpose: different layouts, hostnames that name their environment, per-environment credentials. A **comparison profile** keeps those from failing the build, without hiding real drift:
- **Map paths** when the layouts differ, for example `services/*/prod/**` ⇄ `services/*/staging/**`.
- **Rewrite words** that name the environment inside values, for example `prod` ⇄ `staging`. `db-prod.internal` then matches `db-staging.internal`, but a staging host pointed at production still fails the build. That's why a rewrite is better than ignoring `host`.
- **Ignore keys** that must differ, such as passwords and tokens under `services/**`. They're still listed, marked *ignored*, but they don't make a secret *Different*.
- **Ignore whole paths,** such as `legacy/**`.

Build the profile in the web UI ([guide](build-a-comparison-profile.md)):
1. In the profile editor, **Read both sides** suggests the mappings and rewrites.
2. **Pick what to ignore…** in the results takes care of the rest.

Then export the profile as JSON and commit it next to the workflow. `--profile` accepts the export directly; use `--profile-name` if the file holds several profiles. The report records the profile's rewrites, so `lockstep apply` uses them when it copies.

## Fail only on new drift

Once some drift is accepted, a job that fails on every difference fails on every run. Record the accepted drift in a **baseline**, commit it, and the job fails only on differences that aren't in it:

```sh
lockstep baseline update drift.json …        # the same options as compare
lockstep compare … --baseline drift.json -o drift.sarif -o drift.md
```

The baseline holds paths, key names and statuses, never values. A short one looks like this:

```json
{
  "lockstep_baseline": 1,
  "created": "2026-11-27T15:15:32Z",
  "left": {"name": "vault-a:8200", "mount": "app-config", "prefix": ""},
  "right": {"name": "vault-b:8200", "mount": "app-config", "prefix": ""},
  "drift": [
    {"path": "crypto/keys", "key": "aes_key", "status": "different"},
    {"path": "payments/api", "key": null, "status": "left_only"}
  ]
}
```

Each entry is one accepted difference: a key that differs, or a secret on one side only (`key` is `null`). The [demo's drift checks](https://getlockstep.cloud/drift/) show each pair's live baseline under **View base.json**. `--waivers` accepts single differences with an owner, a reason and an expiry date. `drift.sarif` goes to GitHub code scanning, and `drift.md` is a summary for a pull request comment. See [drift checks in CI](../cli.md#drift-checks-in-ci).

## Sign the baseline

A baseline is a file in the repository, so anyone who can push could add a line and hide new drift. Sign it, and changing what's accepted needs the signing key too:

```sh
lockstep plan-key                                  # once: a key pair
LOCKSTEP_PLAN_SIGNING_KEY=… lockstep baseline update drift.json --sign …
LOCKSTEP_PLAN_SIGNING_KEY=… lockstep waivers sign waivers.yaml
```

The check needs only the public key, in `LOCKSTEP_PLAN_TRUSTED_KEYS`:
- **A signed file is checked.** An edit, a garbled signature, or a key that isn't trusted makes the run exit 2. The summary names the signer.
- **`--require-signed` refuses an unsigned file too.** With the action, set `require-signed: true` and `trusted-keys: ${{ vars.LOCKSTEP_TRUSTED_KEYS }}`. The keys are public, so a repository variable will do; they don't need to be a secret.
- **Keep the private key out of the checking job.** It belongs where baseline changes are approved: an admin's machine, or a protected job that runs once a change is reviewed. A job that can sign could sign anything, and the signature would prove nothing.
- **Signing waivers** puts the issuer and signature at the end of the file. Comments and layout stay, but changing a waiver breaks the signature until someone signs it again.

## On a schedule, in Kubernetes

To check on a schedule rather than in a pipeline, the Helm chart's `driftCheck` CronJob runs the same `lockstep compare`, signed in as its own service account, with a baseline, waivers and a profile. With `--pushgateway` it pushes gauges to a Prometheus Pushgateway (`lockstep_drift_new_keys`, `lockstep_compare_success` and more), so an alert fires when new drift appears or the check stops running. See [drift monitoring](../drift-monitoring.md) for the values and alert rules.

## More than two environments

`lockstep matrix environments.yaml` compares one baseline with up to 12 environments at once, each under its own profile, reading the baseline only once. It exits like `compare` (0 no differences, 1 differences, 2 couldn't run) and writes the grid as text, JSON, YAML, Markdown or CSV, so one job can watch every environment. Rows that differ in only one environment come first. See [environment matrix](../cli.md#environment-matrix).

## Fixing the drift

The report the job keeps can also fix the drift. Download it, set `action: copy-to-right` or `copy-to-left` on the keys that should match, and run `lockstep apply drift.yaml` with a token that can write.
- **Prompts:** it asks before each key.
- **Stale secrets:** anything that changed since the report is skipped.
- **Deletes:** never.

To have a second person approve the change, open the same comparison in the web UI and save a [sync plan](../usage.md#sync-plans) instead.

## Next steps

- [How to compare secrets between two HashiCorp Vault clusters](compare-hashicorp-vault-clusters.md)
- [Syncing secrets between Vault environments safely](sync-vault-secrets-between-environments.md)
- [Logging in to Vault with JWT from CI](vault-jwt-login-from-ci.md)
- [Building a comparison profile](build-a-comparison-profile.md)
- [Command-line reference](../cli.md)
