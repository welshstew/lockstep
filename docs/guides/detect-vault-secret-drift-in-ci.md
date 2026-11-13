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
        run: pipx install "git+https://github.com/welshstew/lockstep@v0.4.0#subdirectory=backend"

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

## GitLab CI and other systems

Any runner with Python 3.13 or newer works the same way: install with `pipx`, get a token, run `lockstep compare`, and keep `drift.yaml` when the job fails. The CLI is also in the [container image](../cli.md#from-the-container-image) as `--entrypoint lockstep`. That image has no shell, so in CI systems that run your script inside the job image, install with pipx instead.

## Ignore what's meant to differ

Environments differ on purpose: hostnames, URLs, per-environment credentials. A **comparison profile** keeps those from failing the build.
- **Ignore keys:** such as `host` or `*_url` under `services/**`. They're still listed, marked *ignored*, but they don't make a secret *Different*.
- **Ignore whole paths:** such as `legacy/**`.
- **Map paths:** when the layouts differ, for example `services/*/prod/**` ⇄ `services/*/staging/**`.

Build the profile in the web UI, most quickly by pressing **Pick what to ignore…** and clicking *Ignore* on the noise ([guide](build-a-comparison-profile.md)). Then export it as JSON and commit it next to the workflow. `--profile` accepts the export directly; use `--profile-name` if the file holds several profiles.

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
