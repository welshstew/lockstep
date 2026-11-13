<!-- description: Log in to HashiCorp Vault from GitHub Actions or GitLab CI with the pipeline's OIDC identity token and Vault's JWT auth method, and run Lockstep comparisons and exports with no stored secrets. -->
# Logging in to Vault with JWT from CI

A pipeline that compares or exports secrets needs a Vault token. Storing a long-lived token as a CI secret is the usual shortcut, and the usual weak spot: it never expires, it's shared by every job that can read it, and nobody remembers to rotate it.

Most CI systems can instead give each job a short-lived, signed **identity token** (a JWT). It says which repository, branch and pipeline the job belongs to. Vault's [JWT auth method](https://developer.hashicorp.com/vault/docs/auth/jwt) can check that token and exchange it for a Vault token with exactly the policies that pipeline should have.

[Lockstep](https://getlockstep.cloud) logs in with JWT directly, in the CLI and in the web UI, so there's nothing to store.

## How it works

1. The CI job asks its platform for an ID token with an audience Vault expects, for example `vault`.
2. Lockstep sends it to `auth/jwt/login` with a role name.
3. Vault checks the signature (against the issuer's published keys), the issuer, the audience, the expiry and the role's claim bindings. It then returns a token with the role's policies.
4. Lockstep uses that token for the comparison or export, and revokes it when the command finishes.

The JWT is never written into reports or logs. The CLI only reads it from an environment variable or a file, never from an argument, because arguments show up in `ps` and shell history.

## GitHub Actions

### Vault side

Trust GitHub's issuer, and bind a role to the repository and branch that may use it:

```sh
vault auth enable jwt
vault write auth/jwt/config \
    oidc_discovery_url=https://token.actions.githubusercontent.com \
    bound_issuer=https://token.actions.githubusercontent.com

vault write auth/jwt/role/lockstep-ci - <<'EOF'
{
  "role_type": "jwt",
  "user_claim": "repository",
  "bound_audiences": ["vault"],
  "bound_claims": {"repository": "my-org/my-repo", "ref": "refs/heads/main"},
  "token_policies": ["lockstep-readonly"],
  "token_ttl": "10m"
}
EOF
```

`bound_claims` is what keeps other repositories, and pull requests from forks, out. Keep it as narrow as you can. The [security guide](../security.md#vault-policies) has a read-only `lockstep-readonly` policy.

### Workflow

```yaml
jobs:
  drift:
    runs-on: ubuntu-latest
    permissions: {id-token: write, contents: read}   # id-token: write lets the job request a JWT
    steps:
      - uses: actions/checkout@v4
      - run: pipx install "git+https://github.com/welshstew/lockstep@v0.4.0#subdirectory=backend"

      - name: Get an ID token for Vault
        run: |
          curl -sSf -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
            "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=vault" | jq -r .value > "$RUNNER_TEMP/vault.jwt"

      - name: Compare production with staging
        run: |
          lockstep compare \
            --left-addr  https://vault-prod.example.com    --left-auth  jwt --left-jwt-file  "$RUNNER_TEMP/vault.jwt" --left-role  lockstep-ci \
            --right-addr https://vault-staging.example.com --right-auth jwt --right-jwt-file "$RUNNER_TEMP/vault.jwt" --right-role lockstep-ci \
            --mount app-config --profile .lockstep/prod-vs-staging.json -o drift.yaml
```

The same token works for both Vaults when both trust GitHub's issuer and accept the `vault` audience. ID tokens expire after a few minutes, so request one just before it's needed.

## GitLab CI

### Vault side

```sh
vault write auth/jwt/config \
    oidc_discovery_url=https://gitlab.example.com \
    bound_issuer=https://gitlab.example.com

vault write auth/jwt/role/lockstep-ci - <<'EOF'
{
  "role_type": "jwt",
  "user_claim": "project_path",
  "bound_audiences": ["vault"],
  "bound_claims": {"project_path": "platform/secrets-checks", "ref_protected": "true"},
  "token_policies": ["lockstep-readonly"],
  "token_ttl": "10m"
}
EOF
```

### Pipeline

```yaml
vault-drift:
  image: python:3.13-slim
  id_tokens:
    VAULT_ID_TOKEN: {aud: vault}
  script:
    - pip install pipx && pipx install "git+https://github.com/welshstew/lockstep@v0.4.0#subdirectory=backend"
    - export PATH="$HOME/.local/bin:$PATH"
    - export LOCKSTEP_LEFT_JWT="$VAULT_ID_TOKEN" LOCKSTEP_RIGHT_JWT="$VAULT_ID_TOKEN"
    - lockstep compare
        --left-addr https://vault-prod.example.com --left-auth jwt --left-role lockstep-ci
        --right-addr https://vault-staging.example.com --right-auth jwt --right-role lockstep-ci
        --mount app-config -o drift.yaml
  artifacts:
    when: on_failure
    paths: [drift.yaml]
```

## Scheduled exports

Exports log in the same way with the `--vault-*` options. A nightly encrypted backup of a mount:

```sh
lockstep export --vault-addr https://vault-prod.example.com \
    --vault-auth jwt --vault-jwt-file "$RUNNER_TEMP/vault.jwt" --vault-role lockstep-backup \
    --mount app-config -o "app-config-$(date +%F).json" --key-file app-config.key
```

The export is encrypted with a new key every time. Store the key separately from the file, for example in a different secret store or with a different retention policy, or the encryption protects nothing. Give the backup role read-only access to just that mount. See [Exporting, importing and migrating Vault secrets](export-import-vault-secrets.md).

## In the web UI

People can sign in with a JWT too: choose **JWT** on the connect screen and paste a token, with an optional role and mount. This is useful for an ID token from your identity provider, or for checking what a CI role can see. Vault applies the same checks. Lockstep doesn't keep the JWT, and revokes the Vault token it returns when you sign out.

For people signing in through a browser, **OIDC** (a redirect to your identity provider) is usually the better choice. Use **JWT** for tokens you already have.

## Troubleshooting

| Vault's error mentions | Usually means |
|---|---|
| `aud` / audience | The token's `aud` isn't in the role's `bound_audiences`. Request the token with the right audience |
| a claim that doesn't match the bound claims | The job runs on a branch, tag or project the role doesn't allow. That's the binding doing its job |
| `role_type` / oidc | The role is for the browser OIDC flow. Create a separate `role_type=jwt` role |
| expired | ID tokens are short-lived. Request one right before the Lockstep step |
| `permission denied` on list or read | Login worked. The role's policies don't cover the mount or path |

## Next steps

- [Detecting secret drift in CI](detect-vault-secret-drift-in-ci.md)
- [Authentication reference: JWT](../authentication.md#jwt)
- [Command-line reference: logging in](../cli.md)
