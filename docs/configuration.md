# Configuration

All configuration comes from environment variables prefixed `LOCKSTEP_`. Lists accept JSON (`["a","b"]`); the two plain string lists also accept comma-separated values.

## Core

| Variable | Default | Description |
|---|---|---|
| `LOCKSTEP_SESSION_KEY` | **required** | At least 32 characters. Encrypts the session cookie, which holds Vault tokens. Every replica needs the same value; changing it signs everyone out |
| `LOCKSTEP_PUBLIC_URL` | `http://localhost:8080` | The URL users open. Used to build the OIDC callback (`<url>/api/auth/oidc/callback`) and the redirect back afterwards |
| `LOCKSTEP_COOKIE_SECURE` | `true` | Send the session cookie only over HTTPS. Set `false` only for plain-HTTP local development |
| `LOCKSTEP_SESSION_TTL_SECONDS` | `28800` (8 h) | Session lifetime. Each connection also expires with its Vault token |

## Vaults

| Variable | Default | Description |
|---|---|---|
| `LOCKSTEP_PRESET_CONNECTIONS` | `[]` | JSON list of Vaults offered in the UI: `{"name": "…", "url": "…", "browser_url": "…", "namespace": "…"}`. `url` is how the **server** reaches Vault and is never sent to browsers; `browser_url` is only for display |
| `LOCKSTEP_ALLOW_CUSTOM_CONNECTIONS` | `true` | Let users type their own Vault address. Set `false` to restrict the tool to the presets |
| `LOCKSTEP_CUSTOM_URL_PATTERNS` | `[]` | If set, a custom address must fully match one of these regular expressions (e.g. `https://vault\.[a-z]+\.example\.com(:8200)?`). Limits which hosts the server will call (SSRF) |
| `LOCKSTEP_VAULT_TLS_VERIFY` | `true` | Verify Vault's TLS certificate. Don't turn off outside development |
| `LOCKSTEP_VAULT_CA_BUNDLE` | — | Path to a PEM bundle, for Vaults with a private CA |
| `LOCKSTEP_PROFILES` | `[]` | Shared [comparison profiles](usage.md#comparison-profiles), JSON: `[{"name", "description"?, "left_mount"?, "left_prefix"?, "right_mount"?, "right_prefix"?, "rules": {"mappings": [{"left", "right"}], "ignore_keys": [{"key", "path"?}], "ignore_paths": [...]}}]`. Validated at startup: a malformed profile stops the server with a clear message. With the Helm chart, set the `profiles` value instead ([example](../charts/lockstep/README.md#examples)) |
| `LOCKSTEP_MAX_TREE_SECRETS` | `5000` | Per side, the most secrets a comparison will list before reporting it as truncated. Use a path prefix for bigger mounts |

## Kubernetes auth

See [authentication](authentication.md#kubernetes-service-account) for what this means for security.

| Variable | Default | Description |
|---|---|---|
| `LOCKSTEP_K8S_AUTH_ENABLED` | `false` | Allow signing in as the pod's service account |
| `LOCKSTEP_K8S_AUTH_ROLES` | *(any)* | Vault role names users may pick (comma-separated or JSON). Empty means any role |
| `LOCKSTEP_K8S_AUTH_MOUNT` | `kubernetes` | Default auth mount path shown in the UI |
| `LOCKSTEP_K8S_TOKEN_PATH` | `/var/run/secrets/kubernetes.io/serviceaccount/token` | Service account token file |

## Other

| Variable | Default | Description |
|---|---|---|
| `LOCKSTEP_STATIC_DIR` | `/app/static` in the image | The built web UI. Leave as is |
