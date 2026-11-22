<!-- description: Every LOCKSTEP_* environment variable: preset Vault connections, custom URLs, sessions, TLS, Kubernetes auth and shared comparison profiles. -->
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
| `LOCKSTEP_POLICY_PATTERNS` | `[]` | Shared [suggestion patterns](usage.md#build-and-suggest-policies), JSON: `[{"name", "layout": "{app}/{env}/**", "values"?, "policies": [{"name": "{app}-{env}-app", "description"?, "rules": [{"where", "can"}]}], "compare"?: {"pair": {"env": ["dev", "prod"]}}}]`. Validated at startup. Helm chart value `policyPatterns` |
| `LOCKSTEP_CONFIG_PROFILES` | `[]` | Shared configuration profiles for the Configuration tab, JSON: `[{"name", "description"?, "mappings"?: [{"left": "kv-dev", "right": "kv-prod"}], "rewrites"?: [{"find", "replace"}], "ignore"?: ["sandbox-*"]}]`. Mappings pair mount paths (a mount's roles and keys follow it). Helm chart value `configProfiles` |
| `LOCKSTEP_POLICY_PROFILES` | `[]` | Shared [policy profiles](usage.md#compare-policies-across-vaults), JSON: `[{"name", "description"?, "mappings"?: [{"left": "*-dev", "right": "*-prod"}], "rewrites"?: [{"find", "replace"}], "ignore"?: ["root"]}]`. Validated at startup. Helm chart value `policyProfiles` |
| `LOCKSTEP_MAX_TREE_SECRETS` | `5000` | Per side, the most secrets a comparison will list before reporting it as truncated. Use a path prefix for bigger mounts |
| `LOCKSTEP_USER_WRITE` | `off` | Let Policies › Roles create userpass users and reset their passwords (a generated password is shown once; audit-logged without it). Meant for development Vaults. Chart value `userWrite` |
| `LOCKSTEP_POLICY_APPLY` | `on` | Let the Policies tab write and delete ACL policies and Kubernetes/JWT/OIDC roles (after a review; Vault's policies still decide who may). `off` where Terraform or another tool owns them: building, comparing and downloading for an admin still work. Chart value `policyApply` |
| `LOCKSTEP_READ_ONLY` | `false` | Make this Lockstep look-only: every write is hidden in the UI and refused by the API (Browse edits, copies, overrides, deleting keys, imports, plan applies, destroys). Browsing, comparing, exports, explaining and comparing policies, and creating sync plans still work. Chart value `readOnly` |
| `LOCKSTEP_ALLOW_CLIPBOARD` | `true` | Offer **Copy** next to shown values in Browse (cleared from the clipboard after 30 seconds where the browser allows). `false` removes the button; it can't stop someone selecting a value they can see. Chart value `allowClipboard` |
| `LOCKSTEP_ALLOW_DESTROY` | `true` | Offer [**Destroy**](usage.md#destroy-secrets), which permanently deletes every version and the metadata of secrets. Vault's policies still decide who may (`delete` on `<mount>/metadata/…`); `false` turns it off for everyone |
| `LOCKSTEP_EXPORT_MODE` | `any` | [Secret-engine exports](usage.md#6-export-and-import), which hold values: `any` lets users choose encrypted or plain, `encrypted` allows only exports encrypted with a one-time key, `off` turns exporting off. Importing isn't affected: it writes with the user's own token |

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
