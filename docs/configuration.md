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
| `LOCKSTEP_PRESET_CONNECTIONS` | `[]` | JSON list of Vaults offered in the UI: `{"name": "…", "url": "…", "browser_url": "…", "namespace": "…", "timeout_seconds": 15}`. `url` is how the **server** reaches Vault and is never sent to browsers; `browser_url` is only for display; `timeout_seconds` (optional) overrides `LOCKSTEP_VAULT_TIMEOUT_SECONDS` for that Vault. `writable`, `allow_destroy`, `write_paths` and `deny_paths` set a [write policy](#write-policy-per-vault) for it |
| `LOCKSTEP_ALLOW_CUSTOM_CONNECTIONS` | `false` | Let users type their own Vault address, which the **server** will call. Off, only the presets can be used. Before 0.11 the default was `true` |
| `LOCKSTEP_CUSTOM_URL_PATTERNS` | `[]` | If set, a custom address's origin must fully match one of these regular expressions (e.g. `https://vault\.[a-z]+\.example\.com(:8200)?`). The address is normalised to `scheme://host[:port]` first (lower case, no default port), and one with a user name, path, query or fragment is refused, so a pattern can't be tricked with `user@other-host` |
| `LOCKSTEP_CUSTOM_ALLOW_PRIVATE` | `false` | Let a custom address resolve to a private, loopback, link-local (such as `169.254.169.254`) or other non-public IP. Off, the host is resolved and refused if any of its addresses isn't public. Either way, Lockstep connects to the address it checked, so a DNS answer can't change in between. Turn on for a Vault on an internal network; then the patterns are the limit. Chart value `customAllowPrivate` |
| `LOCKSTEP_VAULT_TLS_VERIFY` | `true` | Verify Vault's TLS certificate. Don't turn off outside development |
| `LOCKSTEP_VAULT_CA_BUNDLE` | — | Path to a PEM bundle, for Vaults with a private CA |
| `LOCKSTEP_VAULT_TIMEOUT_SECONDS` | `15` | How long one call to a Vault may take. Reads are retried twice, after a short pause, when the connection fails or Vault answers `429`, `502`, `503` or `504` (a `Retry-After` over 2 seconds isn't waited for). Writes are never retried. Set with `extraEnv` in the Helm chart |
| `LOCKSTEP_PROFILES` | `[]` | Shared [comparison profiles](usage.md#comparison-profiles), JSON: `[{"name", "description"?, "left_mount"?, "left_prefix"?, "right_mount"?, "right_prefix"?, "rules": {"mappings": [{"left", "right"}], "ignore_keys": [{"key", "path"?, "field"?}], "ignore_paths": [...], "rewrites": [{"left", "right", "key"?, "path"?}], "exact_keys": [{"key", "path"?}], "unordered_keys": [{"key", "path"?, "field"?, "separator"?}], "volatile": [{"key", "path"?, "pattern"}]}}]`. Validated at startup: a malformed profile stops the server with a clear message. With the Helm chart, set the `profiles` value instead ([example](../charts/lockstep/README.md#examples)) |
| `LOCKSTEP_POLICY_PATTERNS` | `[]` | Shared [suggestion patterns](usage.md#build-and-suggest-policies), JSON: `[{"name", "layout": "{app}/{env}/**", "values"?, "policies": [{"name": "{app}-{env}-app", "description"?, "rules": [{"where", "can"}]}], "compare"?: {"pair": {"env": ["dev", "prod"]}}}]`. Validated at startup. Helm chart value `policyPatterns` |
| `LOCKSTEP_CONFIG_PROFILES` | `[]` | Shared configuration profiles for the Configuration tab, JSON: `[{"name", "description"?, "mappings"?: [{"left": "kv-dev", "right": "kv-prod"}], "rewrites"?: [{"find", "replace"}], "ignore"?: ["sandbox-*"]}]`. Mappings pair mount paths (a mount's roles and keys follow it). Helm chart value `configProfiles` |
| `LOCKSTEP_POLICY_PROFILES` | `[]` | Shared [policy profiles](usage.md#compare-policies-across-vaults), JSON: `[{"name", "description"?, "mappings"?: [{"left": "*-dev", "right": "*-prod"}], "rewrites"?: [{"find", "replace"}], "ignore"?: ["root"]}]`. Validated at startup. Helm chart value `policyProfiles` |
| `LOCKSTEP_MAX_TREE_SECRETS` | `5000` | Per side, the most secrets a comparison will list before reporting it as truncated. Use a path prefix for bigger mounts |
| `LOCKSTEP_AUDIT_REVEALS` | `off` | Add a `secret.reveal` line to the [audit log](usage.md#audit-log) whenever a response carries secret values: who, which Vault, mount, path and key names, with the request ID. Never the values. Chart value `auditReveals` |
| `LOCKSTEP_API_DOCS` | `on` | Serve the interactive API documentation (Swagger UI at `/api/docs`) and `/api/openapi.json`. `off` hides both; the API itself is unchanged. Swagger UI loads its script from jsDelivr, so `/api/docs` alone gets a Content-Security-Policy that allows it. Chart value `apiDocs` |
| `LOCKSTEP_USER_WRITE` | `off` | Let Policies › Roles create userpass users and reset their passwords (a generated password is shown once; audit-logged without it). Meant for development Vaults. Chart value `userWrite` |
| `LOCKSTEP_POLICY_APPLY` | `on` | Let the Policies tab write and delete ACL policies and Kubernetes/JWT/OIDC roles (after a review; Vault's policies still decide who may). `off` where Terraform or another tool owns them: building, comparing and downloading for an admin still work. Chart value `policyApply` |
| `LOCKSTEP_READ_ONLY` | `false` | Make this Lockstep look-only: every write is hidden in the UI and refused by the API (Browse edits, copies, overrides, deleting keys, imports, plan applies, destroys). Browsing, comparing, exports, explaining and comparing policies, and creating sync plans still work. Chart value `readOnly` |
| `LOCKSTEP_RATE_LIMIT_PER_MINUTE` | `0` (off) | Limit API requests per client address, for an install open to anyone (the public demo uses 180). Over the limit, the API answers `429` with `Retry-After`. Held in memory per process, so each replica counts on its own. Behind a reverse proxy the address is the client's only if the proxy sets `X-Forwarded-For` (the image trusts it). Set with `extraEnv` in the Helm chart |
| `LOCKSTEP_RATE_LIMIT_BURST` | a quarter of the per-minute limit, at least 20 | How many requests a client may make at once before the per-minute rate applies |
| `LOCKSTEP_SIGNIN_MAX_FAILURES` | `10` | Failed sign-ins (a wrong password or token, a rejected second factor) allowed per client address, and per user name on a Vault, within the window. Past that, sign-in answers `429` with `Retry-After` until the oldest failure leaves the window, even with the right password. A successful sign-in clears that user's count. Starting an OIDC sign-in waits too while the address is over the limit. `0` turns it off. In memory, per process. Set with `extraEnv` in the Helm chart |
| `LOCKSTEP_SIGNIN_WINDOW_SECONDS` | `300` | The window for `LOCKSTEP_SIGNIN_MAX_FAILURES` |
| `LOCKSTEP_ALLOW_CLIPBOARD` | `true` | Offer **Copy** next to shown values in Browse (cleared from the clipboard after 30 seconds where the browser allows). `false` removes the button; it can't stop someone selecting a value they can see. Chart value `allowClipboard` |
| `LOCKSTEP_ALLOW_DESTROY` | `true` | Offer [**Destroy**](usage.md#destroy-secrets), which permanently deletes every version and the metadata of secrets. Vault's policies still decide who may (`delete` on `<mount>/metadata/…`); `false` turns it off for everyone |
| `LOCKSTEP_EXPORT_MODE` | `encrypted` | [Secret-engine exports](usage.md#6-export-and-import), which hold values: `encrypted` allows only exports encrypted with a one-time key, `any` lets users choose encrypted or plain, `off` turns exporting off. A preset's `export` replaces it for that Vault ([below](#write-policy-per-vault)). Importing isn't affected: it writes with the user's own token. Before 0.11.0 the default was `any` |
| `LOCKSTEP_EXPORT_RECIPIENTS` | none | Teams an export can be encrypted to, as JSON: `[{"name": "Platform", "recipients": ["age1…", "age1…"]}]`. Users tick a team in the Export panel and its members open the file with their own age identity, in Lockstep or with `age -d`. Keys are checked at startup. Users can also paste age keys themselves. Chart value `exportRecipients` |

### Write policy per Vault

Each preset can limit what Lockstep writes to that Vault, so one installation can "compare prod, write dev" without being read-only everywhere:

```json
[{"name": "Prod", "url": "https://vault.prod:8200", "writable": false},
 {"name": "Dev", "url": "https://vault.dev:8200",
  "write_paths": ["app-config/**", "sys/policies/acl/app-*"],
  "deny_paths": ["app-config/*/break-glass/**"], "allow_destroy": false}]
```

| Field | Default | |
|---|---|---|
| `writable` | `true` | `false`: compare, browse and export only. Nothing is written to this Vault from Lockstep |
| `allow_destroy` | `LOCKSTEP_ALLOW_DESTROY` | `false` turns **Destroy** off for this Vault only |
| `write_paths` | everything | Writes only to paths that match one of these |
| `deny_paths` | nothing | Never write to paths that match one of these, even inside `write_paths` |
| `approvals` | `0` | `1`: secrets on this Vault change only through [sync plans someone else approved](#four-eyes-approvals). Copies, Browse edits, imports and destroys there are refused. Policy and role writes aren't affected |
| `export` | `LOCKSTEP_EXPORT_MODE` | Exports from this Vault: `encrypted`, `any` or `off`. It replaces the server's setting, so it can be stricter (`"export": "off"` for Prod) or looser (`"export": "any"` for a dev Vault on a server that otherwise only allows encrypted exports) |

- **Paths** are what a write changes, as Vault names it. For a KV secret that's `<mount>/<path>`, without `data/`, such as `app-config/billing/db`. Anything else uses its API path: `sys/policies/acl/<name>` (policy applies, and the policy *Try* creates for a moment), `auth/<mount>/role/<name>`, `auth/<mount>/users/<name>`, `identity/group/name/<name>`, `sys/mounts/<mount>/tune`, `<mount>/issue/<role>` (PKI), `<mount>/creds/<role>` (database credentials) and `sys/leases/revoke/<lease ID>`. `*` matches one path segment and `**` any number, and `a/**` covers `a` itself.
- **Enforcement:** the API refuses what the rules forbid, whatever the user's Vault policies allow. Copies, sync plans and imports mark each refused secret *invalid* with the reason, while destroys and single writes answer 403. The rules come on top of Vault's policies, which still decide everything else: every write uses the user's own token.
- **In the UI:** a side on a read-only Vault shows no copy arrows toward it, Browse shows *read-only here* without edit buttons, and Destroy disappears where it's off. With `write_paths` or `deny_paths`, Browse says *writes limited*, and a write outside them is refused with the reason.
- **Audit log:** each refusal is logged as a `write.refused` event with the path, who asked and why.
- **Same address:** the rules follow the Vault's address. A user who types a preset's address by hand, or opens a namespace from a preset connection, gets that preset's rules. When several presets share an address, the strictest applies.

`LOCKSTEP_READ_ONLY` still makes the whole installation look-only. Chart: `vaults[].writable`, `allowDestroy`, `writePaths`, `denyPaths`, `approvals` and `exportMode`.

### Browser security headers

Every response carries `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`, a `Permissions-Policy` that turns off camera, microphone and location, and a `Content-Security-Policy` that only allows the app's own scripts and connections (`frame-ancestors 'none'`). `Strict-Transport-Security` (one year) is added when `LOCKSTEP_PUBLIC_URL` starts with `https://`. A reverse proxy that sets the same headers overrides them.

### Vaults behind load balancers and proxies

- **HA standbys:** a standby that answers with a redirect (`307`/`308`) is followed, at most twice, but only to the same Vault or another preset Vault, because the token goes with the request. A redirect anywhere else fails with "Vault redirected to *host*: point Lockstep at the active node or the load balancer".
- **Proxies that block `LIST`:** some proxies and web application firewalls refuse the `LIST` method. When a `LIST` gets `405`, or a `403` that isn't Vault's own "permission denied", Lockstep asks again with `GET …?list=true`, which Vault treats the same, and keeps doing that for the rest of the request.

## Logging

| Variable | Default | Description |
|---|---|---|
| `LOCKSTEP_LOG_LEVEL` | `info` | `debug`, `info`, `warning` or `error`. Chart value `logging.level` |
| `LOCKSTEP_LOG_FORMAT` | `text` | `text`: one readable line per event. `json`: one JSON object per line, for log collectors. Chart value `logging.format` |

The server log goes to **stderr**. Each line has a UTC timestamp, the level, the logger and a request ID:

```
2026-11-25T17:00:47.668Z INFO    lockstep [-] Lockstep 0.11.0 starting; log level info, format text
2026-11-25T17:00:47.668Z INFO    lockstep [-] preset Vault 0: Vault A at http://vault-a:8200
2026-11-25T17:01:03.120Z INFO    lockstep.auth [c1e02a51] sign-in to Vault A as alice (userpass) failed: Vault said 400: invalid username or password
2026-11-25T17:01:03.121Z INFO    lockstep.http [c1e02a51] POST /api/connections 401 18ms client 203.0.113.7
```

- **At `info`:** what the server started with (version, preset Vaults, the main settings), sign-ins and sign-outs, one line per API request (method, path, status, time, client address), and Vaults that can't be reached or answer with a 5xx.
- **At `debug`:** also every call Lockstep makes to a Vault (method, path, status, time). This helps when a page is slow or a Vault answers unexpectedly. Health probes and static files are logged only here.
- **Request IDs:** every response carries an `X-Request-ID` header, and every line logged while handling that request shows the same ID. A proxy's `X-Request-ID` is kept. An unexpected error answers `500` with the request ID in the message, and the log has the stack trace under that ID.
- **Never logged:** secret values, tokens, passwords, request and response bodies, and query strings. Paths are logged: they name secrets but don't hold them.

The [audit log](usage.md#audit-log) is separate: JSON on **stdout**, unaffected by these settings.

## Plans between installations

Sync plans and access plans (policies, roles, tuning) are signed files. By default the signature uses a key derived from `LOCKSTEP_SESSION_KEY`, so a plan applies only where that session key is set: the same installation and its replicas. To make plans on one Lockstep (say dev, where read-only users prepare changes) and apply them on another (prod), sign them with an Ed25519 key pair:

| Variable | Default | |
|---|---|---|
| `LOCKSTEP_PLAN_SIGNING_KEY` | none | This installation's Ed25519 private key (base64 of the 32 raw bytes, or PEM). Plans made here are signed with it. Chart: `plans.signingKeySecret` |
| `LOCKSTEP_PLAN_TRUSTED_KEYS` | `[]` | JSON list of the installations whose plans this one applies: `[{"name": "dev-lockstep", "key": "<base64 public key>"}]`. An installation always trusts its own key. Chart: `plans.trustedKeys` |
| `LOCKSTEP_PLAN_ISSUER` | `LOCKSTEP_PUBLIC_URL`'s host | This installation's name in the plans it makes, and the name a plan's `audience` has to list to be applied here. Chart: `plans.issuer` |
| `LOCKSTEP_PLAN_TTL_HOURS` | `168` | How long a new plan can be applied (7 days). Chart: `plans.ttlHours` |

1. `lockstep plan-key` prints a new key pair. Put the private key in a secret store, and set it as `LOCKSTEP_PLAN_SIGNING_KEY` on the installation that makes plans.
2. On each installation that applies them, add the public key to `LOCKSTEP_PLAN_TRUSTED_KEYS`, under the name the making installation signs as. `GET /api/plans/key` shows an installation's name, key ID and public key.

Every new plan records its `issuer` (name and key ID), `not_before` and `expires_at`, and optionally an `audience`. A plan signed by a key the applying installation doesn't trust, one that has expired, or one whose audience doesn't name the applying installation is refused with the reason. Clocks may differ by 5 minutes.

- **Rotating the key:** keep the old public key in the trusted list until the plans made with it have expired.
- **Typed values:** a plan keeps a check code for each value typed by hand, which only the installation that made it can verify. On another installation, the person applying types each value twice instead.
- **Without a key pair** nothing changes: plans are signed as before. Plans made by earlier versions still apply where they did.

## Four-eyes approvals

A light check against mistakes, not a compliance control: before a sync plan is applied, someone other than the person who made it checks it and approves it.

| Setting | |
|---|---|
| `LOCKSTEP_PLAN_APPROVALS=1` | Every sync plan applied on this installation needs one approval. Copies made without a plan still work. Chart: `plans.approvals` |
| a preset's `"approvals": 1` | Plans writing to that Vault need one approval, and its secrets change **only** through plans: direct copies, Browse edits, imports and destroys there are refused, so the approval can't be gone round. The review dialog says so, and **Save as plan** still works. Chart: `vaults[].approvals` |

- **Approving:** the approver opens the plan in **Sync plans**, signs in to the Vaults it names (write access isn't needed), runs **Check plan** and chooses **Approve**. Lockstep adds a signed approval to the file and downloads it (`…-approved.json`) to pass on. The plan's own signature is unchanged, so an approval can't change what the plan does.
- **Who counts:** someone whose Vault **entity** differs from the creator's on every Vault the plan writes. Entities are compared, not display names, and approving needs a sign-in with an entity (userpass, LDAP, OIDC…), not a root token. The person applying may be the approver.
- **Applying** is refused until there are enough approvals, with the reason. An approval that was edited, or signed by an installation this one doesn't trust, doesn't count. Approvals are signed like plans, so they travel between installations the same way.
- **The audit log** records `plan.approve` with the approver's entity IDs and accessors.
- **Not included:** approver groups, several approvers, and approvals for access plans and undo plans.

## Metrics

| Variable | Default | Description |
|---|---|---|
| `LOCKSTEP_METRICS` | `off` | `on` serves Prometheus metrics at `/metrics`: API requests and latency by route template, calls to each Vault, sign-ins, 429s. Labels never hold secret paths, users or tokens. Chart value `metrics.enabled`. See [drift monitoring](drift-monitoring.md#server-metrics) |
| `LOCKSTEP_METRICS_TOKEN` | *(none)* | When set, `/metrics` needs `Authorization: Bearer <this>`. Chart value `metrics.tokenSecret` |

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
