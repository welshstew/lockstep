# HTTP API

The web UI uses this API, and you can script against it too. Interactive documentation (OpenAPI) is served at `/api/docs`.

**Rules:**
- **Sessions:** a session is the encrypted cookie set when you add a connection, so use a client that keeps cookies.
- **CSRF header:** every request other than GET must send `X-Requested-With: lockstep`.
- **Errors:** they come back as `{"detail": {"message": "…", …}}`.

## Configuration and connections

| Method & path | Purpose |
|---|---|
| `GET /api/config` | Preset Vaults (server-side URLs hidden), whether custom URLs and Kubernetes auth are available |
| `GET /api/connections` | This session's connections, with live token status |
| `POST /api/connections` | Add one: `{"preset_id": 0 \| "url": "…", "namespace"?, "auth": {...}}`, where `auth` is `{"method":"token","token"}`, `{"method":"userpass"\|"ldap","username","password","mount"?}` or `{"method":"kubernetes","role","mount"?}`. `202` with `{"mfa_required": true, "constraints"}` when Vault asks for a second factor |
| `GET /api/connections/mfa` | The second factors a sign-in is waiting for (after a `202` from `POST /api/connections`, or `?mfa=1` after an OIDC redirect) |
| `POST /api/connections/mfa` | `{"payload": {method id: passcode, or "" for push}}` sends them to Vault (`sys/mfa/validate`) and finishes the sign-in, like `POST /api/connections`. `401` for a rejected passcode (try again), `410` when nothing is waiting or it expired |
| `DELETE /api/connections/{id}` | Remove it (revokes tokens the tool created) |
| `GET /api/connections/{id}/mounts` | KV v2 mounts, and whether the list is complete |
| `GET /api/connections/{id}/mounts/{path}` | Check a typed mount path |
| `GET /api/connections/{id}/tree?mount=&prefix=` | Every secret path, plus folders that couldn't be listed |

## Sign-in

| Method & path | Purpose |
|---|---|
| `POST /api/auth/methods` | Sign-in methods a Vault advertises (`{"preset_id"\|"url", "namespace"?}`) |
| `POST /api/auth/oidc/start` | `{"preset_id"\|"url", "mount"?, "role"?, "side"?}` returns `{"auth_url"}`; send the browser there |
| `GET /api/auth/oidc/callback` | Where the identity provider returns. It finishes the login and redirects to the app |

## Comparing

| Method & path | Purpose |
|---|---|
| `POST /api/compare` | `{"left": {"conn_id","mount","prefix"?}, "right": {…}, "rules"?: {mappings, ignore_keys, ignore_paths, rewrites}}` returns a status per secret and key (`ignored` and `rewritten` flags, each side's `left_path`/`right_path`), versions, timestamps and value-type badges. **No values** |
| `POST /api/compare/suggest` | Same body as `/api/compare`. Reads both sides and suggests profile rules on top of `rules`: `mappings` (renamed folders, each with the `pairs` it makes and a `reason`) and `rewrites` (words, the number of differing `keys` each makes equal, where, and a `reason`). Also returns both sides' secret paths and the counts `before` and `after` the suggestions. Rewrite words come only from paths and common environment names. **No values** |
| `GET /api/profiles` | Shared comparison profiles configured on the server |
| `GET /api/connections/{id}/secret?mount=&path=` | One secret's values (what *Show values* uses) |
| `GET /api/connections/{id}/history?mount=&path=` | For each key, the version and time it last changed. No values |

## Certificate expiry

| Method & path | Purpose |
|---|---|
| `POST /api/expiry` | `{"sides": [{"side": "left"\|"right", "conn_id", "mount", "prefix"?}]}` returns every certificate found (subject, issuer, dates, status, where; never values), keystores that couldn't be fully checked, and per-side scan stats |
| `POST /api/expiry` and `/api/expiry/stream` with `"include_pki": true` | Also certificates issued by the Vaults' PKI engines (not revoked) and their issuers, as rows with `container` `PKI-issued` or `PKI issuer` |
| `POST /api/expiry/stream` | The same scan as NDJSON, one event per line: `{"progress": {"side", "stage", "done", "total", "certificates"}}` at least every few seconds, then `{"result": …}` (the `/api/expiry` body) or `{"error": {"status", "message"}}`. A long scan keeps sending lines, so proxies don't time it out. The web app uses this one |

## Copying

| Method & path | Purpose |
|---|---|
| `POST /api/sync/preview` | `{"left","right","changes":[{"path","right_path"?,"direction":"left_to_right"\|"right_to_left","keys": [...]\|null,"set"?: {key: value},"remove"?: [...],"expected_target_version","expected_source_version"}],"reveal"?,"rewrites"?: [{"left","right"}]}` returns a plan per secret. `set` writes typed values; `remove` drops keys from the target's new version; `rewrites` (the comparison profile's) are applied to copied values in the copy's direction, and each key plan says whether they changed it (`rewritten`) |
| `POST /api/sync/apply` | The same body plus `"confirm": true`; returns a result per secret and a summary. A change that removes every key soft-deletes the latest version (`"action": "delete"`) |
| `GET /api/browse/list?conn_id=&mount=&folder=&offset=` | One folder's entries (folders first), 200 at a time, each with what the token may do (`list`, or `read`/`write`/`history`). `denied: true` when the folder can't be listed |
| `GET /api/browse/secret?conn_id=&mount=&path=&version=` | A secret's (or version's) state, key names, versions (created, deleted, destroyed), metadata and capabilities. Never values |
| `GET /api/browse/values?conn_id=&mount=&path=&version=` | The values of the current version or a given one |
| `POST /api/browse/find` | `{"conn_id", "mount", "folder", "query"}`: secrets whose path contains the text |
| `POST /api/browse/diff` | `{"conn_id", "mount", "path", "a", "b", "reveal"?}`: two versions compared key by key (`added`, `removed`, `changed`, `same`) |
| `POST /api/browse/preview` | `{"conn_id", "mount", "edits": [{"path", "action": "write" \| "delete" \| "undelete" \| "destroy" \| "rollback", "expected_version", "set"?, "remove"?, "versions"?, "rollback_to"?}], "reveal"?}`: what each edit would do |
| `POST /api/browse/apply` | The same plus `"confirm": true`. Each write is checked against `expected_version`; a moved secret is a `conflict`. 403 when `LOCKSTEP_READ_ONLY` |
| `POST /api/browse/metadata` | `{"conn_id", "mount", "path", "expected_hash"?, "max_versions"?, "cas_required"?, "delete_version_after"?, "custom_metadata"?}` changes a secret's metadata. `custom_metadata` replaces the whole set. With `expected_hash` (from `/secret`'s `metadata.hash`) it's a `conflict` if the metadata changed meanwhile. Refused when `LOCKSTEP_READ_ONLY` |
| `POST /api/browse/share` | `{"conn_id", "mount", "path", "keys"?, "version"?, "ttl": "5m" \| "15m" \| "1h" \| "24h"}` wraps the chosen values in a single-use token (`sys/wrapping/wrap`) and returns it |
| `POST /api/browse/unwrap` | `{"conn_id", "token", "open"?}` looks the token up, or with `"open": true` unwraps it (once) and returns the values |
| `GET /api/config/overview?conn_id=` | Version, cluster name, seal and storage type, HA and replication status |
| `POST /api/config/compare` | `{"left": conn_id, "right": conn_id}`: both overviews, and every secrets engine (`mounts`), auth method (`auth`) and engine role or key (`engines`, such as `transit/keys/app-key`, for engines both sides have) paired by path, with `status`, the differing `fields` (dotted names), both normalised objects, a `summary` and `missing` rights |
| `POST /api/config/copy` | `{"conn_id": source, "source": "mount"\|"auth"\|"engine", "path", "to_path"?}`: the access changes (`tunes` or `engine_objects`) that would make the other side match, plus `notes`. Nothing is written: send them to `/api/access/preview`, `/apply` or `/plans` |
| `GET /api/identity/groups?conn_id=` | Identity groups with type, policies, member entities (by name), member group count and external alias |
| `POST /api/identity/compare-groups` | `{"left": conn_id, "right": conn_id, "profile"?}`: groups paired by name (or the profile's mappings), compared field by field |
| `POST /api/access/preview` | `{"conn_id", "policies"?: [{"name", "text"}], "roles"?: [{"kind", "mount", "name", "body"}], "delete_policies"?: [...], "delete_roles"?: [{"mount", "name"}]}`: per item, `action` (`new`, `change`, `same`, `delete`), a `diff` against Vault, whether the token is `allowed`, a `hash` of what's there now, problems and warnings |
| `POST /api/access/plans` | The same body as a preview: returns a signed access plan (`format` `lockstep.access-plan`), with the changes, the target Vault, `created_by` and the hashes of what's there now. Allowed even when `LOCKSTEP_POLICY_APPLY=off` |
| `POST /api/access/plans/check` | `{"conn_ids": [...], "plan": {...}}`: verifies the signature, picks the signed-in connection to the plan's Vault (the one with the fewest denials), and previews; items changed since the plan are `conflict`. Returns `plan` (without the changes), `conn_id`, `items`. `400` edited or foreign plan, `409` not signed in to its Vault |
| `POST /api/access/plans/apply` | The same plus `"confirm": true`, with the checked `conn_id` first: applies, skipping conflicts. Guarded like `/api/access/apply` |
| `POST /api/access/apply` | The same plus `"expected": {item id: hash}` and `"confirm": true`. Items that changed since the preview are skipped as `conflict`. 403 when `LOCKSTEP_READ_ONLY` or `LOCKSTEP_POLICY_APPLY=off` |
| `GET /api/pki/mounts?conn_id=` | PKI secrets engines |
| `GET /api/pki/overview?conn_id=&mount=` | A PKI engine's issuers (subject, expiry) and roles (allowed names, TTLs, key type) |
| `POST /api/pki/issue` | `{"conn_id", "mount", "role", "common_name", "alt_names"?, "ttl"?, "store"?: {"mount", "path"}}` issues a certificate and returns it with its private key, chain and details; with `store`, also writes them to a new KV secret (`409` if it exists). Refused when `LOCKSTEP_READ_ONLY` |
| `GET /api/database/mounts?conn_id=` | Database secrets engines |
| `GET /api/database/overview?conn_id=&mount=` | Connections (inline passwords redacted), dynamic roles and static roles |
| `POST /api/database/creds` | `{"conn_id", "mount", "role"}` generates credentials: `data` (username, password), `lease_id`, `ttl`. Refused when read-only; audit-logged without the password |
| `GET /api/leases?conn_id=&prefix=` | One level of the lease tree: `folders`, `leases` (full IDs), `truncated`, `note` (when the top level was listed mount by mount); `403` without sudo |
| `POST /api/leases/lookup` | `{"conn_id", "lease_ids"}` (up to 100): issue and expire time, TTL, renewable |
| `POST /api/leases/renew` | `{"conn_id", "lease_id", "increment"?}` (seconds). Refused when read-only; audit-logged |
| `POST /api/leases/revoke` | `{"conn_id", "lease_ids"}` revoked one by one; per-lease results. Refused when read-only; audit-logged |
| `GET /api/transit/mounts?conn_id=` | Transit secrets engines |
| `GET /api/transit/keys?conn_id=&mount=` | Keys with their settings (type, versions, what they support), never key material |
| `POST /api/transit/run` | `{"conn_id", "mount", "key", "op": "encrypt" \| "decrypt" \| "rewrap" \| "sign" \| "verify" \| "hmac", "text", "signature"?, "context"?}`: plaintext as UTF-8 text (base64 to Vault) |
| `GET /api/roles/mounts?conn_id=` | Kubernetes, JWT and OIDC auth mounts (`sys/auth`, or the UI listing when that's all the token may read) |
| `GET /api/roles?conn_id=&mount=` | Every role on the mount, normalised (defaults left out, durations in seconds), with the policies a login gets and findings |
| `GET /api/roles/templates` | Starting points for new roles (Kubernetes, GitLab CI, GitHub Actions, Kubernetes through JWT, OIDC group) |
| `POST /api/roles/check` | `{"kind": "kubernetes" \| "jwt", "body", "conn_id"?}` normalises and checks a role being built (with `conn_id`, flags policies that don't exist) |
| `POST /api/roles/explain` | `{"conn_id", "mount", "role", "kv_mount", "prefix"?}`: the role's policies explained together on a KV v2 mount (the `/api/policies/explain` result) |
| `POST /api/roles/compare` | `{"left": {"conn_id", "mount"}, "right": {…}, "profile"?}`: the roles of two auth mounts compared field by field |
| `POST /api/roles/secret-id` | `{"conn_id", "mount", "role", "ttl": "5m" \| "15m" \| "1h" \| "24h", "metadata"?}`: an AppRole secret ID, wrapped in a single-use token, with the role ID. Refused when `LOCKSTEP_READ_ONLY` |
| `GET /api/roles/granting?conn_id=&policy=` | The roles, in every supported mount the token can read, that grant the policy |
| `GET /api/policies?conn_id=` | ACL policy names the token may list. 403 with a hint when it may not |
| `GET /api/policies/{name}?conn_id=` | One policy's text |
| `POST /api/policies/explain` | `{"conn_id", "mount", "prefix"?, "names"?: [...], "pasted"?: [{"name", "text"}], "token"?: "self", "identity"?: {"kind": "entity" \| "group" \| "token", "name"}}` returns what the policies allow on each secret: `columns`, `rows` (per secret, a cell per column: `ok`, `deny`, `caps`, and `rule`, an index into `rules`), `rules` (with the policy, path and line each came from), `findings`, `policies` (each with any read or parse error), `missing` (rights the token lacks), `mode` (`policies`, or `vault` when the token's own policies couldn't be read and the answers come from `sys/capabilities-self`), `denied` and `truncated`. Read-only |
| `POST /api/policies/build` | `{"mount", "name"?, "rules": [{"where", "can": ["names", "read", "write", "delete", "destroy", "history"]}]}` returns the policy's `hcl` and lint `findings` |
| `POST /api/policies/suggest` | `{"conn_id", "mount", "prefix"?, "pattern"?: YAML or JSON text}` returns the `layout`, `why`, `notes`, `suggestions` (each with `name`, `description`, `rules`, `hcl`), the pattern's policy `profile`, and `pattern_yaml` (the pattern used) |
| `POST /api/policies/bundle` | `{"policies": [{"name", "text"}], "roles"?: [{"kind", "mount", "name", "body"}], "terraform"?: {"tool": "terraform" \| "opentofu", "provider": "~> 5.0" \| "~> 4.0", "layout": "single" \| "files", "imports"}, "conn_id"?}` returns a zip: `policies/*.hcl`, `apply.sh`, `README.md`, and the Terraform or OpenTofu files. With `conn_id`, policies that already exist get `import` blocks |
| `GET /api/policies/patterns` | Shared suggestion patterns (`LOCKSTEP_POLICY_PATTERNS`), as YAML |
| `GET /api/policies/profiles` | Shared policy profiles (`LOCKSTEP_POLICY_PROFILES`) |
| `POST /api/policies/compare` | `{"left": conn_id, "right": conn_id, "profile"?: {"name", "mappings": [{"left", "right"}], "rewrites": [{"find", "replace"}], "ignore": [...]}}` compares every policy on the two Vaults by meaning. Returns `pairs` (each with `left`, `right`, `status`, `mapped`, `formatting`, `note`, `rules` with each path's capabilities on both sides, and both texts), a `summary`, each side's policy `count` or `error`, and `missing` rights |
| `POST /api/policies/compare-access` | `{"left": {"conn_id", "mount", "prefix"?, "name" \| "text"}, "right": {…}}` explains each policy on its own side's mount and joins the results by path relative to each prefix: per secret, both sides' cells and whether they `differs` |
| `POST /api/destroy` | `{"side": {"conn_id", "mount", "prefix"?}, "secrets": [{"path", "expected_version"?}], "confirm": true}` permanently deletes every version and the metadata of each secret. One that's at a different version than `expected_version` isn't destroyed (`conflict`). Returns a result per secret (`destroyed`, `absent`, `conflict`, `denied`, `error`) and a summary. 403 when `LOCKSTEP_ALLOW_DESTROY` is false |

## Sync plans

A plan is a signed JSON file (format `lockstep.sync-plan`, version 1) with no values. See [usage](usage.md#sync-plans).

| Method & path | Purpose |
|---|---|
| `POST /api/plans` | The `/api/sync/preview` body (without `reveal`) plus optional `"note"` and `"profile"`; returns the signed plan. Typed values (`set`) go into the plan as they are, and the plan says `"holds_values": true`. 409 if a change conflicts or can't be read, 400 if nothing would change |
| `POST /api/plans/verify` | `{"plan"}`: returns `{"plan"}` if the signature is valid, else 400. No Vault access |
| `POST /api/plans/report` | `{"plan"}`: the plan as Markdown |
| `POST /api/plans/check` | `{"plan","left_conn_id","right_conn_id"}`: `{"status": "ready"\|"stale"\|"denied"\|"error","message","changes"}`. 409 if a connection isn't the Vault the plan names |
| `POST /api/plans/apply` | The same body plus `"confirm": true`; like `/api/sync/apply` plus `"plan_id"`. 409, with nothing written, unless the check is `ready` |

## Value tools

| Method & path | Purpose |
|---|---|
| `POST /api/analyze` | `{"conn_id","mount","path","key","password"?,"password_key"?,"trust"?:[locators],"trust_sha256"?:[...],"system_roots"?}` returns the analysis tree |
| `POST /api/analyze/content` | The same body plus `"node_id"`; returns the raw bytes of that part of the value |

## Health

`GET /healthz` (liveness) and `GET /readyz` (readiness) return `{"status": …}`.
