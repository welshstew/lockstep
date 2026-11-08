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
| `POST /api/connections` | Add one: `{"preset_id": 0 \| "url": "…", "namespace"?, "auth": {...}}`, where `auth` is `{"method":"token","token"}`, `{"method":"userpass"\|"ldap","username","password","mount"?}` or `{"method":"kubernetes","role","mount"?}` |
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
| `POST /api/compare` | `{"left": {"conn_id","mount","prefix"?}, "right": {…}, "rules"?: {mappings, ignore_keys, ignore_paths}}` returns a status per secret and key (`ignored` flags, each side's `left_path`/`right_path`), versions, timestamps and value-type badges. **No values** |
| `GET /api/profiles` | Shared comparison profiles configured on the server |
| `GET /api/connections/{id}/secret?mount=&path=` | One secret's values (what *Show values* uses) |
| `GET /api/connections/{id}/history?mount=&path=` | For each key, the version and time it last changed. No values |

## Certificate expiry

| Method & path | Purpose |
|---|---|
| `POST /api/expiry` | `{"sides": [{"side": "left"\|"right", "conn_id", "mount", "prefix"?}]}` returns every certificate found (subject, issuer, dates, status, where; never values), keystores that couldn't be fully checked, and per-side scan stats |

## Copying

| Method & path | Purpose |
|---|---|
| `POST /api/sync/preview` | `{"left","right","changes":[{"path","right_path"?,"direction":"left_to_right"\|"right_to_left","keys": [...]\|null,"expected_target_version","expected_source_version"}],"reveal"?}` returns a plan per secret |
| `POST /api/sync/apply` | The same body plus `"confirm": true`; returns a result per secret and a summary |

## Value tools

| Method & path | Purpose |
|---|---|
| `POST /api/analyze` | `{"conn_id","mount","path","key","password"?,"password_key"?,"trust"?:[locators],"trust_sha256"?:[...],"system_roots"?}` returns the analysis tree |
| `POST /api/analyze/content` | The same body plus `"node_id"`; returns the raw bytes of that part of the value |

## Health

`GET /healthz` (liveness) and `GET /readyz` (readiness) return `{"status": …}`.
