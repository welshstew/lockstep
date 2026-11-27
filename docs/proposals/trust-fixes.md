# Proposal: correctness and trust fixes

**Status:** implemented, 2026-11-25 · **Written:** 2026-11-25

| # | Fix | Pull request |
|---|---|---|
| 1 | Policy explainer follows OpenBao's own rules | #117 |
| 2 | Configuration: secret fields named, settings that only sound secret compared, real `false` kept | #119 |
| 3 | Standby redirects, `LIST` fallback, read retries, configurable timeout | #121 |
| 4 | Custom addresses: origin checked, private addresses refused, checked address pinned (**breaking**: off by default) | #122 |
| 5 | Browser security headers from the app; `LOCKSTEP_API_DOCS` | #123 |
| 6 | Sign-in throttling | #124 |
| 7 | `secret.reveal` audit event (`LOCKSTEP_AUDIT_REVEALS`) | #125 |
| 8 | Plans: a moved source is a conflict at write time; stop at the first failed write | #120 |
| 9 | Read both sides reads each secret once | #126 |

Not done from the fix descriptions: a real HA standby in the dev stack for 3 (optional; the redirect handling is tested with a mock transport), and remembering the `LIST` fallback across requests (it's per request).

Lockstep's value rests on two promises: **equal means equal**, and **nothing is written that you didn't review**. An outside review of 0.10.1 found places where those promises are weaker than they should be. Each finding below has been checked against the code. These are small, separate changes, each with a regression test. They should come before the larger features in [meaning-aware comparison](meaning-aware-compare.md), [promotion governance](promotion-governance.md) and [continuous drift](continuous-drift.md).

Ordered by how much trust each one protects, against its size.

---

## 1. The policy explainer on OpenBao

**Problem.** `behaviour_for()` in `policy/acl.py` picks a set of evaluation rules from the version number alone. OpenBao 2.7.3 therefore gets "Vault 2.2.2 or later". Run against a real OpenBao 2.7.3, the existing differential check (random policies, compared with `sys/capabilities`) **disagrees with both of Lockstep's rule sets**. OpenBao ranks `+` and `*` rules differently around trailing slashes. Today the differential tests run only against Vault A.

Enforcement isn't affected (Vault or OpenBao still decides), and the **Vault** matrix mode, which asks `sys/capabilities-self`, is always right. But the explainer, the policy builder's checks and policy comparison can say *allowed* where OpenBao says *denied*, or the reverse.

**Fix.**
1. Detect the product, not just the version. OpenBao's built-in plugins report versions ending in `.bao` (the test helper `is_openbao_b()` already relies on this), and `sys/seal-status` gives the build. Pass `(product, version)` to `behaviour_for`.
2. Add an `OPENBAO` behaviour, derived from OpenBao's own ACL code and pinned by the differential test against OpenBao.
3. Run the differential tests against **every** Vault in the compose stack: Vault A, Vault B (OpenBao under `make test-openbao`) and the latest Vault. Run them in the weekly OpenBao workflow too, so a change in OpenBao's matching fails CI.
4. When the product or version is unknown, the UI says **"evaluation rules unknown: check with the Vault matrix"** instead of assuming the newest Vault.

**Size:** medium (most of it is reading OpenBao's ACL code). **Test:** the existing `_check_against` against OpenBao, with both seeds.

## 2. Configuration comparison: stop dropping fields that aren't secret

**Problem.** `SENSITIVE` in `api/vaultconfig.py` is a regex matched against every field name (`secret|password|private|credential|…`). Every match is dropped, so `password_policy` on database and LDAP roles and GCP's `secret_type` are never compared. `_clean()` also drops `false` and `0`, so a field one side reports as `false` and the other doesn't report at all compares equal.

**Fix.**
- Replace the regex with an **explicit list of sensitive fields per engine and auth method**: `password`, `bindpass`, `token_reviewer_jwt`, `client_key`, `private_key`, `secret_key`, `credentials` and so on, each named.
- Keep the regex only as a safety net for **unknown** engines, and report what it hides.
- Report sensitive fields as **not compared: sensitive** instead of leaving them out, so a reader can see they exist.
- Drop only values that are known defaults for that field. Keep a real `false`.

**Size:** small to medium. **Test:** Vault and OpenBao fixtures proving that `password_policy`, `secret_type`, `secret_id_bound_cidrs` and a `false` flag are compared, while `password` and `bindpass` never leave the server.

## 3. Redirects from HA standbys, and proxies that block LIST

**Problem.** `VaultClient` doesn't follow redirects, and `request()` treats any status below 400 as success. A standby answering `307` comes back as `{}`, and the caller fails with a server error instead of a clear message. Lockstep uses the `LIST` verb in 12 places (KV trees, policies, roles, leases, transit keys), and some proxies and WAFs block it. There are no retries, and every call has the same 15-second timeout.

**Fix.**
- Treat `3xx` from Vault explicitly. Follow `307`/`308` only to the **same host or an address allowed for this connection** (see 4), at most twice. Otherwise raise a clear `VaultError`: "Vault redirected to *host*: point Lockstep at the active node or the load balancer."
- Fall back from `LIST` to `GET …?list=true` on `405`, or on a proxy-style `403` with no Vault error body. Remember the result per connection.
- Retry idempotent reads with a short backoff on connection errors, `429`, `502`, `503` and `504`, two attempts at most. Never retry writes. Check-and-set already makes a write safe to repeat by hand.
- Make the timeout configurable: `LOCKSTEP_VAULT_TIMEOUT_SECONDS`, and per preset.

**Size:** small. **Test:** an httpx mock transport for 307, 405-on-LIST and 503-then-200; the real standby case in the dev stack is optional.

## 4. Custom Vault addresses: validate the origin, not the string

**Problem.** `LOCKSTEP_CUSTOM_URL_PATTERNS` is matched against the raw URL. The documented example pattern is safe, but a loose pattern (one ending in `.*`) also accepts addresses whose real host is elsewhere. Nothing checks which address the name resolves to, and the app's default allows custom addresses (the Helm chart's default doesn't).

**Fix.**
- Parse and **normalise** to `scheme://host:port`. Reject userinfo, query, fragment and any path other than `/`. Match the patterns against the normalised origin.
- Resolve the host and refuse loopback, link-local (including `169.254.169.254`), and private or unique-local ranges, unless `LOCKSTEP_CUSTOM_ALLOW_PRIVATE=true`. Connect to the address that was checked, so a DNS answer can't change between the check and the connection.
- Apply the same check to redirects (3).
- Default `LOCKSTEP_ALLOW_CUSTOM_CONNECTIONS` to `false` to match the chart. This is a breaking change for `docker run` users, so it goes in a minor release with a CHANGELOG note.

**Size:** small. **Test:** a table of URLs, with userinfo, IPv6, decimal-encoded IPs, private ranges and redirects.

## 5. Browser hardening in the app itself

**Problem.** The demo gets CSP, HSTS, `frame-ancestors`, `nosniff` and `Referrer-Policy` from its Caddy proxy. A Helm or `docker run` install gets none. `/api/docs` (Swagger UI) is always on.

**Fix.**
- Have the app send these headers itself, with the same values as the demo's Caddyfile. The SPA is self-contained, so `script-src 'self'` works.
- Send HSTS only when `LOCKSTEP_PUBLIC_URL` is `https`.
- Add `LOCKSTEP_API_DOCS` (default `on`; the chart and the demo can turn it off).

**Size:** small. **Test:** header assertions on `/`, `/api/config` and a static asset.

## 6. Sign-in throttling

**Problem.** Sign-ins are limited only by the general per-client limit, which is off by default. A Lockstep that accepts custom addresses, or sits in front of a Vault whose own rate limits key on Lockstep's address, can be used to guess passwords.

**Fix.** A separate, always-on limit for `POST /api/connections`, `/mfa` and `/api/auth/oidc/start`, per client address **and** per username: for example 10 failures in 5 minutes, then `429`. Same in-memory token bucket as #112. Log a warning line (see the server log, #115).

**Size:** small.

## 7. Audit when values are revealed

**Problem.** Writes, exports, credentials, share and destroy are audit-logged. Showing a value isn't: Browse's **Show**, **Inspect**, or a comparison with values revealed. A security team will ask who looked at a production secret.

**Fix.** An optional `secret.reveal` audit event (`LOCKSTEP_AUDIT_REVEALS=on`, default off): actor, Vault, mount, path, key names, request ID. Never values. One event per request, not per key.

**Size:** small.

## 8. Plans: strict at write time, honest about partial applies

**Problem.** A plan's check refuses a plan whose source has moved, but between that check and each write, `evaluate()` only warns. A network error halfway through leaves earlier writes in place. `docs/cli.md` says a plan "is all or nothing", but that's only true of the check.

**Fix.**
- For plan applies, a moved source is a **conflict** for that change, like a moved target.
- Stop at the first failed write, and report the outcome as **partially applied: N of M written**, listing the writes that happened.
- Fix the wording in cli.md.

Rollback is in [promotion governance](promotion-governance.md).

**Size:** small.

## 9. Read both sides: compare once, not three times

**Problem.** `POST /api/compare/suggest` runs a full comparison up to three times, each one reading every value on both sides. On a 5,000-secret mount, that's a lot of load on Vault.

**Fix.** Read values once into a per-request cache keyed by `(side, path, version)`, and run the later passes from memory. The "after" summary only needs the rules applied to data already read.

**Size:** small. **Test:** count Vault reads with a mock transport: at most one per secret per side.

---

## Order

1, 2 and 8 protect what an answer *means*. 3 and 4 are the fixes most likely to bite a real install, and 5, 6 and 7 are hygiene a security review will ask for. 9 is free load reduction.

Each item ships separately, with its test and a CHANGELOG line. Only the default change in 4 is breaking.
