# Proposal: validating connection details ("connection probes")

**Status:** idea, not scheduled · **Written:** 2026-11-10 · **Owner:** unassigned

Vault often holds the details for logging in to other services: databases, LDAP directories, HTTP services behind basic auth or tokens, message brokers. Lockstep can show that two environments hold the *same* values. It can't show that those values still *work*. This proposal adds an optional **Validate** action. It takes credentials from Vault, tries one read-only login against the service they belong to, and reports how far it got. Values are never shown.

It's written to be revisited later: the design, the choices still open, and the pros and cons.

---

## 1. Goals and non-goals

**Goals**
- Check that a set of connection details stored in Vault can log in to the service it describes. If it can't, say why: DNS, network, TLS, credentials or permissions.
- Work for the common service types, with TLS material (CA certificates, client certificates, keystores) also taken from Vault.
- Fit how Lockstep already works: values stay on the server, every action is audit-logged, and the feature is off unless an admin turns it on.
- Be most useful where Lockstep is strongest: comparing sides ("left credentials work, right credentials fail") and checking after a copy, import or sync plan.

**Non-goals**
- Monitoring or uptime checks. Checks only run when someone asks for them.
- Changing anything on the target service: no writes, no schema checks, no password rotation.
- Replacing Vault's dynamic secrets or its database secrets engine. This is for static credentials kept in KV.

---

## 2. How it would work

### 2.1 The admin turns it on and defines probe types

The feature is **off by default**. When it's on, the admin defines **probe types**: which kinds of service users may check, and where those services may be:

```yaml
# Helm values (LOCKSTEP_PROBES as JSON with snake_case keys)
probes:
  enabled: true
  runner: inline                 # inline | agent (see section 4)
  timeoutSeconds: 10
  types:
    - name: PostgreSQL
      kind: postgres             # built-in implementation
      allow: ["*.db.internal:5432", "10.20.0.0/16"]      # hosts / CIDRs (and ports) checks may reach
      check: "SELECT 1"
    - name: Corporate LDAP
      kind: ldap
      allow: ["ldap.corp.example.com:636"]
      tls: required
    - name: Internal HTTP APIs
      kind: http
      allow: ["*.svc.internal"]
      method: GET
      expect: [200, 204]         # status codes that count as "logged in"
```

The admin decides **which kinds** are available and **which hosts** can be reached. Without an `allow` list, a probe type can't run (see section 5.2).

### 2.2 The user maps references to credential fields

Each probe type has a fixed set of **fields**. For each one, the user picks where its value comes from: a **reference** to a key in Vault, a typed literal (not for secret fields), or a default.

| Field | Example reference | Notes |
|---|---|---|
| `host` | `app-config/services/billing/prod/db` → `host` | or parsed from a URL/JDBC string key |
| `port` | `… → port` | literal `5432` allowed |
| `username` | `… → username` | |
| `password` | `… → password` | secret field: must be a reference, never typed |
| `database` | `… → dbname` | type-specific |
| `tls.mode` | literal `verify-full` | `disable` / `require` / `verify-ca` / `verify-full` |
| `tls.ca` | `certs/ca/root` → `ca.crt` | PEM, DER or base64, decoded with the existing value tools |
| `tls.client_cert`, `tls.client_key` | `certs/clients/billing` → `tls.crt`, `tls.key` | PEM |
| `tls.keystore` | `certs/some-secrets/files/certs.p12` → `certs.p12` | PKCS#12, JKS or JCEKS, read by the existing inspector code |
| `tls.keystore_password` | `certs/some-secrets/strings/KEYSTORE_PASSWORD` → `value` | the **password finder** can suggest it, as it does in the inspector |

A saved set of mappings is a **probe binding**. Bindings live in comparison profiles, so they can be shared like profiles today (personal in the browser, or shared from the server). They're also usable from the CLI.

```yaml
bindings:
  - name: Billing DB
    type: PostgreSQL
    path: "services/*/{env}/db"          # one binding, matched on both sides
    fields:
      host: {key: host}
      port: {key: port}
      username: {key: username}
      password: {key: password}
      database: {literal: billing}
      tls.mode: {literal: verify-full}
      tls.ca: {ref: "certs/ca/root", key: "ca.crt"}
```

**Suggesting bindings.** Lockstep can propose a binding from how a secret looks: `jdbc:`/`postgres://`/`ldaps://` values, key names such as `host`, `port`, `bind_dn` and `password`, and nearby keystores. It ranks guesses the way the password finder does. A suggestion is only a starting point: the user confirms it, because a wrong guess sends credentials to the wrong place.

### 2.3 Running a check

- **Where:** a **Validate** button on an expanded secret that has a binding, for one side or both. Also an optional **Validate after writing** in the review dialog, and the import preview.
- **What happens:** one connection attempt and one login, plus at most one harmless read (`SELECT 1`, LDAP "who am I", one HTTP request). No retries.
- **What you get back** (never values):

| Stage | Result |
|---|---|
| Resolve | DNS name not found |
| Connect | Refused / timed out / blocked by `allow` |
| TLS | Handshake failed; certificate untrusted, expired or for the wrong name (with certificate details, as in the inspector) |
| Authenticate | Credentials rejected |
| Authorise | Logged in, but the check query or request was refused |
| OK | Logged in; took *n* ms; server version if the protocol reports it |

- **Comparing sides:** for two sides, the results sit next to each other, like comparison statuses, so you can see at a glance where one side works and the other doesn't.
- **CLI:**
  - `lockstep probe --profile p.yaml --left-… --right-…` checks every bound secret;
  - `lockstep compare --probe` adds the results to the report;
  - exit codes follow `compare`, so it can be a CI gate.

---

## 3. Service types to start with

| Kind | Python library | Login check | TLS material |
|---|---|---|---|
| `postgres` | `asyncpg` or `psycopg` | `SELECT 1` | CA, client cert/key |
| `mysql` (MariaDB) | `aiomysql` / `PyMySQL` | `SELECT 1` | CA, client cert/key |
| `mssql` | `pymssql` / `pytds` (pure Python) | `SELECT 1` | CA |
| `ldap` (incl. AD) | `ldap3` (pure Python) | simple bind, then "who am I" | CA, client cert |
| `http` | `httpx` (already a dependency) | one request with Basic, Bearer or header auth; status against `expect` | CA, client cert/key |
| `redis` | `redis` | `AUTH`, then `PING` | CA, client cert/key |
| `amqp` | `aio-pika` | open and close a connection | CA, client cert/key |
| `smtp` | `smtplib` (standard library) | `EHLO`, `STARTTLS`, `AUTH` | CA |
| `tcp` / `tls` | standard library | connect only, or a TLS handshake (no credentials) | CA |

Oracle, Kafka (SASL) and JDBC-only drivers would need heavy native clients. They are the main reason to consider separate probe workers (section 4).

Keystores turn into what the client libraries need, an `ssl.SSLContext`, using the existing value-tools code (PKCS#12/JKS/JCEKS decoding, chain building). Decoded material stays in memory for that one check only.

---

## 4. Where the check runs

This is the main design decision, because **network reach** matters more than code: the Lockstep pod usually can't reach every environment's databases.

| Option | How | Pros | Cons |
|---|---|---|---|
| **A. Inside Lockstep (inline)** | The server runs the check itself | Simplest; no new parts; fast; values are already there | Only reaches what the Lockstep pod reaches; NetworkPolicy has to be opened; drivers make the image bigger |
| **B. A short-lived Kubernetes Job per check** | Lockstep creates a pod in a chosen namespace and collects the result | Can run inside the target's network; drivers isolated in their own image | Lockstep needs permission to create pods (a big privilege); a few seconds' start-up per check; the secret has to reach the pod (pod spec or Kubernetes Secret, so etcd) unless the pod reads Vault itself; cleanup and quotas |
| **C. Probe agents (pull model)** | A small long-running worker in each network zone. Lockstep sends it a reference (path, key and binding); the agent reads Vault with **its own** identity (Kubernetes or JWT auth) and returns only the result | Reaches segmented networks; values never pass through Lockstep or Kubernetes objects; each agent's Vault policy limits what it can check; drivers can live in the agent image | A new component to deploy, version and secure; needs agent registration and authentication to Lockstep; results are asynchronous |

**Recommendation:** build **A** first. Design the check request from the start around **references, not values**: binding plus path plus side, and Lockstep resolves the values. Running the same request on an agent (**C**) then becomes a deployment option rather than a rewrite. Consider **B** only if there's a concrete need for isolated native drivers, and even then let the pod read Vault itself.

---

## 5. Security and safety

### 5.1 Lockouts and noise
- Failed logins count against lockout policies, especially in Active Directory: one wrong password in a check could lock a service account used in production. So:
  - **one attempt**, with **no retries**;
  - **no bulk runs by default:** checking a whole mount needs the admin to allow it (`bulk: true` per type) and runs one check at a time;
  - **a rate limit per target and per user** (for example one check per binding per minute).
- Checks appear in the target service's own logs and could trigger its alerts. The UI should say so the first time.

### 5.2 SSRF: Lockstep as a network scanner
- Anyone who can write a secret could make Lockstep connect anywhere it can reach. The admin's **allow list** (hosts, wildcards, CIDRs, ports) is therefore **required** for every probe type.
- **Checked after resolving names**, so a DNS name can't point at an internal address.
- **No redirects** for HTTP probes, or only redirects within the allow list.
- Link-local and metadata addresses (`169.254.0.0/16`, `fd00:ec2::254`) are **always blocked**.
- Errors say *which stage* failed, but not raw server banners or response bodies, so a check can't be used to read internal services.

### 5.3 Who may run a check
- A successful login proves the password, which reveals about as much as showing it. Running a check therefore needs the same Vault access as reading the referenced keys, done with the **user's own token** (inline) or the agent's narrow policy (agents).
- **Optional:** an admin setting limiting checks to some users or groups (`LOCKSTEP_PROBE_ALLOWED_GROUPS`), if Vault identity groups can be read.

### 5.4 Values
- Values are resolved on the server, used once, and dropped.
- They never appear in responses, logs, CLI reports or audit lines.
- **Audit:** each check is logged as `"event": "probe"`: who, which binding, which references, the target host, and the stage reached.

### 5.5 Configuration
- `LOCKSTEP_PROBES_ENABLED=false` by default.
- The Helm chart adds the matching NetworkPolicy egress rules only for the allowed targets.
- `/api/config` tells the UI which probe types exist, so the button is hidden when the feature is off.

---

## 6. Pros and cons

**For**
- Finds a class of problem comparisons can't: matching values that are both wrong, expired passwords, rotated certificates, firewall changes.
- Fits sync and import: after you copy or import, check the target actually works.
- Reuses what Lockstep already has: the value tools for keystores and chains, the password finder for keystore passwords, profiles for sharing bindings, the audit log, the CLI exit codes for CI.
- Off by default and limited by admin settings, so it adds no risk to installs that don't use it.

**Against**
- **Security surface:** the first feature where Lockstep connects to anything other than Vault. SSRF, lockouts and "logged in successfully" as an oracle all need care, and mistakes would be serious.
- **Network reach:** inline checks only help where the Lockstep pod can reach the services. Real coverage likely needs agents, which means a second component to build and run.
- **Drivers:** each service type adds dependencies, image size and CVE-scanning noise to a deliberately small, distroless image. That may push towards optional extras or a separate probe image.
- **Scope creep:** users will ask for scheduled checks, alerting and history. That is monitoring, which other tools already do. Keep this on-demand and say so.
- **Bindings take effort:** mapping fields for many secrets is work. Without good suggestions and wildcard bindings (`services/*/{env}/db`), few people will set them up.

---

## 7. Possible phases

1. **Foundations:** the probe framework, admin config and allow list, the binding format in profiles, and inline running. Types: `tcp`/`tls`, `http`, `postgres`. The **Validate** button for one side. Audit, rate limits.
2. **More types and TLS from Vault:** `mysql`, `mssql`, `ldap`, `redis`. Keystores and client certificates from references, keystore passwords suggested by the password finder. Both sides next to each other, and **Validate after writing**.
3. **CLI and CI:** `lockstep probe`, `compare --probe`, schema for bindings, exit codes.
4. **Agents (only if needed):** the agent image, registration and authentication, routing a check to the agent for that network zone, agent-side Vault login.

## 8. How to test it

- Add throwaway services to the dev compose stack, seeded with matching secrets in Vault A and Vault B. One side gets wrong credentials and a certificate for the wrong host on purpose:
  - PostgreSQL with TLS and a client certificate;
  - OpenLDAP;
  - an HTTP server with basic auth;
  - Redis.
- Browser tests: map a binding, check both sides, and see one pass and one fail at the right stage.
- Security tests:
  - targets outside the allow list are refused, including after DNS resolution;
  - redirects are refused;
  - metadata addresses are blocked;
  - rate limits hold;
  - no value appears in responses, logs or audit lines.

## 9. Open questions

- Should bindings live in profiles, or in their own "connections" list? Profiles are already shared and versioned in the same way, but they're about comparing.
- Wildcard bindings for both sides: is `{env}` substitution enough, or do mappings need their own field overrides per side?
- Should a successful check be able to report more (server version, granted roles)? Useful for diagnosing, but more for an attacker to learn.
- With agents, how does Lockstep authenticate them (mTLS, Vault-issued tokens, Kubernetes service account tokens)? Who can register one?
- Licensing and size of the database drivers in the distroless image: optional extras, or a separate `lockstep-probes` image?
