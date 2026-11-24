# Vault Enterprise: namespaces and licence expiry

**Status:** proposal, blocked on a licence · **Written:** 2026-11-23 · **Owner:** unassigned

Two features are wanted for Vault Enterprise users:

- **Namespaces:** phase 7 of the [policy builder](policy-builder.md), and the namespace picker from the [gap analysis](vault-ui-gap-analysis.md).
- **Licence expiry** in the Configuration overview.

Neither can be built or tested without a running Enterprise Vault, and Enterprise Vault won't start without a licence. This document records what was tried, what already exists, and the plan for when a licence is available.

## Update, 2026-11-23: namespaces work on OpenBao

OpenBao (2.3+) has namespaces with the same API as Vault Enterprise: nested namespaces, mounts and auth methods inside them, the `X-Vault-Namespace` header, and sign-in into a namespace. So the namespace half of this proposal (**part 2**) no longer needs a licence:
- The dev and demo OpenBaos are seeded with namespaces (`team-a`, `team-a/apps`, `team-b` on A, `team-c` on B), each with users and drift.
- `tests/test_namespaces.py` (backend and browser) compares across them under `make test-openbao`: two namespaces, a namespace with its child (a root token working below), a user confined to their namespace, and the configuration of two namespaces.

Part 2 (the namespace picker and linked connections) can be built and tested against OpenBao now. A licence is still needed for **part 3** (licence expiry) and for checking Enterprise-only behaviour, such as Sentinel, replication and performance standbys.

## What's blocking it

Every Vault Enterprise build checks for a licence at start-up, **including `server -dev`**:

```
Error initializing core: license check failed: no autoloaded license provided.
```

Tried so far:

| Image | Result |
|---|---|
| `docker.io/hashicorp/vault-enterprise` (2026-11-22) | Exits on the licence check |
| A local mirror of `hashicorp/vault-enterprise` 1.19.26+ent.hsm.fips1403, arm64 only (2026-11-23) | Exits on the licence check |

**To unblock:**

1. Get a trial licence at <https://www.hashicorp.com/products/vault/trial>. It's free and lasts 30 days.
2. Put it in `.env` as `VAULT_LICENSE=…`.

The licence is never printed, committed, baked into an image, or sent to the demo.

**Which image:** the HSM/FIPS build above works for local trials. For the dev stack, prefer the standard `hashicorp/vault-enterprise` image, for three reasons:

- It's multi-arch, and CI is amd64. The dev stack pins the multi-arch index digest.
- It doesn't need an HSM library.
- Pin the same minor as `vault-a` and `vault-b` (1.21.x), so results compare like for like.

## What already works with a namespace

Lockstep already connects *into* a namespace. The namespace is fixed for the life of a connection:

- **Sign-in:** the web UI's connect form and presets take a namespace. The CLI takes `--left-namespace`, `--right-namespace`, `LOCKSTEP_<SIDE>_NAMESPACE` or `VAULT_NAMESPACE`.
- **Requests:** `VaultClient` sends `X-Vault-Namespace` on every request (`backend/src/lockstep/vault.py`).
- **Display:** a side's summary shows "namespace …". Exports and sync plans record it, and plans label the Vault with it.
- **Saved access plans:** a plan stores its namespace and only applies through a connection to the same Vault *and* namespace (`api/access.py`, `_targets`).

So every view should already work inside one namespace. None of it has been tested against Enterprise.

## Part 1: an Enterprise dev service

This part comes first; everything else is tested against it.

- **Compose service:** `vault-ent` under a new `enterprise` profile, off by default.
  - Image: `${VAULT_ENT_IMAGE:-docker.io/hashicorp/vault-enterprise:<1.21.x>-ent}`, pinned by digest.
  - `VAULT_LICENSE` from `.env`.
  - Root token `root-ent`, port 8202.
  - Without the profile, nothing changes: CI, the demo and `make up` don't need a licence.
- **Seed:** `seed_enterprise()` runs only when `vault-ent` is reachable.
  - Namespaces `team-a`, `team-a/apps` and `team-b`.
  - A KV v2 mount and a policy in each.
  - A userpass user in `team-a`, and an identity group in `team-a` whose member is an entity from the root namespace.
  - Different contents in `team-a` and `team-b`, so comparisons find something.
- **Preset:** a "Vault Ent" connection preset, added only when the profile is up.
- **Tests:**
  - A pytest marker `enterprise`, skipped with a clear reason when `vault-ent` isn't reachable.
  - Browser tests tagged the same way.
  - `make test-enterprise` runs both.
- **CI:** none to start with. A scheduled job could later use a licence stored as a GitHub Actions secret, never on pull requests (forks can't see secrets anyway), with its output checked for the licence string.

Size: S.

## Part 2: namespaces (policy builder phase 7)

### A namespace picker per side

Child namespaces come from `LIST sys/namespaces`, relative to the namespace you signed in to. A token can work in its own namespace and in those below it, by changing `X-Vault-Namespace`. It can't work in the namespaces above.

**Recommended:** **switching namespace makes a linked connection.** It's the same token with a different working namespace, and it gets its own connection id: `POST /api/connections/{id}/namespace {path}`. Each linked connection:

- shares the parent's token and expiry, and is never revoked on its own. Signing out the parent removes it too.
- shows as "alice via userpass on Vault Ent · namespace team-a/apps".

Every view already works on a connection id, so Browse, Compare, Policies, Configuration, Tools, exports, plans and the audit log all work in the chosen namespace unchanged.

The alternative was a `namespace` parameter on every endpoint. That touches all ~90 routes and every API call in the frontend, which is why the policy builder proposal said this phase "touches every view". The linked connection avoids that.

**UI:**
- A **Namespace** select under a side's connection, showing the namespace tree.
- The side summary and the compare header name the namespace.
- **Compare this namespace with…**: two sides on one cluster can be `team-a` and `team-b`. That already works once each side can pick a namespace.

### Things that change with namespaces

**Policies:**
- Policy names are per namespace.
- A policy's paths are relative to the namespace it's written in.
- A token signed in at the root, working in `team-a`, is governed by root-namespace policies whose paths must include `team-a/…`.

Explain and the matcher need a namespace prefix for each policy: compute the effective path as `<policy's namespace>/<path>`, then match. "Try for real" (`sys/capabilities-self`, already namespace-aware in Vault) is the check that this is right.

**Identity:**
- Entities and groups can live in any namespace.
- A group in `team-a` can contain an entity from the root namespace, and the group's policies then apply in `team-a` only.

Explain for an entity has to collect groups from every namespace it can read, and tag each policy with its namespace.

**Configuration:**
- Mounts, auth methods and engine roles are per namespace. Compare works per namespace.
- A new overview row compares each side's **namespace tree**: which exist on one side only.

**Access review and plans:**
- Writes go to the connection's working namespace.
- Plans already bind to it; check that a linked connection matches a plan's namespace.
- Audit entries add the namespace.

**CLI:** `--left-namespace` and `--right-namespace` already exist. Add `lockstep config compare --namespaces` to include the namespace tree.

Size: M for the picker and linked connections. M for namespace-aware Explain and identity.

## Part 3: licence expiry in the overview

The data comes from `GET sys/license/status`, read in the root namespace (Vault 1.8+ autoloaded licences). It returns:

- `autoloaded.expiration_time` and `termination_time`;
- the licence's `features`;
- `license_id`, which is never shown in full.

**Overview:** a "Licence" row per side, giving the expiry date and days left.
- It turns into a warning under 30 days and an error once expired.
- It shows the differences when the two sides' expiry dates or features differ.
- Not shown at all for Vault Community. "Can't read" if the token lacks `read` on `sys/license/status`.

**Edition badge:** the version string `1.21.4+ent` is shown as an "Enterprise" badge in the overview. HSM and FIPS builds are named too.

**CLI:** `lockstep config compare` includes the licence row, so CI can warn before a licence runs out.

**Optional:** a line on the **Certificate expiry** dashboard: "Vault licence expires in N days", because people already look there for expiry.

Size: S.

## What can be done before a licence

The parsing and display can be built with unit tests on recorded responses:
- the licence status;
- the `LIST sys/namespaces` tree;
- the linked-connection logic, against a stubbed Vault.

That's worth doing only if a licence is coming soon. Without a real Enterprise Vault the details (permissions, the shape of responses across versions, how identity crosses namespaces) are guesses. **Recommendation:** wait for the licence, then do parts 1 → 3 → 2. Part 3 is small and shows the service works; part 2 is the larger piece.

## Open questions

- Is a 30-day trial enough? Development is quick, but the browser tests need the licence every time they run. A longer development licence would be needed to keep the `enterprise` tests running.
- Should the public demo ever show Enterprise? Probably not, since it would need a licence on the demo server. Screenshots from the dev stack are enough.
- Sentinel policies (EGP/RGP): show them read-only next to ACL policies? Out of scope for now, but they live in the same namespaces.
