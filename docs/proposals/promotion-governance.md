# Proposal: promotion and governance

**Status:** implemented (phases 1–5 2026-11-26, phase 6 2026-11-27); decisions made (§8) · **Written:** 2026-11-25 · **Decided:** 2026-11-25 · **Owner:** unassigned

Sync plans let one person prepare a change and another apply it: "a read-only user makes a plan, a production admin applies it". Today that works within a single Lockstep. A plan is signed with a key derived from `LOCKSTEP_SESSION_KEY`, so:
- another installation can't verify it;
- rotating the session key invalidates every outstanding plan;
- the signer is recorded only by Vault display name, which a token can choose.

Writes can't be limited per Vault either: `LOCKSTEP_READ_ONLY` is all or nothing. This proposal makes promotion work across installations, with identities that can be audited.

---

## 1. Goals and non-goals

**Goals**
- A plan made on a dev Lockstep can be verified and applied on a prod Lockstep.
- Who made, approved and applied a plan is recorded with identifiers that can't be chosen freely.
- Admins can say "compare prod, write dev" without making all of Lockstep read-only.
- A partial or wrong apply can be undone without Lockstep ever storing old values.

**Non-goals**
- Lockstep becoming a workflow engine with queues and notifications. Plans stay files; where they travel (a ticket, a PR, chat) is up to the team.
- Replacing Vault's own policies. Every write still uses the applier's token.

---

## 2. Plan signatures that travel

- **Ed25519 signing.** `LOCKSTEP_PLAN_SIGNING_KEY` holds the private key on installations that create plans. `LOCKSTEP_PLAN_TRUSTED_KEYS` lists public keys, each with a name, on installations that apply them. The session key stops having anything to do with plans.
- **Backwards compatibility:** with no signing key set, today's HMAC scheme continues, so single installations change nothing.
- **New plan fields:**
  - `issuer`: the installation's name and key ID;
  - `audience`: which installations may apply it, optional;
  - `not_before` and `expires_at`, default 7 days;
  - `format: 2`.
- **Identity:** record the creator's Vault **entity ID** and **token accessor**, as well as the display name. Both come from `lookup-self`, so they can be checked against Vault's own audit log.

## 3. Four-eyes approval (optional, lightweight)

Decided: four-eyes is a **convenience, not a compliance control** (§8.1). Its job is catching mistakes before they reach production, and the design stays light to match.

- **Off by default.** `LOCKSTEP_PLAN_APPROVALS=1` turns it on for the installation that applies plans. A preset can ask for it on its own: `"approvals": 1` on Prod only.
- **Approving:** someone opens the plan, runs **Check plan** against the live Vaults, and chooses **Approve**. Lockstep adds an approval to the file: the approver's entity ID, display name and time, signed with the installation's plan key (§2). The plan's content signature is unchanged, so an approval can't alter what the plan does.
- **Applying:** refused until there are enough approvals from identities **other than the creator**, compared by Vault **entity ID**, not display name. The applier may be the approver.
- **Not included:** named approver groups, several approvers, or records built to be impossible to deny later. If four-eyes ever becomes a compliance requirement, those go on top: approver groups resolved through Vault's identity API at apply time, and the plan file kept as the record.

## 4. Per-preset write policy

Add these fields to each preset:

```json
{"name": "Prod", "url": "…", "writable": false, "allow_destroy": false,
 "write_paths": ["kv/apps/**"], "deny_paths": ["kv/apps/*/break-glass/**"]}
```

- The API refuses writes, destroys and policy applies outside these rules, on top of Vault's own policies.
- The UI hides write actions for the side.
- The audit log records refusals.

`LOCKSTEP_READ_ONLY` stays as the global switch.

**Per-group access to presets,** so not every user sees every Vault, comes after this. It needs OIDC group claims mapped to presets, and fits once identities are first-class (§2).

## 5. Applying safely

- **Strict sources** (also [trust fixes](trust-fixes.md) 8): a source that moved between check and write is a conflict.
- **Stop on error:** on by default for plans. The outcome **partially applied** lists what was written.
- **Step-up before destroy and plan apply:** optional (`LOCKSTEP_STEP_UP=on`). If the token is older than *n* minutes, Lockstep asks the user to sign in to that Vault again, with the same method and the same entity, and uses the fresh token for the write. This is separate from Vault's login MFA, though Vault applies that MFA again if it's set up.
- **Undo:** after an apply, Lockstep offers **Make an undo plan**. It records the target versions that were overwritten, and builds a plan that writes each target's *previous* version back, read from Vault's KV history when it runs. Old values are never stored. Undo fails cleanly when a version has since been destroyed, or when the target moved on.

## 6. Values typed into a plan

Values typed into a plan (overrides) are stored as plain text today, with the user's consent. Two options:
- **(a)** Encrypt them to the applying installation's public key, an X25519 key next to the signing key.
- **(b)** Ask for them again at apply time.

I'd do **(b)** first, because it's simpler and nothing secret sits in a file. Then (a) if teams ask for it.

## 7. Exports

- **Default `LOCKSTEP_EXPORT_MODE` to `encrypted`**, with plain exports as an opt-in.
- **Passphrase encryption** as well as the one-time key: Argon2id, then the same AES-256-GCM.
- **age recipients:** encrypt to a team's age public keys, so no key has to be passed around.
- **Per-preset export policy:** for example, Prod exports must be encrypted.
- **Import `vault kv get -format=json` dumps** to make migrations easier.
- **Streaming** for big exports. Today an export is built in memory.

---

## 7a. Phases

1. Per-preset write policy (§4). It stands alone, has a big effect and is small. **Done:** `writable`, `allow_destroy`, `write_paths` and `deny_paths` on presets ([write policy per Vault](../configuration.md#write-policy-per-vault)). Paths are KV `mount/path` or the API path for other writes. The rules also apply to a typed-in address or a namespace opened from a preset. Per-group access to presets waits for §2.
2. Stop-on-error and the partial-apply outcome (§5); asking again for typed values (§6b). **Done:** stop-on-error and *partially applied* came with the trust fixes (strict sources). Typed values are now typed again at apply: the plan keeps an HMAC check code per typed key, keyed with the server's secret, so a mistyped value is refused and nothing secret is in the file. Phase 3 has to keep this working across installations: the check codes need a key both installations share, or (a) instead.
3. Ed25519 signing, expiry, entity IDs (§2). **Done:** `lockstep/plansign.py` for sync and access plans; `LOCKSTEP_PLAN_SIGNING_KEY`, `LOCKSTEP_PLAN_TRUSTED_KEYS`, `LOCKSTEP_PLAN_ISSUER`, `LOCKSTEP_PLAN_TTL_HOURS`; version 2 plans with `issuer`, `audience`, `not_before`, `expires_at`; the creator's entity ID and accessor in plans and in every audit event. `format: 2` is the existing `version` field. Typed values on a plan from another installation are typed twice, because their check codes need the issuing installation's key.
4. Undo plans (§5). **Done:** `POST /api/undo` from apply results, checked and applied in Sync plans (`/api/undo/check`, `/apply`). Restore, delete (the apply created it) and undelete (the apply soft-deleted it). Signed like plans, all-or-nothing check, stop at the first failure. Browse edits and imports don't offer it yet.
5. Approvals (§3), in the shape decided in §8.1. **Done:** `LOCKSTEP_PLAN_APPROVALS` and a preset's `approvals`; **Approve** in Sync plans adds a signed approval outside the plan's signature; entities compared per Vault the plan writes. A preset with `approvals` also refuses direct secret writes, so plans are the only way in. Access plans and undo plans don't take approvals yet.
6. The export additions (§7), each separate.
   - **Done:** `LOCKSTEP_EXPORT_MODE` defaults to `encrypted` (chart `exportMode` too; the demo keeps `any`), and a preset's `export` (`any`, `encrypted`, `off`) replaces it for that Vault. A typed-in address of several presets gets the strictest. The dev setup allows plain exports from Vault A only.
   - **Done:** passphrase (Argon2id 64 MiB/3/4, cost capped at 256 MiB when opening) and age recipients (`pyrage`; the ciphertext is an armored age file, so `age -d` opens it; the header is checked against the contents). `LOCKSTEP_EXPORT_RECIPIENTS` names teams. Export version 2 for the new schemes; one-time-key files stay version 1. Admins can't yet require one scheme over another.
   - **Done:** `vault kv get -format=json` output read as an export (`lockstep/kvdump.py`, `POST /api/exports/from-kv-get`, `lockstep import FILE|FOLDER`): one file, a folder, or a path: output object.
   - **Done:** streaming. `exports.stream` writes the document as secrets are read (64 at a time, in path order); `POST /api/exports/stream` (NDJSON) streams a plain export into its result line and holds an encrypted one only as compressed bytes (age reads them decompressed as it goes). AES-GCM's authenticated header holds the secret count, so an encrypted file can't be sent before reading ends. The CLI writes plain exports straight to a temporary file. 20,000 secrets (23 MB): about 98 MB at peak before, 2 MB encrypted and 1.5 MB plain after.

## 8. Decisions (2026-11-25)

1. **Four-eyes is a convenience,** not a compliance requirement: one optional approval from another identity (§3).
2. **Plans cross installations:** yes, with Ed25519 signing (§2). Single installations without a signing key keep working as today.
3. **Exports default to encrypted:** yes (§7). `LOCKSTEP_EXPORT_MODE` defaults to `encrypted`, and plain exports need `any`. This is a breaking change, so it ships in a minor release with a CHANGELOG note. The Helm chart's `exportMode` default changes with it, and the demo keeps `any`, so visitors can still see a plain export.
