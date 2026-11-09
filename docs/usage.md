<!-- description: How to use Lockstep: compare two Vault KV v2 locations, read the statuses, use profiles, copy values safely, sync plans, value tools and certificate expiry. -->
# Using the tool

## 1. Choose what to compare

Each side (left in blue, right in orange) needs:

- **a connection:** a Vault and a sign-in. See [authentication](authentication.md).
- **a KV v2 secrets engine.** Mounts are listed from `sys/mounts`. If the token can't read that, the list comes from what the token can access, and you're told it may be incomplete. You can always type a mount path, which is checked before use. KV v1 mounts are not offered.
- **an optional path prefix.** Paths are compared relative to each side's prefix, so `app-config/payments` can be compared with `app-config-staging/payments`.

Both sides can be the same Vault with different mounts or prefixes. ⇄ swaps the sides.

## 2. Read the comparison

Press **Compare**. The server lists both trees, reads every secret on both sides, compares them, and returns **only statuses**: no values. They're dropped as soon as each secret has been compared.

| Status | Meaning |
|---|---|
| **Equal** | Same keys, same values |
| **Different** | At least one key differs, or exists on one side only |
| **Left only / Right only** | The secret exists on one side only (a soft-deleted latest version counts as absent, shown as *deleted*) |
| **No access** | One side can't list or read it. Its keys show as *unknown*, never as "only on the other side", so nobody copies over data they couldn't see |
| **Error** | Vault returned something else; the message is shown |

What counts as a difference:

- Only **values** count. Versions, timestamps and metadata are shown but ignored.
- Values are compared as canonical JSON: key order inside nested JSON doesn't matter.
- `5432` (a number) and `"5432"` (a string) are different. The row says **type differs: number vs string**, and values are shown with their types.

Filters (*All changes*, *Different*, *Left only*…, *Everything*) and the path/key search narrow the list. Folders a side couldn't list are named above the results.

### Values and metadata

- **Show values** (top right) reveals values, only for secrets you expand. They're fetched on demand and forgotten when you switch it off.
- Each secret's header shows each side's **current version and when it was written**. Under every value is **when that key last changed** (`changed 3 days ago · v2`). Vault only timestamps whole versions, so the tool works this out by walking back through the versions. `≥` means the history was cut short (deleted, destroyed or trimmed versions). None of this affects the comparison.
- A **badge** under each value says what it is (`PKCS#12 keystore · password needed`, `PEM · expired`…), even while values are masked. See [value tools](#4-value-tools).

## Comparison profiles

A profile tells Lockstep how the two sides relate, when they aren't laid out identically. Choose one in the **Comparison profile** bar, then compare.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="images/09-profile-dark.png">
  <img alt="A profile pairing prod paths with staging paths, with the host key ignored" src="images/09-profile-light.png">
</picture>

| Rule | Example | Effect |
|---|---|---|
| **Path mapping** | `services/*/prod/**` ⇄ `services/*/staging/**` | Pairs `services/billing/prod/db` (left) with `services/billing/staging/db` (right). The row shows both paths |
| **Ignored key** | `host` under `services/**` | `host` is still shown, marked *ignored*, but its difference doesn't make the secret **Different** |
| **Ignored path** | `legacy/**` | Matching secrets are left out of the comparison |

How the rules work:
- **Patterns:** `*` matches within one path segment and `**` across any depth. Both sides of a mapping need the same wildcards in the same order, and what they match is carried across. The first matching mapping wins. Paths no mapping matches are compared as they are.
- **Copies follow the mapping.** Copying a left-only `services/search/prod/config` to the right writes `services/search/staging/config`.
- **Collisions are refused, not guessed.** If two left paths map onto the same right path, that pair shows as an **Error** explaining which paths collide.
- **Mounts too:** a profile can also remember each side's mount and prefix, applied when you pick it.
- **The summary line** says how many pairs a mapping matched, and how many key differences and paths the profile ignored.

**Shared and personal profiles:**
- *Shared* profiles come from the server (`LOCKSTEP_PROFILES`, see [configuration](configuration.md)), so a team sees the same rules. They're read-only: **Duplicate** makes an editable copy.
- *Personal* profiles are saved in your browser. **New** and **Edit** open the editor; **Export** and **Import** move them between browsers or people as JSON.

## 3. Copy values between the sides

- **← / →** next to a key stages a copy of that key toward that side. A key can only travel one way.
- **all keys to left / right**, inside an expanded secret, stages every key the source has.
- A dashed outline marks each value that will be overwritten. The bar at the bottom counts what's staged.

**Review & apply** opens a preview for each target secret: keys **added** or **updated** (with old → new values if *Show values* is on), the version it will become, and any problems:

| Preview status | Meaning |
|---|---|
| Will be written | Ready |
| Already the same | Nothing to do |
| Changed since compare | The target's version moved since you compared. Compare again |
| No permission | The target token can't write there (`sys/capabilities-self`) |
| Can't copy | The source no longer has that key or data |

Tick the confirmation (it names the target Vaults and mounts) and **Apply**. Then:

- **Fresh source values:** source values are **read again from Vault**. Nothing the browser holds is written.
- **Check-and-set:** each write uses KV v2 **check-and-set** against the version you saw. If someone else changes the target in the meantime, that secret comes back as **Conflict: not written**; the rest still go through.
- **No deletes:** keys that exist only on the target are kept. Nothing is ever deleted.
- **Types preserved:** a number stays a number.

Results are shown for each secret, then the tool compares again.

### Audit log

Every attempted write, applied or not, produces one JSON line on the server's stdout:

```json
{"event": "sync.apply", "outcome": "applied", "ts": "2026-11-08T12:00:00Z",
 "actor": {"source_identity": "oidc-alice@example.com", "source_auth": "oidc",
           "target_identity": "oidc-alice@example.com", "target_auth": "oidc"},
 "source": {"vault": "Vault B", "url": "http://vault-b:8200", "mount": "app-config", "path": "frontend/settings", "version": 8},
 "target": {"vault": "Vault A", "url": "http://vault-a:8200", "mount": "app-config", "path": "frontend/settings",
            "old_version": 8, "new_version": 9},
 "keys": ["cdn_url"], "message": ""}
```

Values are never logged. Outcomes are `applied`, `conflict`, `denied`, `invalid` and `error`.

### Sync plans

A plan is a reviewed set of copies saved as a file, so one person can prepare the changes and
another (with write access to the targets) can apply them later. It's also a report of what
needs updating from where.

**Save a plan.** Stage copies as usual and open **Review & apply…**. Add an optional note and
choose **Save as plan**. You don't need write access to the targets to do this: a read-only
user can prepare a plan for someone else. Lockstep downloads `lockstep-plan-<date>-<id>.json`;
**Download report** gives the same plan as a Markdown table (from, to, key, add or update).
Changes that conflict or can't be read can't go into a plan: compare again first. Keys whose
target already has the same value are left out.

A plan records, for each secret: the source and target paths, the keys and whether each is
added or updated, and the version of the source and target at the time. It **never contains
values**: they're read from the source when the plan is applied. It also records who created
it on each side, the comparison profile (if any) and the note. The file is signed by the
Lockstep server (with a key derived from `LOCKSTEP_SESSION_KEY`), so any edit to it is
detected and the plan is refused. A plan made by one Lockstep server can't be applied on
another with a different session key, and changing the session key invalidates existing plans.

**Apply a plan.** Connect both sides to the Vaults the plan names (any identity with write
access to the targets), open the **Sync plans** tab and choose **Open a plan file…**. Check
the report, then **Check plan**: Lockstep reads every source and target now.

- If every secret is exactly as it was when the plan was made, tick the confirmation and
  choose **Apply plan**. Each write uses check-and-set and is audit-logged with the plan's ID
  (`"plan_id"` in the `sync.apply` event).
- If **any** source or target has changed since then, the whole plan is refused and nothing
  is written. The person applying it is told to ask for a new plan, made from a fresh
  comparison.
- If you lack write access to any target, nothing is written either.

The check runs again when you apply. If a secret changes in the moment between that check and
its write, that one write is refused (check-and-set) and the result says so.

## 4. Value tools

**Inspect** (under the status of a key with a badge) opens that key's value from one or both sides. The value is identified by **content, not by key name**, through as many layers as it has: base64 → PEM → certificates, base64 → DER, and so on.

| Detected | What you get |
|---|---|
| X.509 certificate, PEM bundle, PKCS#7, DER | Subject, issuer, names (SANs), validity, key usage, key type, serial, fingerprints. **Chain validation** link by link: signature, issuer is a CA, dates. The verdict is *trusted*, *untrusted root*, *incomplete* or *invalid* |
| PKCS#12 | Opens with a typed password, or one taken from another key in the same secret (keys named like `*pass*` are suggested). Lists the private key and certificates, and checks the key matches its certificate |
| JKS / JCEKS | Certificates are listed without a password. With it, the keystore's integrity is verified and JKS private keys are decrypted and matched to certificates. JCEKS private keys are shown as present only |
| Private key, encrypted key, public key, CSR | Type and size; which certificate (in this value or elsewhere in the secret) the key belongs to |
| PNG, JPEG, GIF, WebP, ICO, SVG | Preview. SVGs are shown as images, so scripts inside them never run |
| ZIP / JAR, GZIP, PDF, other binary | File list (ZIP), hex preview, download |

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="images/08-inspect-jks-dark.png">
  <img alt="A JKS keystore opened with its password: integrity verified, private key decrypted and matched to its certificate" src="images/08-inspect-jks-light.png">
</picture>

**Chains.** Intermediates are taken from the value itself and from the secret's other keys (`chain.pem`, `ca.crt`…). Trust anchors are the **system roots** (Mozilla's list), any certificate key from the comparison you tick, or **Trust this root**, offered for a self-signed root found alongside the value. Anchor choices apply to that inspection only and aren't saved.

**Both sides.** When a key exists on both sides, Inspect opens them in two columns and compares their first certificates field by field. For example, a renewed certificate shows the same subject and a new serial and expiry.

**Previews and downloads** need *Show values*. Private keys inside keystores can't be downloaded. Keystore passwords are used for that one request only.

## 5. Certificate expiry

The **Certificate expiry** tab scans the mounts (and prefixes) chosen on one or both sides for **every certificate stored anywhere**: PEM certificates and bundles, DER, base64-wrapped forms, PKCS#12 files, and JKS/JCEKS keystores. All are found by content, not key name.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="images/11-expiry-dark.png">
  <img alt="Certificate expiry dashboard" src="images/11-expiry-light.png">
</picture>

- **Tiles** split the certificates into expired or not yet valid, within 30 days, in 31–90 days, and later. Each certificate is in exactly one tile. Click a tile to show just that group.
- **Each row** shows the certificate (subject, issuer, CA or self-signed), when it expires, and where it lives: side, path, key, the container (e.g. *PKCS#12 keystore*, alias) and, for keystores, which sibling key's password opened it.
- **Filter and export:** filter by side, hide CA certificates, search, and **Export CSV** what's shown.
- **Inspect** opens the value in the [value tools](#4-value-tools).

Keystores that need a password are opened **only with a password stored in the same secret** (keys named like `*pass*`, `*pwd*`), which you can already read. Keystores that can't be fully checked are listed under *not fully checked*, never silently skipped. Only certificate details come back from the server, never secret values.
