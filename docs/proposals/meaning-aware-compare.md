# Proposal: meaning-aware comparison

**Status:** implemented (2026-11-26), all five phases · **Written:** 2026-11-25

Today two values are **equal** only if they are the same JSON text (`diff._canon`: object keys sorted, everything else exact). So:
- a change deep inside a JSON value marks the whole key different, with no hint where;
- a list in a different order is different;
- a certificate re-encoded with other line endings is different;
- a keystore saved again with a new timestamp is different.

Every one of those is a false alarm that a reviewer has to clear by hand. That wears down trust in the word *different*, and that's the word Lockstep exists to get right.

This proposal makes statuses follow what a value **means**, and makes every status explainable. It builds on what's already there:
- **Inspect** already recognises base64, PEM, DER, certificates and keystores for display.
- Comparison profiles already have mappings, key ignores and whole-word rewrites.

---

## 1. Goals and non-goals

**Goals**
- Fewer false "different" results, with no new false "equal" ones.
- Say **where** inside a value the difference is (`config.db.host`).
- Say **why** a key got its status: which rule or comparator decided.
- Keep it all server-side. Values still never reach the browser unless the user reveals them.

**Non-goals**
- Fuzzy matching. Every comparator is exact about something: bytes, structure, or named certificate fields.
- Comparing values that aren't in Vault. That's [connection probes](connection-probes.md).

**Anti-goal**
- A comparator that calls two values equal when a service would behave differently with them. When in doubt, a comparator says **different** and explains.

---

## 2. Nested JSON diff

- When both sides of a key are JSON objects or arrays, or strings that parse as JSON or YAML, diff them **structurally**. Report the changed paths: `config.db.host`, `hosts[2]`.
- In a profile, ignore rules and rewrites can name a nested path: `{"key": "config", "field": "db.password"}`.
- **Limits:** depth 8 and 1,000 leaves per value. Past them, fall back to whole-value comparison and say so.
- The browser receives only the **paths** that differ, never the values at them. This follows the existing rule that statuses carry no values.

## 3. Comparators for common value types

A **comparator** decodes both values to a form that drops differences that don't matter, then compares that form. It's chosen automatically from what Inspect detects, and a profile can turn it off per key.

| Type | Compared as | Ignored |
|---|---|---|
| JSON or YAML in a string | parsed structure | whitespace, key order |
| base64 | decoded bytes | padding, line breaks |
| PEM | DER bytes of each block, in order | line endings, header spacing |
| X.509 certificate | fingerprint (SHA-256 of DER) | encoding only. *Equal* means the same certificate. A *different* result shows which fields changed: subject, SANs, issuer, validity, key. |
| Private key | public key | encoding (PKCS#1 vs PKCS#8) |
| PKCS#12 or JKS | the list of aliases with certificate fingerprints, and the private keys' public halves | MAC salt, timestamps, entry order |

Text normalisation (trailing newline, CRLF vs LF, Unicode NFC) is **opt-in per key**, because some services do care.

## 4. Rule additions to comparison profiles

- **Unordered lists, per key:** `{"key": "allowed_hosts", "unordered": true}`, for SANs, scopes and host lists.
- **Volatile values:** ignore or normalise by regex within a key or path scope, such as timestamps, UUIDs and build numbers: `{"key": "*", "path": "apps/**", "pattern": "\\d{4}-\\d{2}-\\d{2}T[^\"]+"}`.
- **Scoped rewrites:** a rewrite can be limited to keys and paths, so `test` → `dev` applies to `*.host` but never to `password`. Today rewrites are whole-word and global, so they can change a word inside an unrelated value. Review already marks rewritten keys; scoping prevents the surprise.
- **Regex rewrites with capture groups,** behind the same scope, for names that follow a pattern (`(\w+)-test-db` → `$1-dev-db`). Each rewrite is still shown in review and in the plan.

The profile builder (**Read both sides**) suggests these, the same way it suggests mappings and rewrites today. For example: "these 14 keys differ only in a date: ignore that pattern?"

## 5. "Not compared" as a status of its own

Some things can't be compared, and the reason should show:
- a value in a sensitive configuration field (see [trust fixes](trust-fixes.md) 2);
- a value past the nesting limits;
- a keystore that needs a password.

These get the status **not compared** with the reason, rather than being left out or called equal. Denied folders and truncated listings are already shown. They move under the same heading so the summary counts are honest.

## 6. Explain each status

Each key's status carries a short reason, for example:
- "equal after rewrite `test`→`dev`";
- "equal as certificates (same fingerprint; PEM line endings differ)";
- "ignored by profile rule `log_level`";
- "different at `config.db.host`".

Results show it under the status, and the CLI report includes it. This is what makes a status something people can trust instead of second-guessing it.

---

## 7. Phases

1. Nested JSON diff with paths, and the **explain** reason (§2, §6). **Done**, with one difference from §2: rewrites can't be scoped to a nested path yet (that's §4, phase 3). Ignore rules can (`field`).
2. base64, PEM and certificate comparators (§3, without keystores). **Done**, on by default (§9), and stricter than the table in §3 where a service could read the two texts differently: a private key in PKCS#1 and PKCS#8, a PEM label, PEM against DER, and base64 padding or alphabet stay *different*, with a reason that says it's the same thing. Only line endings, line wrapping and spacing around PEM blocks are ignored. A profile's `exact_keys` turns the comparators off per key.
3. Profile additions: unordered lists, volatile patterns, scoped rewrites (§4). **Done.** Volatile patterns take a key and path scope but not a field (they apply to the whole value, text inside JSON included). Rewrites are scoped by key and secret path, not by a field inside a value. A key that differs only in volatile text is *ignored* (like an ignored field), not *equal*, so it can still be copied.
4. Keystores, regex rewrites, and builder suggestions for all of the above. **Done**, with these differences:
   - Regex rewrites are **patterns with placeholders** (`{app}-test-db` ⇄ `{app}-dev-db`) rather than raw regexes with `$1`. A placeholder is one word, so matching can't backtrack badly on any value, and every pattern works in both directions (a copy to the left reads it back), which a raw regex doesn't.
   - Keystores: PKCS#12 only when it opens without a password; JKS and JCEKS always (their certificates aren't encrypted), but a JKS private key counts as the same only when its encrypted bytes are. Keystores that need a password wait for phase 5.
   - The builder suggests unordered lists (whole values: JSON/YAML lists and comma-separated text) and volatile patterns from three fixed patterns: timestamp, date and UUID. It doesn't suggest pattern rewrites yet.
5. **Not compared** (§5), together with trust fix 2. **Done** for keys and secrets: a keystore whose password isn't in the secret, and a JKS key that can't be decrypted. Before giving up, a keystore is opened with passwords stored next to it in the same secret, or Java's default. Two of §5's cases needed nothing new. Values past the nesting limits are still compared exactly as a whole (only the list of fields is incomplete, and the reason says so), so their status is right. Sensitive configuration fields already show as *not compared* in the Configuration tab (trust fix 2). Denied folders and cut-short listings are already counted (as *No access*) and named above the results.

## 8. Testing

- Property tests: a comparator never says equal for two values whose decoded bytes or structure differ.
- Fixtures: the same certificate in PEM with LF and with CRLF, and in DER; a keystore saved twice; JSON with keys reordered.
- Seed data: add an `encodings` example to the demo so the guide can show it.

## 9. Open questions

- Should comparators be on by default, or opt-in per profile at first? I'd turn them on by default, with the reason always shown, because every comparator only removes encoding noise.
- Does a certificate that was renewed (same subject and key, new validity) count as *different*? Yes, with the reason "renewed: new validity". The expiry view already cares about that difference.
