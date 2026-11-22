# Proposal: browsing and editing one Vault ("Browse")

**Status:** phases 1–3 built (metadata editing added with the gap analysis' Wave 1); browsing export files not started · **Written:** 2026-11-21 · **Updated:** 2026-11-21 with decisions (section 8) · **Owner:** unassigned

Everything in Lockstep starts from two sides. Often, though, people want to look around one Vault: find a secret, check a value, see when it changed, fix a key. Today they go to the Vault UI or the CLI for that, then come back to Lockstep to compare. This proposal adds a **Browse** tab, first in the row before **Compare** and the tab Lockstep opens on, for exploring a KV v2 secrets engine and editing it safely. Edits use the same review, check-and-set and audit log as everything else Lockstep writes.

---

## 1. Goals and non-goals

**Goals**
- Browse a KV v2 mount as a tree: folders, secrets and keys, fast on big mounts.
- See a secret's keys (masked until asked), its metadata and its version history. Use the value tools on any value.
- Edit with the same safety as copying:
  - change, add and remove keys;
  - create a secret;
  - soft-delete, undelete and destroy versions;
  - roll back to an older version.

  Each goes through a review, a check-and-set write and the audit log.
- Show what you're allowed to do before you try, and why, using the Policies work.
- Connect naturally to the other tabs: compare this folder, scan it for certificates, explain the policies on it, export it.

**Non-goals**
- Replacing the Vault UI. No other secrets engines (PKI, database, transit…), no auth methods, no system configuration.
- Bulk editing across many secrets. That's what Compare (bulk copy), Import (transforms) and sync plans are for.
- KV v1, in any form. Lockstep stays KV v2 only.

---

## 2. What it would look like

**Browse** shows one side at a time: the left by default, with a toggle to switch to the right when it has a Vault (or an export file) chosen. The mount and prefix chosen in the side card are the starting point; the tree can also start at the mount's root.

```
 Browse   Compare   Certificate expiry   Sync plans   Export & import   Policies

 ◧ Vault A · app-config ▾        [ Find secret… ]                     ⇄ Browse the right side
 ┌───────────────────────────┬──────────────────────────────────────────────────────────┐
 │ ▾ payments/               │ app-config / payments / db                v7 · 3 days ago  │
 │     api            ⊘      │ ───────────────────────────────────────────────────────── │
 │     db             ●      │  host       ••••••••      [Show] [Edit] [Delete]           │
 │ ▸ frontend/               │  port       ••••          [Show] [Edit] [Delete]           │
 │ ▸ services/               │  password   ••••••••      [Show] [Edit] [Delete]  Inspect  │
 │ ▸ restricted/      ⊘      │  ＋ Add key                                                │
 │   legacy/old-service      │                                                           │
 │                           │  Versions  v7 now · v6 3 d · v5 deleted · v4 destroyed …  │
 │ 3 folders · 1 secret      │  Metadata  max versions 10 · cas_required off · owner=pay │
 │                           │                                                           │
 │                           │  Compare… · Scan certificates · Why can I…? · Export…     │
 │                           │  Delete latest · Destroy…                                 │
 └───────────────────────────┴──────────────────────────────────────────────────────────┘
                                         1 change staged     [ Clear ]  [ Review & apply… ]
```

### 2.1 The tree

- Folders are listed **as you open them** (`LIST <mount>/metadata/<folder>/`), so a mount of any size opens straight away. Big folders are paged.
- Icons show what you can do, from `sys/capabilities-self` for the shown paths, batched:
  - ⊘ no access: can't be listed or read;
  - ● a secret whose latest version is deleted;
  - a lock on folders you can list but not read inside.
- **Find secret** searches by name: names in folders already loaded straight away, then a server-side walk of the rest, limited by `LOCKSTEP_MAX_TREE_SECRETS`, like Compare. **Go to path** jumps straight to a path you type.
- The tree remembers which folders were open, per connection and mount, in the browser.
- Selecting a secret updates the address (`#/browse/<side>/<mount>/<path>`), so the back button works and a link can be shared. The link holds no connection id or token: whoever opens it picks their own connection.

### 2.2 A secret

- **Keys and values:** values are masked and not even fetched until you ask. **Show** reveals one key; the global *Show values* switch reveals all. They use the same value cells as Compare: type badges (certificate, keystore, JSON, base64…), **Inspect**, the keystore password finder and downloads.
- **Versions:**
  - the list of versions, with creation time and whether each is current, deleted or destroyed;
  - open any readable older version (read-only);
  - **diff two versions**: keys added, removed or changed. Values stay masked unless shown.
- **Metadata:** current version, created and updated times, `max_versions`, `cas_required`, `delete_version_after` and custom metadata. Lockstep's per-key "last changed" is shown under each value, as in Compare.
- **Links to the other tabs:**
  - **Compare…** opens Compare with this folder as the prefix on this side;
  - **Scan certificates** runs the expiry scan on this folder;
  - **Why can I…?** opens Policies → Explain on this path for your token;
  - **Export…** exports this folder.

### 2.3 Editing

A quick fix shouldn't need a review dialog. So by default a single edit **applies straight away**, after an inline confirmation that shows the change. A whole review is there when you want one: turn on **Stage changes** to collect several edits and apply them together, as copies are in Compare.

Every action, whichever way it's applied:

| Action | What's written |
|---|---|
| **Edit** a value, **＋ Add key** | A new version with the change. The other keys are kept |
| **Delete** a key | A new version without it. Removing every key soft-deletes the latest version instead, as in Compare |
| **New secret** (in a folder, or at a typed path) | A first version. Check-and-set `0`: it must not exist yet |
| **Delete latest** / **Undelete** a version | Soft-delete or restore that version (`delete/` and `undelete/`) |
| **Roll back to vN** | A new version with vN's data (`vault kv rollback`) |
| **Destroy…** a version, or the whole secret | The existing destroy dialog with its typed confirmation. Destroying a single version is new |
| **Metadata** (later phase) | `max_versions`, `cas_required`, `delete_version_after`, custom metadata |

- **Inline confirmation** (the default): under the edited secret, Lockstep shows the keys added, changed or removed (values only if *Show values* is on), and the version the write will create. **Save** writes it; **Cancel** drops it. Delete, undelete and roll back confirm the same way. Destroying always uses its own dialog with the typed phrase.
- **Stage changes** (a switch, remembered per browser): edits collect in the changeset bar, and **Review & apply** shows them all per secret, as in Compare.
- **Check-and-set:** every write is checked against the version shown when you started editing. If someone changed the secret in the meantime, it's a conflict, nothing is written, and the secret reloads.
- **Audit log:** every write is logged without values, like copies, with `"event": "browse.write"` or `"browse.delete"`. Typed values are never logged.

### 2.4 Browsing an export file

An export file opened on a side can be browsed the same way, read-only: the tree, the keys and the value tools. Exports hold no version history or metadata, so those parts are hidden.

---

## 3. How it works inside

Most of the pieces exist already:

| Need | Reuse |
|---|---|
| Listing, reading, versions | `VaultClient.kv_list`, `kv_read(version=…)`, `kv_metadata`; the key history behind "last changed" |
| Values on request | the existing reveal endpoint and value cells |
| Writes with check-and-set | the sync engine's `evaluate`/`apply_changes`. A Browse edit is a change with no source: typed values (`set`) and removed keys (`remove`), exactly what overrides and Delete already send. It needs a one-sided entry point rather than a left/right pair |
| Soft delete and destroy | `kv_delete`, `kv_destroy_all`, plus new `kv_undelete`, `kv_destroy_versions` and rollback |
| Permissions | `sys/capabilities-self`, and the Policies matcher for "why" |
| Review UI | the Review dialog, with a one-sided mode |

**New API (sketch):**
- `GET /api/browse/list?conn_id&mount&folder` lists one folder: names, and which entries are folders.
- `GET /api/browse/secret?conn_id&mount&path[&version]` returns metadata, versions and key names. Values only with `reveal=true`.
- `POST /api/browse/preview` and `POST /api/browse/apply` take staged changes for one side. Each change sets keys, removes keys, creates a secret, deletes, undeletes, destroys or rolls back, and carries the expected version.
- `POST /api/browse/find` finds secrets by name under a folder.

**CLI:** no new command at first. `vault kv` already covers one-off reads and writes from a terminal.

---

## 4. Security and safety

- **Values:** never fetched until shown; never stored server-side; typed values never logged.
- **Clipboard:** **Copy** next to a shown value puts it on the clipboard. The copy is cleared after 30 seconds where the browser allows it. An admin can turn copying off with `LOCKSTEP_ALLOW_CLIPBOARD=false` (chart `allowClipboard`); the button then doesn't appear. It's a deterrent, not a barrier: someone who can see a value can still select it.
- **Writes:** each one confirmed (inline, or in the review when staging), check-and-set, and audit-logged. Destroying needs the typed confirmation and follows `LOCKSTEP_ALLOW_DESTROY`.
- **A read-only server:** some teams want Lockstep for looking only. `LOCKSTEP_READ_ONLY=true` (chart `readOnly`) hides and refuses every write, in Browse and everywhere else: copies, overrides, deleting keys, imports, plan applies and destroys. Reading, comparing, exports (as `LOCKSTEP_EXPORT_MODE` allows), explaining policies and creating sync plans still work. Vault's policies still decide what each person may do; this switch is for installs that never want Lockstep to write. It comes with Browse's first phase, so read-only installs can adopt Browse straight away.
- **Permissions before you try:** controls you aren't allowed to use are disabled, with the reason, instead of failing after a review.

---

## 5. Pros and cons

**For**
- Most people's first question is "what's in here?". Answering it in Lockstep means they stay for the comparison and the fix.
- Lockstep's value tools (certificates, keystores, the password finder) are more useful while browsing than through the Vault UI.
- Edits get the safety the Vault UI doesn't give: a review, check-and-set against what you saw, and an audit line without values.
- It reuses the sync engine, the value cells, the destroy dialog and the Policies matcher, so it's mostly new UI.

**Against**
- **Overlap with the Vault UI.** Lockstep must stay focused on KV v2 and not grow into a general Vault console.
- **A second way to write.** Every write path needs the same care and tests. The shared engine keeps this manageable.
- **Big mounts.** Lazy listing helps, but search across a huge mount is bounded by the same limit as Compare.

---

## 6. Possible phases

1. **Read-only browse:**
   - Browse becomes the default tab, with the left/right toggle;
   - the tree with lazy listing, paging and permission icons;
   - the secret view: masked keys, reveal, **Copy** (with `LOCKSTEP_ALLOW_CLIPBOARD`), value tools, metadata, the version list and older versions;
   - Find and Go to path, deep links, and the links to the other tabs;
   - `LOCKSTEP_READ_ONLY` across the whole app.
2. **Edit:**
   - change, add and remove keys, and new secrets, applied with an inline confirmation;
   - **Stage changes** with the one-sided review;
   - check-and-set and audit for both;
   - soft delete and undelete, roll back, destroy a version or the secret.
3. **Versions and metadata:** diff two versions; edit `max_versions`, `cas_required`, `delete_version_after` and custom metadata; respect `cas_required` everywhere.
4. **More:** browsing export files, read-only.

---

## 7. How to test it

- **Backend:**
  - listing and paging on the seeded mounts, including the space in a name and deep nesting;
  - permission icons for alice, bob and carol, checked against `sys/capabilities-self`;
  - every write type against the dev Vaults, including conflicts (the secret changed after it was loaded) and `cas_required` mounts;
  - audit lines without values.
- **Browser tests:**
  - open folders, find a secret, reveal and inspect a value;
  - edit a key, review and apply, and see the conflict when the secret changed meanwhile;
  - roll back, soft-delete, undelete, destroy a version with the typed confirmation;
  - the deep link survives a reload;
  - with `LOCKSTEP_READ_ONLY`, no write control appears anywhere and the API refuses writes;
  - with `LOCKSTEP_ALLOW_CLIPBOARD=false`, there's no Copy button;
  - carol's restricted folder shows as no access.
- **A big mount:** a generated mount with many thousands of secrets to check lazy listing and paging stay fast.

---

## 8. Decisions

Settled on 2026-11-21:

| Question | Decision |
|---|---|
| One side or both? | **One side at a time**, with a toggle to switch to the other side when it has something chosen |
| Default tab? | **Yes:** Lockstep opens on Browse |
| Is a review for every edit too slow? | **Yes.** Single edits apply after an inline confirmation by default; **Stage changes** collects edits for one review |
| `LOCKSTEP_READ_ONLY` now? | **Yes**, in phase 1, for the whole app |
| KV v1? | **No.** KV v2 only |
| Clipboard? | **Allowed**, and an admin can turn it off with `LOCKSTEP_ALLOW_CLIPBOARD=false` |
