# Getting Lockstep in front of DevOps teams

**Status:** in progress · **Written:** 2026-11-23 · **Owner:** Stuart (posting, accounts), Claude (building, drafting)

As of 2026-11-23 the site has had about 1,500 unique visitors. The aim is to reach people when they're facing a problem Lockstep solves. People search for the problem, not the tool. Three jobs to lead with:

1. **"Is staging the same as prod?"** Comparing two Vaults, or two mounts.
2. **Promoting secrets from dev to prod safely,** with a review, and a plan someone else applies.
3. **Migrating between clusters, or from Vault to OpenBao,** then proving that every secret arrived.

Who does what:
- **Claude** builds and drafts.
- **Stuart** posts, publishes, and changes accounts and repo settings. Nothing goes out under Stuart's name without Stuart.

## 1. Foundations

| # | Task | Who | Status |
|---|---|---|---|
| 1 | Test Lockstep against **OpenBao**: `make test-openbao` runs every backend and browser test with OpenBao 2.7 as Vault B. Built-in plugin versions no longer count as configuration drift. | Claude | ✅ Done (all pass) |
| 2 | Configuration compare: Vault and OpenBao return different default fields for engine roles. Fields only one server returns (and PKI `signature_bits` left automatic) are set aside and listed as "not compared". | Claude | ✅ Done |
| 3 | Run the OpenBao suite in CI: weekly, like the `vault-release` workflow, so OpenBao support stays true. | Claude | To do |
| 4 | **Pitch:** the landing page and README lead with the three jobs above. Add "Works with HashiCorp Vault and OpenBao" to the landing page. (The README now says it.) | Claude drafts, Stuart reviews | To do |
| 5 | **GitHub repo:** <ul><li>topics: `vault`, `hashicorp-vault`, `openbao`, `secrets-management`, `devops`, `kubernetes`, `helm`, `gitops`</li><li>a one-line description</li><li>a social preview image (1280×640)</li></ul> | Claude makes the image, Stuart sets them | To do |
| 6 | A 20–30 second **GIF** at the top of the README: compare, show a difference, copy, review. Recorded with Playwright from the dev stack. | Claude | To do |
| 7 | A **GitHub Action**: runs `lockstep compare` / `lockstep config compare` in a workflow and fails or comments when Vaults drift. Needs its own public repo (`welshstew/lockstep-action`) for a Marketplace listing. | Claude builds, Stuart creates the repo and publishes | To do |
| 8 | Per-channel `?ref=` tags on every link we post (`?ref=hn`, `?ref=reddit-devops`, …), so the stats show which channels bring people who go on to install Lockstep. | Claude lists them, Stuart checks the stats | To do |

## 2. Content

Guides on getlockstep.cloud, cross-posted to dev.to or Hashnode with the canonical link back to the site. Each one answers a question people search for, with a working example on the dev stack.

| # | Post | Status |
|---|---|---|
| 9 | How to diff two Vault clusters (and what "different" should mean) | To do |
| 10 | Copy secrets between Vault clusters without scripts: reviewed, check-and-set, audit-logged | To do |
| 11 | Catch Vault configuration drift in CI: `lockstep config compare` and the GitHub Action (after #7) | To do |
| 12 | Vault → OpenBao migration, verified: export, import, compare every secret and policy | To do |

Claude drafts, Stuart reviews and publishes.

## 3. Launch

Spread these over a couple of weeks. Each needs a reason to look: a new guide, the Action, OpenBao support.

| # | Task | Who | Status |
|---|---|---|---|
| 13 | **Demo check before any launch:** a short load test on demo.getlockstep.cloud, and check the hourly reset and session limits hold up. | Claude runs it, with Stuart's go-ahead | To do |
| 14 | **Show HN:** "Show HN: Lockstep – diff and sync secrets between Vault clusters". Link the live demo, and post on a weekday morning, US time. Stay around to answer comments. | Claude drafts, Stuart posts | To do |
| 15 | **Reddit:** one post per subreddit, each written for that audience. r/devops, r/kubernetes, r/selfhosted (the demo), r/hashicorp, and the OpenBao community. | Claude drafts, Stuart posts | To do |
| 16 | **Newsletters:** DevOps Weekly, SRE Weekly, KubeWeekly, Console.dev, TLDR DevOps. Each has a submission form or address. | Claude drafts a blurb, Stuart submits | To do |
| 17 | **Answer existing questions** about copying or diffing secrets between clusters, linking the guides: HashiCorp Discuss, Stack Overflow, Reddit. Say you're the author. | Claude finds threads, Stuart answers | To do |

## 4. Listings

| # | Task | Who | Status |
|---|---|---|---|
| 18 | Artifact Hub: confirm 0.8.0 is listed with its change log, and add the "verified publisher" metadata. | Claude checks, Stuart does the publisher step | To do |
| 19 | Awesome lists (awesome-vault, awesome-kubernetes, and an OpenBao list if there is one). Read each list's rules first. | Claude drafts entries, Stuart opens the PRs | To do |
| 20 | awesome-selfhosted, once the project meets its age rule. | Later | Not yet |

## 5. Later

| # | Task | Who |
|---|---|---|
| 21 | A lightning talk at a local DevOps or Kubernetes meetup: a 5-minute live diff of two Vaults. | Claude drafts the abstract and demo script, Stuart gives it |
| 22 | HashiConf and KubeCon calls for papers, with the meetup talk as practice. | Stuart |

## Order

1 → 4 → 6 → 7 → 9–12 (posts) → 13 → 14–16 (launch) → 17–19 alongside.

The OpenBao work (1–3) comes first, because it gives the strongest new angle. Nothing gets posted until the demo check (13) is done.
