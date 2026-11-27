# Public demo deployment

To run the demo on your own machine instead, see [Running the demo locally](guides/run-the-lockstep-demo-locally.md).

`deploy/demo/compose.yaml` runs a self-contained public demo on any Docker host: two
throwaway dev-mode Vaults and two OpenBaos, Dex for OIDC sign-in, the seed jobs and Lockstep, behind Caddy
with automatic HTTPS (Let's Encrypt), plus a landing page and visit statistics. Only Caddy
publishes ports (80 and 443).

## DNS

Point these A records at the server (no AAAA record unless the server has that IPv6 address):

| Name | Used for |
|---|---|
| `demo.<domain>` | Lockstep |
| `login.<domain>` | Dex (OIDC sign-in) |
| `<domain>` | landing page (`deploy/demo/site`), drift checks at `/drift/`, and visit statistics at `/stats/` |
| `www.<domain>` | redirect to `<domain>` |

## Deploy

```sh
scripts/deploy-demo.sh root@<server> <domain>
```

The script copies the repository to `/opt/lockstep` with rsync (install `rsync` on the server
first), and on the first run writes `/opt/lockstep/.env` with random secrets: the session
key, the Vault and OpenBao root tokens and the Dex client secret. Later runs keep that file,
adding any secret a newer version needs (the OpenBao tokens, `BAO_A_TOKEN` and `BAO_B_TOKEN`). It renders
the Dex config from `deploy/demo/dex.yaml.tmpl` (Dex doesn't expand environment variables),
then builds and starts the stack. Run it again to deploy a new version. It also adds a
password for the statistics page to `.env` the first time (`STATS_PASSWORD`, user `stats`).

## What visitors get

- Only the demo's servers (`LOCKSTEP_ALLOW_CUSTOM_CONNECTIONS=false`), so the server can't
  be pointed at other hosts: Vault A and B, and OpenBao A and B. The OpenBaos are seeded
  with the same data by their own seed job (`seed-openbao`), without the LDAP mounts, which
  OpenBao doesn't ship. Vault against OpenBao shows what a migration check looks like. The
  OpenBaos also have namespaces (`team-a`, `team-a/apps`, and `team-b` on A or `team-c` on B):
  type one in the connect form's **Namespace** field and sign in as `alice`.
  None of them is published.
- Memory: each Vault is limited to 384 MB and each OpenBao to 256 MB; the whole stack
  stays under about 3 GB.
- Userpass sign-in as `alice` (admin), `bob` (read-only) or `carol` (limited), password
  `password`, or OIDC as `alice@example.com` / `password`.
- A banner (`LOCKSTEP_DEMO_BANNER`) saying the data is temporary. The seed job restores the
  demo data every `RESEED_INTERVAL` seconds (default 3600).
- Security headers from Caddy: HSTS, a strict Content-Security-Policy, `frame-ancestors 'none'`.

## Landing page

`deploy/demo/site/` is a static page (HTML and CSS, no scripts) served at `<domain>`. Its
screenshots come straight from `docs/images`, so `make screenshots` keeps it current.

## Visit statistics

Caddy writes an access log for every site; [GoAccess](https://goaccess.io/) turns it into a
report every 5 minutes, served at `https://<domain>/stats/` behind a password:

```sh
ssh root@<server> grep STATS_PASSWORD /opt/lockstep/.env   # user: stats
```

The report shows visitors and requests per day, per site (landing page, demo, login), pages,
referrers, browsers and countries. Demo use shows up in the requested URLs, for example
`POST /api/connections` (sign-ins), `POST /api/compare` (comparisons) and `POST /api/plans`
(saved plans).

Privacy: no cookies or scripts are used for this. IP addresses are anonymised in the report.
The raw access log keeps full IP addresses for 30 days, then rotates out. Sign-in material
never reaches the log: Caddy drops Cookie and Authorization headers, and the OIDC
callback's `code` and `state` are removed from logged URLs. Totals survive log rotation
(`stats-db` volume).

## Drift checks

The `drift-check` service shows the drift check working on the demo's own data, at `https://<domain>/drift/`. Every 5 minutes it runs `lockstep compare` on four seeded pairs (Vault A and B, OpenBao A and B, each on `app-config` and `apps` under the shared profiles), signed in as the read-only user `bob`. It writes a static page, with no scripts, into the `drift-data` volume, which Caddy serves.

- **Baselines:** the seed writes a marker to the `seed-marks` volume after each hourly reset (`SEED_MARKER`). Within 15 seconds the job records a new baseline from the fresh data, so a run fails only on drift a visitor made since the reset.
- **The page** has one card per pair: the latest status (no drift, known drift only, new drift, couldn't run), the counts, a strip of the last 12 hours (a fixed slot per run; point at one for when it ran and what it found), a table of the new drift with paths, keys and reasons, the pair's baseline, `base.json`, to expand or download, and a screenshot of the same comparison in Lockstep. It never shows values, so it has no password. It refreshes itself after each run.
- **Code:** `deploy/demo/drift/drift.py` and `drift.css`. It runs in the Lockstep image, read-only, with a 192 MB memory limit. Each compare has a 2-minute timeout. `DRIFT_INTERVAL` sets the time between runs, in seconds (300 by default).

## Operating it

```sh
cd /opt/lockstep
docker compose -f deploy/demo/compose.yaml --project-directory . ps
docker compose -f deploy/demo/compose.yaml --project-directory . logs -f app
docker compose -f deploy/demo/compose.yaml --project-directory . down   # stop
```

Rotate the secrets by deleting `.env` and redeploying; everyone is signed out.

## Host hardening

Allow only SSH, HTTP and HTTPS in, and turn off services listening on all interfaces that
the demo doesn't need (for example LLMNR on port 5355 on Debian).
