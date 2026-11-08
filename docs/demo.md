# Public demo deployment

`deploy/demo/compose.yaml` runs a self-contained public demo on any Docker host: two
throwaway dev-mode Vaults, Dex for OIDC sign-in, the seed job and Lockstep, behind Caddy
with automatic HTTPS (Let's Encrypt). Only Caddy publishes ports (80 and 443).

## DNS

Point these A records at the server (no AAAA record unless the server has that IPv6 address):

| Name | Used for |
|---|---|
| `demo.<domain>` | Lockstep |
| `login.<domain>` | Dex (OIDC sign-in) |
| `<domain>`, `www.<domain>` | redirect to `demo.<domain>` |

## Deploy

```sh
scripts/deploy-demo.sh root@<server> <domain>
```

The script copies the repository to `/opt/lockstep` with rsync (install `rsync` on the server
first), and on the first run writes `/opt/lockstep/.env` with random secrets: the session
key, both Vault root tokens and the Dex client secret. Later runs keep that file. It renders
the Dex config from `deploy/demo/dex.yaml.tmpl` (Dex doesn't expand environment variables),
then builds and starts the stack. Run it again to deploy a new version.

## What visitors get

- Only the two demo Vaults (`LOCKSTEP_ALLOW_CUSTOM_CONNECTIONS=false`), so the server can't
  be pointed at other hosts. The Vaults themselves aren't published.
- Userpass sign-in as `alice` (admin), `bob` (read-only) or `carol` (limited), password
  `password`, or OIDC as `alice@example.com` / `password`.
- A banner (`LOCKSTEP_DEMO_BANNER`) saying the data is temporary. The seed job restores the
  demo data every `RESEED_INTERVAL` seconds (default 3600).
- Security headers from Caddy: HSTS, a strict Content-Security-Policy, `frame-ancestors 'none'`.

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
