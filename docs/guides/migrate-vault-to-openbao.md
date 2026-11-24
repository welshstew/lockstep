<!-- description: Migrate KV v2 secrets from HashiCorp Vault to OpenBao and prove every secret arrived: check what OpenBao lacks, export and import, compare both sides, then compare policies and configuration. -->
# Migrating from HashiCorp Vault to OpenBao, verified

OpenBao is the open-source fork of HashiCorp Vault. It has the same API, the same KV v2 engine and much the same CLI (`bao` instead of `vault`), so most migrations amount to copying what's in Vault and pointing clients at the new address.

The hard part is knowing you're finished. Did every secret arrive, with every key, and with numbers still numbers? Did anyone change something in Vault after you copied it? Do the policies grant the same access? A loop over `vault kv get` and `bao kv put` copies data, but it can't answer any of those questions.

This guide does the migration with [Lockstep](https://getlockstep.cloud), and checks it, with Vault on one side and OpenBao on the other:
1. check what the OpenBao cluster is missing before you start;
2. copy each KV v2 mount;
3. prove the two sides match, and keep proving it until the cutover;
4. compare policies and configuration.

Every command below was run against Vault 1.21 and OpenBao 2.7.

## Install Lockstep

```sh
pipx install "git+https://github.com/welshstew/lockstep@v0.10.0#subdirectory=backend"
```

Or run the CLI from the image: `docker run --rm -it --entrypoint lockstep ghcr.io/welshstew/lockstep:0.10.0 --help`. See [Command line](../cli.md#install).

Lockstep's commands log in with tokens, userpass, LDAP or JWT. The examples use tokens:

```sh
export LOCKSTEP_LEFT_TOKEN=…    # a token on Vault
export LOCKSTEP_RIGHT_TOKEN=…   # a token on OpenBao
```

## 1. Before you start: what's different

Compare the two clusters' configuration first. It lists every secrets engine and auth method on each side, and the differences in their settings:

```sh
lockstep config compare --left-addr https://vault.example.com --right-addr https://openbao.example.com
```

```text
Vault 1.21.4 ⇄ OpenBao 2.7.3  (versions differ)
left only   secrets engine app-config/ (kv)
left only   secrets engine database/ (database)
left only   secrets engine directory/ (ldap)
left only   auth method ldap/ (ldap)
…
```

Every `left only` line is something the migration has to create on OpenBao. Check two things before you go further:

- **Plugins OpenBao doesn't have.** OpenBao doesn't ship every plugin Vault does. On our OpenBao 2.7.3 test cluster, `ldap`, `aws`, `azure` and `gcp` weren't in the plugin catalog. Run `bao plugin list` on yours. Anything missing needs another plan (an external plugin, or a different auth method) before cutover.
- **Fields only one product reports.** Vault and OpenBao return slightly different settings for the same thing. For example, OpenBao adds a `status` to JWT and OIDC auth configuration, and PKI roles have fields only one product has. In engine roles and auth configuration, Lockstep doesn't count a field that only one server returns as a difference. The web UI lists these fields as "not compared".

## 2. Copy a KV v2 mount

Create the mount on OpenBao, with the same path:

```sh
bao secrets enable -path=app-config kv-v2
```

Export it from Vault. The export file is encrypted with a one-time key:

```sh
lockstep export --vault-addr https://vault.example.com --vault-token-file ~/.vault-token \
    --mount app-config -o app-config.json --key-file app-config.key
```

```text
Exported 14 secrets (30 keys) from https://vault.example.com app-config to app-config.json (encrypted).
Not exported, deleted (latest version): retired/thing
Key written to app-config.key. Keep it apart from the export.
```

Secrets whose latest version is deleted aren't exported, and the output lists them. Then preview the import into OpenBao:

```sh
lockstep import app-config.json --vault-addr https://openbao.example.com \
    --mount app-config --key-file app-config.key --dry-run
```

```text
  new       services/billing/prod/api    key (add), timeout (add)
  new       services/billing/prod/db     host (add), password (add), port (add), user (add)
  …
14 to write, 0 already the same.
Dry run: nothing written.
```

Run the same command without `--dry-run` to write. Lockstep asks once before writing, or you can pass `--yes`. Each write uses check-and-set, so nothing that changed on OpenBao in the meantime is overwritten. Values keep their types: a port stored as the number `5432` stays a number.

Need to rename paths, leave things out or rewrite values on the way across? Use the import rules in [Exporting, importing and migrating Vault secrets](export-import-vault-secrets.md). The web UI's **Export & import** tab does the same steps, if you prefer it.

When you're done, delete the export file and the key. The export holds every value from the mount.

## 3. Prove every secret arrived

Compare the two live mounts:

```sh
lockstep compare --left-addr https://vault.example.com --left-name vault \
    --right-addr https://openbao.example.com --right-name openbao --mount app-config
```

```text
Left:  vault (https://vault.example.com) app-config
Right: openbao (https://openbao.example.com) app-config

15 secrets: 15 equal.
```

Every key of every secret has been compared, on the machine running Lockstep. Values are never printed. The exit code is 0 when the two sides match and 1 when they don't, like `diff`.

**Until the cutover, things will change in Vault.** Compare again and you see what changed:

```text
  different   services/billing/prod/api  differs: timeout

15 secrets: 14 equal, 1 different.
Report written to report.yaml. Set actions in it, then run: lockstep apply report.yaml
```

There are two ways to bring OpenBao up to date:
- **Import again.** Export a fresh copy and import it the same way. Only secrets that changed are written; the preview shows how many are already the same.
- **Copy just the differences.** In the report, set `action: copy-to-right` on the secrets you want, then run `lockstep apply report.yaml`. Apply rereads each value from Vault, so values never sit in the report. It skips any secret that changed since the comparison.

For the final check, run the comparison in a script or CI job just before switching clients over. `lockstep compare -q` prints nothing and only sets the exit code. See [Detecting secret drift in CI](detect-vault-secret-drift-in-ci.md).

## 4. Policies and configuration

Secrets are only half of a migration: the people and applications reading them need the same access on OpenBao.

**Policies:** compare them by meaning, not by text:

```sh
lockstep policy compare --left-addr https://vault.example.com --right-addr https://openbao.example.com
```

```text
different   default
              path "sys/control-group/request"  [update] → —
              path "sys/renew"  [update] → —
left only   payments-dev ⇄ —
left only   search-app ⇄ —
```

The built-in `default` policy differs between the two products. Vault's grants two paths that OpenBao's doesn't: `sys/control-group/request`, which is for Vault Enterprise's control groups, and `sys/renew`. That difference is expected. Copy only the policies you wrote yourself: in the web UI, **Policies › Compare across Vaults** has **Copy to right →** on each row, with a diff and a review before anything is written.

**Configuration:** rerun `lockstep config compare` once the engines and auth methods exist on OpenBao. In the web UI's **Configuration** tab, a row that differs has **Copy tuning to …** (TTLs, description, visibility), and engine roles (PKI, database, SSH, Transit, Kubernetes and more) have **Copy to …**. Lockstep never copies secrets held in configuration, such as database passwords and bind credentials. Set those on OpenBao yourself.

## Namespaces

OpenBao 2.3 and later has namespaces, with the same API as Vault Enterprise. Lockstep signs in to a namespace with `--left-namespace` and `--right-namespace` (or the **Namespace** field in the web UI). So you can migrate and compare one namespace at a time, or check that `team-a` on Vault matches `team-a` on OpenBao.

## Try it on the demo

The [live demo](https://demo.getlockstep.cloud) has two Vaults and two OpenBaos with the same sample data. Sign in as `alice` / `password`, with **Vault A** on one side and **OpenBao A** on the other. Choose `app-config` and press **Compare**. Then open **Configuration** to see what a Vault-to-OpenBao check looks like.

## Next steps

- [Exporting, importing and migrating Vault secrets](export-import-vault-secrets.md): rules that rename paths and rewrite values
- [Syncing secrets between Vault environments safely](sync-vault-secrets-between-environments.md)
- [Detecting secret drift between Vault environments in CI](detect-vault-secret-drift-in-ci.md)
