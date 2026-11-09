<!-- description: The lockstep command line: compare two Vault KV v2 locations into a YAML report with Vault UI links and vault kv get commands, then apply it key by key. -->
# Command line

The `lockstep` command does what the web UI does, from a terminal or a CI job:

1. **`lockstep compare`** compares two KV v2 locations and writes a **report**: a YAML file
   listing every secret that differs, with no values in it. For each secret it gives both
   sides' versions, a link to the secret in the **Vault UI** and the **`vault kv get`**
   command to see its values.
2. You set an **action** on the keys or secrets you want to change.
3. **`lockstep apply`** carries out those actions. It reads the values fresh from the source
   and asks before writing each key.

Copies use the same rules as the web UI:
- A write is skipped if the target changed since the report was made (check-and-set).
- Keys that exist only on the target are kept.
- Nothing is deleted.

## Install

The CLI isn't on PyPI yet. You can install it from GitHub or run it from the container image.

### From GitHub (pipx or uv)

You need Python 3.13 or newer and `git`. The package is in the repository's `backend/` directory, so the URL ends in `#subdirectory=backend`.

With [pipx](https://pipx.pypa.io/), which installs the CLI into its own virtual environment and puts `lockstep` on your PATH:

```sh
# a release (recommended); the CLI is in v0.2.0 and later
pipx install "git+https://github.com/welshstew/lockstep@v0.2.0#subdirectory=backend"

# or the latest code on main
pipx install "git+https://github.com/welshstew/lockstep#subdirectory=backend"

lockstep --version
```

[uv](https://docs.astral.sh/uv/) works the same way:

```sh
uv tool install "git+https://github.com/welshstew/lockstep@v0.2.0#subdirectory=backend"
```

To move to another release, run the same command with the new tag and `--force` (`pipx install --force ...`, `uv tool install --force ...`). To remove the CLI, run `pipx uninstall lockstep` or `uv tool uninstall lockstep`.

If you'd rather use a plain virtual environment:

```sh
python3 -m venv ~/.venvs/lockstep
~/.venvs/lockstep/bin/pip install "git+https://github.com/welshstew/lockstep@v0.2.0#subdirectory=backend"
~/.venvs/lockstep/bin/lockstep --help
```

The package also contains the web app's server, so it installs FastAPI and Uvicorn as well. The CLI doesn't start a server.

### From the container image

Every release image (`ghcr.io/welshstew/lockstep`, v0.2.0 and later, for amd64 and arm64) contains the CLI. Its entrypoint starts the web app, so override it with `--entrypoint lockstep`:

```sh
docker run --rm -it --entrypoint lockstep \
  -e VAULT_ADDR -e VAULT_TOKEN \
  -v "$PWD:/work" -w /work \
  ghcr.io/welshstew/lockstep:0.2.0 \
  compare --mount app-config -o report.yaml
```

Podman works the same way: replace `docker` with `podman`. When you run it in a container:
- **Pass tokens through the environment.** `-e VAULT_TOKEN`, with no `=value`, copies the variable from your shell, so the token doesn't show up in the command line. To use the token from `vault login`, mount the file and point the CLI at it:

  ```sh
  -v ~/.vault-token:/run/vault-token:ro ... compare --left-token-file /run/vault-token ...
  ```
- **Mount a directory for the report.** The container runs as uid 65532, so the mounted directory must be writable by that user. On SELinux hosts, add `:Z` to the volume. If you can't do either, write the report to stdout instead with `-o - > report.yaml`, and to apply it pass it in with `-v "$PWD/report.yaml:/report.yaml:ro"`.
- **Keep `-it` for `apply`.** It asks before each write, which needs a terminal. In a pipeline, use `--yes` or `--dry-run` without `-it`.
- **Use the host network for a Vault on localhost.** `localhost` inside the container is the container itself, so add `--network host` (Linux) or use `host.docker.internal` / `host.containers.internal` as the address.

A shell alias makes the image feel like an installed command:

```sh
alias lockstep='docker run --rm -it --entrypoint lockstep -e VAULT_ADDR -e VAULT_TOKEN -e VAULT_NAMESPACE \
  -e LOCKSTEP_LEFT_TOKEN -e LOCKSTEP_RIGHT_TOKEN -v "$PWD:/work" -w /work ghcr.io/welshstew/lockstep:0.2.0'
```

## Logging in

The CLI logs in the way the `vault` CLI does, so `vault login` is usually all you need.
Each side looks for its settings in this order; the first one found wins.

| | Left side | Right side |
|---|---|---|
| Address | `--left-addr`, `LOCKSTEP_LEFT_ADDR`, `VAULT_ADDR` | `--right-addr`, `LOCKSTEP_RIGHT_ADDR`, the left side's address |
| Namespace | `--left-namespace`, `LOCKSTEP_LEFT_NAMESPACE`, `VAULT_NAMESPACE` | `--right-namespace`, `LOCKSTEP_RIGHT_NAMESPACE`, the left side's (same Vault), `VAULT_NAMESPACE` |
| Token | `LOCKSTEP_LEFT_TOKEN`, `--left-token-file`, `VAULT_TOKEN`, `~/.vault-token` | `LOCKSTEP_RIGHT_TOKEN`, `--right-token-file`, `VAULT_TOKEN`, `~/.vault-token` |

- **Userpass or LDAP:** `--left-auth userpass --left-user alice` asks for the password, or reads it from `LOCKSTEP_LEFT_PASSWORD`. Use `--left-auth-mount` if the method isn't mounted at its default path. The token that login creates is revoked when the command finishes.
- **OIDC and other methods:** run `vault login -method=oidc` first, and the CLI picks up the token from `~/.vault-token`. To use two different Vaults, give each side its own token, for example:

  ```sh
  LOCKSTEP_RIGHT_TOKEN=$(VAULT_ADDR=https://vault-b vault login -method=oidc -token-only)
  ```
- **Same Vault on both sides:** to compare two mounts or prefixes in one Vault, give only the left address. The right side then reuses the left side's connection.
- **TLS:** `--ca-cert` or `VAULT_CACERT`; `--tls-skip-verify` or `VAULT_SKIP_VERIFY` (insecure).

The CLI never takes tokens or passwords as arguments, because arguments show up in `ps` and shell history.

## Compare

```sh
lockstep compare \
  --left-addr https://vault-prod.example.com --left-name prod \
  --right-addr https://vault-staging.example.com --right-name staging \
  --mount app-config --prefix services/billing \
  -o report.yaml
```

It prints a summary:

```
Left:  prod (https://vault-prod.example.com) app-config/services/billing
Right: staging (https://vault-staging.example.com) app-config/services/billing

  different   db                differs: password, port (type)
  left only   api
  right only  queue

5 secrets: 2 equal, 1 different, 1 left only, 1 right only.
Report written to report.yaml. Set actions in it, then run: lockstep apply report.yaml
```

| Option | |
|---|---|
| `--mount`, `--left-mount`, `--right-mount` | KV v2 mount on both sides, or on each side |
| `--prefix`, `--left-prefix`, `--right-prefix` | only compare under this path |
| `--profile FILE\|NAME` | a [comparison profile](usage.md): a YAML or JSON file (a profile exported from the web UI, or just its `mappings` / `ignore_keys` / `ignore_paths`), or a name from `LOCKSTEP_PROFILES`. Its mounts and prefixes are used when you don't give them. |
| `--profile-name NAME` | which profile to use when the file holds several (the web UI's export can) |
| `--left-name`, `--right-name` | labels used in the report (default: the host) |
| `--left-ui-addr`, `--right-ui-addr` | the address people open the Vault UI at, if it differs from the API address the CLI uses |
| `-o FILE` | write the report (`-o -` writes it to stdout, and the summary goes to stderr) |
| `--include-equal` | list equal secrets in the report too |
| `-q` | no summary |

**Exit codes**, like `diff`:
- 0: the two sides are the same.
- 1: there are differences.
- 2: the comparison couldn't run.

This makes `lockstep compare -q` usable as a drift check in CI.

## The report

```yaml
lockstep_report: 1
created: '2026-11-09T11:19:48Z'
left:  {name: prod, addr: https://vault-prod.example.com, mount: app-config, prefix: services/billing, identity: oidc-alice}
right: {name: staging, addr: https://vault-staging.example.com, mount: app-config, prefix: services/billing, identity: oidc-alice}
summary: {equal: 2, different: 1, left_only: 1, right_only: 1, ...}
secrets:
- path: db
  status: different
  action: per-key  # per-key | skip | copy-to-right | copy-to-left
  left:
    path: services/billing/db
    state: present
    version: 4
    updated: '2026-11-02T09:12:44Z'
    ui: https://vault-prod.example.com/ui/vault/secrets/app-config/kv/services%2Fbilling%2Fdb/details
    cli: vault kv get -address=https://vault-prod.example.com -mount=app-config services/billing/db
  right:
    path: services/billing/db
    state: present
    version: 7
    ...
  equal_keys: 2
  keys:
  - key: password
    status: different
    action: skip  # skip | copy-to-right | copy-to-left
  - key: port
    status: different
    type_differs: true
    action: skip  # skip | copy-to-right | copy-to-left
  - key: keystore
    status: left_only
    left_holds: PKCS#12 keystore, expires in 41 days
    action: skip  # skip | copy-to-right | copy-to-left
```

Each `keys` entry is a key that isn't equal on both sides:
- `status` is `different`, `left_only` or `right_only`.
- `type_differs` marks `5432` vs `"5432"`.
- `ignored` marks a difference that a profile rule ignores.
- `left_holds` / `right_holds` say what the value is (a certificate, a keystore and so on) without showing it.

When a profile maps paths, `left.path` and `right.path` differ, and copies follow the mapping. If a side couldn't be read, its `state` is `no_access` or `error`, and that secret can't be copied.

### Setting actions

Actions can go on keys or on whole secrets.

**On a key:**
- `copy-to-right` writes the left side's value to the right side.
- `copy-to-left` writes the right side's value to the left side.
- `skip` leaves the key alone. This is the default.

You can mix directions within one secret.

**On a secret:**
- `copy-to-right` or `copy-to-left` copies **every** key the source has, including keys that are already equal.
- `skip` ignores the secret's key actions.
- `per-key` (the default) uses the actions set on its keys.

Don't set both a secret action and key actions on the same secret.

`lockstep apply` checks every action before it writes anything. If something can't work, it lists all of the problems and writes nothing. Examples:
- copying a key from a side that doesn't have it
- an action on a secret one side couldn't read
- a misspelt field or action

## Apply

```sh
lockstep apply report.yaml               # asks before writing each key
lockstep apply report.yaml --dry-run     # show what would be written, write nothing
lockstep apply report.yaml --yes         # write everything the report says, without asking
```

```
→ staging · app-config/services/billing/db   from prod · app-config/services/billing/db
  2 keys to write (v7 → v8):
    update password
  Write password? [y]es / [n]o / [a]ll / [q]uit: y
    update port  (type changes)
  Write port? [y]es / [n]o / [a]ll / [q]uit: n
  Written: v8 (1 key).
```

**Answers at each prompt:**
- `a` says yes to everything after it.
- `q` stops. Secrets already written stay written.

The keys you confirm for a secret are written together, as one new version.

**What apply checks**, for each secret:
- It reads the source again, and writes the value it reads, so values never pass through the report.
- **If the source or target changed since the report was made, the secret is skipped and reported.** The rest still go ahead. Compare again to pick up the changes.
- The write uses check-and-set, so a change made while you are answering prompts also makes it skip.
- The target needs write permission (`create` / `update`).

**Options:**

| Option | |
|---|---|
| `--show-values` | print each key's current and new value before asking. This prints secrets to your terminal. |
| `--audit-log FILE` | append one JSON line per write: who, where, versions, outcome, never values. This is the same format as the web app's audit log. Writes also show up in Vault's own audit device. |
| `--left-addr` and the other login options | the Vault addresses come from the report, but you can override them here, for example when this machine reaches Vault at a different address |

**Exit codes:**
- 0: done.
- 1: some secrets were skipped because they changed or couldn't be written.
- 2: nothing was applied (a bad report, a failed login and so on).

Without a terminal, apply can't ask questions, so it refuses to run unless you pass `--yes` or `--dry-run`.

## Reports and sync plans

A report and a web UI [sync plan](usage.md#sync-plans) are related, but they're used differently.

**A report:**
- is something you edit.
- is applied secret by secret: anything that went stale is skipped and the rest goes ahead.
- isn't signed. Whoever runs `apply` uses their own Vault permissions and confirms each write.

**A sync plan:**
- is signed by the server.
- is all or nothing.

Neither one holds values.
