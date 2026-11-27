<!-- description: Run the Lockstep demo on your own machine with Podman Compose: two HashiCorp Vaults (or a Vault and OpenBao) filled with demo data, demo users, OIDC sign-in through Dex, and a drift check. -->
# Running the demo locally with Podman

The [public demo](https://demo.getlockstep.cloud) resets every hour and is shared with everyone. To try Lockstep on your own, run the same demo on your machine. It's one command, and nothing leaves your machine.

You get:
- two Vaults in dev mode (Vault A and Vault B), filled with demo data that differs between them on purpose;
- three demo users, signing in with a username and password or with OIDC through Dex;
- Postgres, for the database credentials tool;
- Lockstep at http://localhost:8080.

Everything runs in memory. Stop the stack and the data is gone; start it again and it's back as it was.

## What you need

- **Podman 5** with Compose: `podman compose` runs `docker-compose` or `podman-compose`, whichever is installed. Docker with Compose works too: type `docker` wherever this guide says `podman`.
- **On a Mac or Windows,** a Podman machine with at least 4 GB of memory and 2 CPUs:

  ```sh
  podman machine init --memory 4096 --cpus 2   # first time only
  podman machine start
  ```
- **Free ports:** 8080 (Lockstep), 8200 and 8201 (the Vaults' own UIs) and 5556 (Dex).

## Start it

```sh
git clone https://github.com/welshstew/lockstep.git
cd lockstep
podman compose up --build -d        # or: make up
```

The first build takes a few minutes. Then the stack starts in this order:

1. Vault A, Vault B, Postgres and Dex.
2. **The seed job.** Once both Vaults are healthy it creates the demo's secrets engines, secrets, policies, auth methods and users, then exits.
3. **Lockstep.** It waits for the seed to finish, so when http://localhost:8080 answers, the data is there.

To check on it:

```sh
podman compose ps                 # seed shows "Exited (0)" when it's done
podman compose logs seed          # what it created
```

## Sign in

Open http://localhost:8080. Both sides offer **Vault A** and **Vault B**: choose one for each side and sign in.

| Sign in as | Password | Can do |
|---|---|---|
| **Username** `alice` | `password` | everything (admin) |
| **Username** `bob` | `password` | read and list every secret, but not write |
| **Username** `carol` | `password` | only `app-config`: `restricted/` is hidden and `payments/api` can be listed but not read |
| **OIDC** `alice@example.com` or `bob@example.com` | `password` | as alice or bob. Dex opens at `dex.localhost`, which Chrome and Firefox send to your own machine |

The users exist on both Vaults. Root tokens work too (**Token**: `root-a` for Vault A, `root-b` for Vault B), but a root token has no identity, so it can't approve a plan.

Two extra connections point at Vault B:
- **Vault B (read-only)** refuses writes from Lockstep.
- **Vault B (with approval)** only takes writes through a sync plan that someone else approved.

## Things to try

- **Compare:** pick `app-config` on both sides and press **Compare**. You'll see equal, different and one-sided secrets, a soft-deleted secret, images and certificates.
- **A comparison profile:** choose **Prod ↔ staging services** to compare `services/<name>/prod` in Vault A with `services/<name>/staging` in Vault B.
- **A rename:** on the `apps` mount, the profile **Test ↔ dev: apps (ELP rename)** lines up `enterprise-logging-app` in Vault A with `ELP` in Vault B. The [rename guide](compare-environments-after-a-rename.md) walks through it.
- **Matrix:** compare one baseline with several environments at once.
- **Certificate expiry:** scan `certs` for expired and expiring certificates, including ones inside Java keystores.
- **Promote with an approval:** sign in as alice on Vault A and to **Vault B (with approval)**, stage a copy and save a sync plan. Then, in a private window, sign in to the same two connections as bob, open the plan in **Sync plans**, check it and approve it. Back as alice, apply it. The [approvals guide](promote-vault-secrets-with-approvals.md) has the details.

The [development guide](../development.md) lists every mount, fixture and policy in the demo data.

## Reset the demo data

The seed job recreates its secrets engines each time it runs, so this puts back the demo data, however much you've changed:

```sh
podman compose run --rm seed
```

If Lockstep then says a sign-in has ended, sign in again.

## Run a drift check

The Lockstep image includes the command line tool. Record the drift between the two Vaults as accepted, then check against it. Do this as bob, who can only read:

```sh
mkdir -p drift && chmod 777 drift      # the container runs as uid 65532 and writes here
lockstep() {
  podman compose run --rm --no-deps -v "$PWD/drift:/work" -w /work --entrypoint lockstep \
    -e LOCKSTEP_LEFT_PASSWORD=password -e LOCKSTEP_RIGHT_PASSWORD=password app "$@" \
    --left-addr http://vault-a:8200 --left-auth userpass --left-user bob \
    --right-addr http://vault-b:8200 --right-auth userpass --right-user bob --mount app-config
}

lockstep baseline update drift.json            # accept the drift as it is now
lockstep compare --baseline drift.json; echo "exit $?"   # 0: nothing new
```

Now change a secret on either side in **Browse** (sign in as alice) and run the `compare` line again. It lists the new drift and exits with 1. `drift/drift.json` is the baseline: paths, keys and statuses, never values. [Detecting drift in CI](detect-vault-secret-drift-in-ci.md) explains the options.

## Use OpenBao as Vault B

OpenBao can stand in for Vault B, to see what a migration check looks like. This starts OpenBao, points Lockstep at it and seeds it:

```sh
podman compose --profile openbao up -d --wait openbao
VAULT_B_HOST=openbao VAULT_B_BROWSER_URL=http://localhost:8210 podman compose up -d --force-recreate app
VAULT_B_HOST=openbao podman compose run --rm seed
```

The connections named **Vault B** now reach OpenBao. It gets the same data, without LDAP, which OpenBao doesn't ship, and with namespaces (`team-a`, `team-a/apps`, `team-c`): type one in the **Namespace** field and sign in as alice. To go back to Vault B:

```sh
podman compose up -d --force-recreate app
podman compose run --rm seed
```

## Stop it

```sh
podman compose down        # or: make down
```

The Vaults keep their data in memory, so the next `podman compose up -d` starts from fresh demo data.

## Kubernetes sign-in

`podman compose --profile k8s up --build -d` (or `make up-k8s`) also starts a small k3s cluster, so you can sign in with a Kubernetes service account. See [Authentication](../authentication.md#trying-it-locally).
