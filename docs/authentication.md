# Authentication

Each side of a comparison has its own **connection**: a Vault address, an optional namespace, and a way to sign in. A browser session can hold up to six connections; a connection made for one side can be reused on the other (same Vault, different mount).

The connect form asks the chosen Vault which sign-in methods it advertises (`sys/internal/ui/mounts`, no token needed, the same call the Vault UI's login screen makes) and lists them. OIDC is preselected when it's offered.

| Method | You enter | Token revoked on *Sign out*? |
|---|---|---|
| [Token](#token) | a Vault token | no (you supplied it) |
| [Username / LDAP](#username-and-ldap) | username, password, optional mount path | yes |
| [OIDC](#oidc-redirect) | optional mount path and role, then sign in at your IdP | yes |
| [Kubernetes](#kubernetes-service-account) | mount path and role name | yes |

Tokens are kept only in the encrypted session cookie (see [security](security.md)). The connection chip shows the identity Vault reports (`display_name`), the policies, and when the token expires.

## Token

Paste any Vault token. The tool checks it with `auth/token/lookup-self` and never revokes it, because you may still be using it elsewhere.

## Username and LDAP

Uses `auth/<mount>/login/<username>`. The mount defaults to `userpass` or `ldap`; change it in **Auth mount path** if yours is mounted elsewhere. The password is sent to Vault once and not kept.

## OIDC (redirect)

The same flow as the Vault UI's OIDC login:

1. **Continue with OIDC** asks Vault for the identity provider's login URL (`auth/<mount>/oidc/auth_url`), passing this tool's callback and a random client nonce.
2. The pending login (Vault's `state`, the nonce, which Vault and which side) is stored in the encrypted session cookie: **single use, valid for 10 minutes**. The whole page then goes to the identity provider.
3. The provider redirects back to `/api/auth/oidc/callback`. The `state` must match the pending login, and Vault exchanges the code (with the nonce) for a token.
4. You're back in the tool, with the new connection selected on the side you started from. Any failure shows up as a readable message.

### Vault-side setup

The role's `allowed_redirect_uris` **must include the tool's callback**, built from [`LOCKSTEP_PUBLIC_URL`](configuration.md):

```sh
vault auth enable oidc
vault write auth/oidc/config \
    oidc_discovery_url="https://idp.example.com" \
    oidc_client_id="vault" oidc_client_secret="…" \
    default_role="default"
vault write auth/oidc/role/default \
    role_type=oidc user_claim=email \
    allowed_redirect_uris="https://lockstep.example.com/api/auth/oidc/callback" \
    allowed_redirect_uris="https://vault.example.com/ui/vault/auth/oidc/oidc/callback" \
    token_policies="lockstep-read"

# Optional: show the method on login screens (the Vault UI and this tool)
vault auth tune -listing-visibility=unauth oidc/
```

The identity provider must also allow the tool's callback as a redirect URI for that client. JWT auth mounts configured for the OIDC flow (`role_type=oidc`) work the same way.

## Kubernetes service account

When the tool runs in Kubernetes, it can sign in to a Vault **as its own pod's service account**, through Vault's `kubernetes` auth method. You choose the **mount path** (default `kubernetes`) and the **role name** for each Vault login.

### What happens

1. The tool reads its service account token from `/var/run/secrets/kubernetes.io/serviceaccount/token`. It reads the file **fresh on every login**, because projected tokens are rotated by the kubelet.
2. It calls `auth/<mount>/login` with `{"role": "<role>", "jwt": "<token>"}`.
3. Vault validates the token through the cluster's **TokenReview** API, checks that the service account matches the role's `bound_service_account_names` and `bound_service_account_namespaces`, and returns a Vault token with the role's policies.
4. The connection shows the identity as `kubernetes-<namespace>-<serviceaccount>`. The Vault token is revoked on *Sign out*.

### ⚠️ It's the tool's identity, not yours

Anyone who can open the tool and choose Kubernetes gets **that service account's Vault access**, and copies are audit-logged under the service account (`"target_auth": "kubernetes"`), not the person. That's why the feature is opt-in:

| Setting | Default | Effect |
|---|---|---|
| `LOCKSTEP_K8S_AUTH_ENABLED` | `false` | Off unless set to `true`. The option only appears in the UI when it's enabled **and** the token file exists |
| `LOCKSTEP_K8S_AUTH_ROLES` | *(any)* | Comma-separated or JSON list of Vault role names users may pick. The UI then offers a drop-down, and the server rejects any other role |
| `LOCKSTEP_K8S_AUTH_MOUNT` | `kubernetes` | Mount path prefilled in the UI |
| `LOCKSTEP_K8S_TOKEN_PATH` | `/var/run/secrets/kubernetes.io/serviceaccount/token` | Where to read the token |

Recommendations:
- Give the service account's roles **read-only** policies unless the tool is meant to sync. Prefer per-user methods (OIDC) for anything that writes.
- Use `LOCKSTEP_K8S_AUTH_ROLES` to pin exactly which roles the UI may use.
- Restrict who can reach the tool (ingress auth, network policy), since reaching it is enough to use the service account.

The form says which service account it will act as, and that it isn't your identity.

### Vault-side setup

**Vault running in the same cluster** can use its own pod's credentials to call TokenReview:

```sh
vault auth enable kubernetes
vault write auth/kubernetes/config kubernetes_host="https://kubernetes.default.svc"
```

**Vault running elsewhere** needs the cluster's API address, its CA, and a token from a service account allowed to call TokenReview (`system:auth-delegator`):

```sh
kubectl -n lockstep create serviceaccount vault-reviewer
kubectl create clusterrolebinding vault-reviewer-auth-delegator \
    --clusterrole=system:auth-delegator --serviceaccount=lockstep:vault-reviewer
kubectl -n lockstep create token vault-reviewer --duration=8760h > reviewer.jwt   # or a long-lived token Secret

vault auth enable kubernetes
vault write auth/kubernetes/config \
    kubernetes_host="https://k8s-api.example.com:6443" \
    kubernetes_ca_cert=@ca.crt \
    token_reviewer_jwt=@reviewer.jwt \
    disable_local_ca_jwt=true
```

Then a role bound to the tool's service account (namespace and name as deployed):

```sh
vault write auth/kubernetes/role/lockstep-read \
    bound_service_account_names=lockstep \
    bound_service_account_namespaces=lockstep \
    token_policies=lockstep-read \
    token_ttl=1h

vault auth tune -listing-visibility=unauth kubernetes/   # optional: advertise it
```

Do this on each Vault you want to reach this way (Vault A and Vault B can use different roles and mount paths). Example policies are in [security.md](security.md#vault-policies).

### Trying it locally

`make up-k8s` runs the normal stack plus a real **k3s** API server:

- a setup job creates the namespace `lockstep`, the service account `lockstep/lockstep`, and a token reviewer with `system:auth-delegator`, then mounts a token into the app **at the in-cluster path**
- both demo Vaults get `kubernetes` auth pointing at k3s, with three roles:

| Role | Bound to | Policy |
|---|---|---|
| `lockstep-reader` | `lockstep/lockstep` | read-only |
| `lockstep-admin` | `lockstep/lockstep` | admin |
| `other-app` | `lockstep/other-app` | read-only. The tool's own account is refused, showing what a mismatched role looks like |
| `lockstep-helm` | `lockstep-helm/lockstep` | read-only, for the Helm chart installed by `make helm-test` |

Choose **Kubernetes** on the connect form, keep the mount `kubernetes`, enter `lockstep-reader`, and connect. `make test-k8s` runs the test suite including real logins through k3s.
