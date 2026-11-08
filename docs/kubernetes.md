# Deploying on Kubernetes

Lockstep is one stateless container, so any number of replicas can serve any request:

- **no local state:** sessions, including Vault tokens, live in an encrypted, httpOnly cookie
- **environment-only configuration:** everything is set through `LOCKSTEP_*` variables
- **non-root and distroless:** it runs as UID 65532 on a Red Hat Hardened Image with no shell, works with a read-only root filesystem, and listens on port 8080
- **probes:** `GET /healthz` (liveness) and `GET /readyz` (readiness)

## With Helm (recommended)

```sh
podman build -t registry.example.com/lockstep:0.1.0 . && podman push registry.example.com/lockstep:0.1.0

helm upgrade --install lockstep ./charts/lockstep -n lockstep --create-namespace -f my-values.yaml
helm test lockstep -n lockstep
```

```yaml
# my-values.yaml
image:
  repository: registry.example.com/lockstep
publicUrl: https://lockstep.example.com
vaults:
  - {name: Production, url: https://vault.prod.example.com}
  - {name: Staging, url: https://vault.staging.example.com}
ingress:
  enabled: true
  className: nginx
  hosts: [{host: lockstep.example.com, paths: [{path: /, pathType: Prefix}]}]
  tls: [{secretName: lockstep-tls, hosts: [lockstep.example.com]}]
```

The [chart README](../charts/lockstep/README.md) has every value and more examples (private CA, NetworkPolicy, Kubernetes auth).

## Checklist

1. **Image:** build it from this repository and push it where your cluster can pull it. Set `image.repository` (and `image.digest` for an immutable deployment).
2. **Vaults:** list them in `vaults`. `allowCustomConnections` is **off** in the chart, so the pods only call Vaults you list.
3. **TLS:** terminate it at the ingress, and keep `session.cookieSecure: true`.
4. **Private CA:** if your Vaults use one, put the bundle in a ConfigMap or Secret and set `vaultTls.caBundle`.
5. **OIDC (optional):** set `publicUrl` and add `<publicUrl>/api/auth/oidc/callback` to the Vault role's `allowed_redirect_uris` ([details](authentication.md#oidc-redirect)).
6. **Kubernetes auth (optional):** decide whether users may act as the release's service account. If so, set `kubernetesAuth.enabled: true`, pin `kubernetesAuth.roles`, and bind the roles in Vault to `<namespace>/<release name>` ([details](authentication.md#kubernetes-service-account)). Without it, the service account token isn't mounted at all.
7. **Shared comparison profiles (optional):** list the team's path mappings and ignore rules in `profiles`, so everyone compares environments the same way.
8. **Restrict access** to the UI (ingress authentication, `networkPolicy`). That matters most with Kubernetes auth on, since reaching the UI is enough to use the service account.
9. **Session key:** the chart generates one and keeps it across upgrades. To manage it yourself (e.g. from an external secret store), set `session.existingSecret`. Every replica must use the same key; changing it signs everyone out.

## Audit log

Copies are logged to **stdout** as one JSON object per line (`"event": "sync.apply"`): identities and their auth methods, Vault, mount, path, keys, versions, outcome. Values are never logged. Ship container logs to your log platform and filter on that event. See [usage](usage.md#audit-log) for the format.

## Without Helm

Render the chart once and apply the manifests with your own tooling:

```sh
helm template lockstep ./charts/lockstep -n lockstep -f my-values.yaml > lockstep.yaml
```

The generated session key Secret then changes each time you render. Create your own Secret instead and set `session.existingSecret`.

## How the chart is tested

`make chart-check` (in CI) lints the chart, validates the rendered objects against the Kubernetes schemas, and checks its guards. `make helm-test` installs it into a real k3s cluster: it signs in to Vault with Kubernetes auth as the chart's own service account, confirms the replicas share sessions, runs a comparison, and checks that an upgrade keeps the session key. Trivy scans the rendered chart for misconfigurations on every PR.
