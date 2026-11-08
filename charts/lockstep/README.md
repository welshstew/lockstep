# Lockstep Helm chart

Deploys [Lockstep](../../README.md): compare, inspect and sync KV secrets across HashiCorp Vault clusters.

```sh
helm upgrade --install lockstep ./charts/lockstep -n lockstep --create-namespace -f my-values.yaml
helm test lockstep -n lockstep
```

The smallest working values:

```yaml
image:
  repository: registry.example.com/lockstep   # where you pushed the image
vaults:
  - name: Production
    url: https://vault.prod.example.com
```

## What you get

- **Deployment** with 2 replicas, hardened by default: non-root (65532), read-only root filesystem, all capabilities dropped, `RuntimeDefault` seccomp, no privilege escalation. Startup, liveness (`/healthz`) and readiness (`/readyz`) probes.
- **Session key Secret:** generated on first install and **kept on upgrade** (a new key would sign everyone out). You can bring your own with `session.existingSecret`.
- **ServiceAccount**, with its token mounted **only if Kubernetes auth is enabled** (`serviceAccount.automountToken: auto`).
- **Service** (ClusterIP); optional **Ingress**, **NetworkPolicy**, and a **PodDisruptionBudget** (when replicas > 1).
- **Helpful `NOTES.txt`:** warns when `publicUrl` is missing for OIDC, and names the exact service account to bind in Vault when Kubernetes auth is on.
- **Validation:** `values.schema.json` rejects unknown keys and bad values (e.g. a Vault URL that isn't http(s)). Template guards catch combinations that would only fail at runtime.

## Values

| Key | Default | Description |
|---|---|---|
| `image.repository` | `lockstep` | Image to run. Build it with `podman build -t <registry>/lockstep:<version> .` and push it |
| `image.tag` | chart `appVersion` | |
| `image.digest` | `""` | `sha256:…`; overrides the tag |
| `image.pullPolicy` | `IfNotPresent` | |
| `imagePullSecrets` | `[]` | |
| `replicaCount` | `2` | Replicas share sessions through the session key |
| `publicUrl` | `""` | URL users open. **Required for OIDC**: add `<publicUrl>/api/auth/oidc/callback` to the Vault role's `allowed_redirect_uris` |
| `session.existingSecret` | `""` | Use your own Secret for the session key (at least 32 characters) |
| `session.existingSecretKey` | `session-key` | Key within that Secret |
| `session.ttlSeconds` | `28800` | Session lifetime |
| `session.cookieSecure` | `true` | Keep `true` behind TLS. `false` only for plain-HTTP testing (e.g. `kubectl port-forward`) |
| `vaults` | `[]` | Vaults offered in the UI: `name`, `url` (how pods reach Vault), optional `browserUrl`, `namespace` |
| `allowCustomConnections` | `false` | Let users type any Vault address (the pods will call it) |
| `customUrlPatterns` | `[]` | Regexes a custom address must fully match |
| `maxTreeSecrets` | `5000` | Per side, most secrets listed in one comparison |
| `vaultTls.verify` | `true` | |
| `vaultTls.caBundle.configMap` / `.secret` | `""` | A PEM CA bundle for private-CA Vaults (one or the other) |
| `vaultTls.caBundle.key` | `ca.crt` | Key in that ConfigMap or Secret |
| `kubernetesAuth.enabled` | `false` | Let users sign in to Vault **as this release's service account**. Read the warning below |
| `kubernetesAuth.roles` | `[]` | Vault roles users may pick (empty = any) |
| `kubernetesAuth.mount` | `kubernetes` | Default auth mount path in the UI |
| `serviceAccount.create` | `true` | |
| `serviceAccount.name` | release full name | |
| `serviceAccount.annotations` | `{}` | |
| `serviceAccount.automountToken` | `auto` | `auto` = only with Kubernetes auth; or `true`/`false` |
| `profiles` | `[]` | Shared [comparison profiles](../../docs/usage.md#comparison-profiles), read-only for users: `name`, optional `description`, `leftMount`/`leftPrefix`/`rightMount`/`rightPrefix`, and `rules` (`mappings[].left/right`, `ignoreKeys[].key/path`, `ignorePaths[]`). See the example below |
| `extraEnv` | `[]` | Extra container env vars |
| `podAnnotations`, `podLabels` | `{}` | |
| `podSecurityContext`, `securityContext` | hardened | See `values.yaml` |
| `resources` | 50m CPU / 128Mi request, 512Mi memory limit | No CPU limit, to avoid throttling |
| `service.type` / `.port` / `.annotations` | `ClusterIP` / `80` / `{}` | |
| `ingress.*` | disabled | `className`, `annotations`, `hosts[].paths[]`, `tls[]` |
| `podDisruptionBudget.enabled` / `.minAvailable` | `true` / `1` | Created only when `replicaCount > 1` |
| `networkPolicy.enabled` | `false` | Ingress only on port 8080 (optionally only from `ingressFrom`); egress only to DNS (`allowDns`) and your `vaultEgress` rules |
| `nodeSelector`, `tolerations`, `affinity`, `topologySpreadConstraints`, `priorityClassName` | empty | |

## Kubernetes auth: read this first

With `kubernetesAuth.enabled: true`, anyone who can open Lockstep can sign in to Vault as **this release's service account** (`<namespace>/<release full name>`), not as themselves, and copies are audit-logged under it. Pin the roles with `kubernetesAuth.roles`, give those roles read-only policies unless the tool is meant to sync, and restrict who can reach the UI. The Vault side:

```sh
vault write auth/kubernetes/role/lockstep-read \
    bound_service_account_names=lockstep bound_service_account_namespaces=lockstep \
    token_policies=lockstep-read token_ttl=1h
```

Full details: [docs/authentication.md](../../docs/authentication.md#kubernetes-service-account).

## Examples

**OIDC behind an ingress with TLS:**

```yaml
publicUrl: https://lockstep.example.com
ingress:
  enabled: true
  className: nginx
  hosts: [{host: lockstep.example.com, paths: [{path: /, pathType: Prefix}]}]
  tls: [{secretName: lockstep-tls, hosts: [lockstep.example.com]}]
```

**Private CA for Vault:**

```sh
kubectl -n lockstep create configmap corporate-ca --from-file=ca.crt=corporate-ca.pem
```

```yaml
vaultTls:
  caBundle: {configMap: corporate-ca, key: ca.crt}
```

**Shared comparison profile:** pair each service's prod secrets in one Vault with its staging secrets in another, and ignore keys that differ by design. Users pick it from the profile list; the server checks the rules at startup, so a bad pattern stops the pod with a clear message in its log.

```yaml
profiles:
  - name: Prod vs staging services
    description: services/<name>/prod against services/<name>/staging
    leftMount: app-config
    rightMount: app-config
    rules:
      mappings:
        - {left: "services/*/prod/**", right: "services/*/staging/**"}
      ignoreKeys:
        - {key: host, path: "services/**"}
        - {key: "*_url"}
      ignorePaths: ["legacy/**"]
```

**Locked-down network:**

```yaml
networkPolicy:
  enabled: true
  ingressFrom:
    - namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: ingress-nginx}}
  vaultEgress:
    - to: [{ipBlock: {cidr: 10.20.0.0/16}}]
      ports: [{port: 8200, protocol: TCP}]
```

## Testing the chart

- `make chart-check`: lint, render with minimal and all-options values, validate every object against the Kubernetes schemas (kubeconform), and check the guards reject bad values. Runs in CI.
- `make helm-test`: installs into the dev k3s cluster (`make up-k8s`) and tests it for real. It runs `helm test`, then an in-cluster check that signs in to the demo Vaults with Kubernetes auth as the chart's service account, confirms the replicas share sessions, runs a comparison, checks the role allowlist, and makes sure an upgrade keeps the session key.
- `make scan`: Trivy scans the rendered chart for Kubernetes misconfigurations (both value sets).
