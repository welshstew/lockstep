# Lockstep Helm chart

Deploys [Lockstep](../../README.md): compare, inspect and sync KV secrets across HashiCorp Vault clusters.

```sh
helm upgrade --install lockstep oci://ghcr.io/welshstew/charts/lockstep --version 0.11.0 \
  -n lockstep --create-namespace -f my-values.yaml
helm test lockstep -n lockstep
```

From a checkout, use `./charts/lockstep` instead of the `oci://` reference. The chart runs the signed release image `ghcr.io/welshstew/lockstep` at the chart's `appVersion` unless you set `image.*`.

The smallest working values:

```yaml
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
| `image.repository` | `ghcr.io/welshstew/lockstep` | Image to run. Release images are multi-arch and signed; set your own registry to run your own build or a mirror |
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
| `customUrlPatterns` | `[]` | Regexes a custom address's origin (`scheme://host[:port]`) must fully match |
| `customAllowPrivate` | `false` | Let custom addresses resolve to private, loopback or link-local addresses (an internal Vault). Off, they must be public |
| `maxTreeSecrets` | `5000` | Per side, most secrets listed in one comparison |
| `policyPatterns` | `[]` | Shared suggestion patterns for **Build & suggest**: `name`, `layout` (`{app}/{env}/**`), `values`, `policies` (`name`, `rules` of `where`/`can`), `compare` |
| `configProfiles` | `[]` | Shared configuration profiles for the Configuration tab: `name`, `mappings` (mount paths, `left`/`right` with `*`), `rewrites` (`find`/`replace` on the left side's values), `ignore` (paths) |
| `policyProfiles` | `[]` | Shared policy profiles for comparing policies across Vaults: `name`, `mappings` (`left`/`right` with `*`), `rewrites` (`find`/`replace`), `ignore` |
| `policyApply` | `on` | Write ACL policies and auth roles from the Policies tab; `off` where Terraform owns them |
| `auditReveals` | `off` | Audit-log a `secret.reveal` event whenever a response carries secret values (who, where, key names; never values) |
| `apiDocs` | `on` | The interactive API documentation (Swagger UI at `/api/docs`, and `/api/openapi.json`). `off` hides both |
| `userWrite` | `off` | Create userpass users and reset their passwords from Policies › Roles (for development Vaults) |
| `readOnly` | `false` | Look-only Lockstep: every write is hidden and refused |
| `allowClipboard` | `true` | Offer **Copy** next to shown values in Browse |
| `logging.level` | `info` | Server log level: `debug`, `info`, `warning`, `error`. `debug` adds every call to a Vault |
| `logging.format` | `text` | `text` or `json` (one object per line, for log collectors) |
| `metrics.enabled` | `false` | Prometheus metrics at `/metrics`: requests, Vault calls, sign-ins, 429s. No paths or users in labels |
| `metrics.tokenSecret.name` / `.key` | `""` / `token` | A Secret with a bearer token Prometheus must send |
| `metrics.serviceMonitor.enabled` / `.interval` / `.labels` | `false` / `30s` / `{}` | A ServiceMonitor for the Prometheus Operator (needs its CRDs) |
| `driftCheck.enabled` | `false` | A CronJob that runs `lockstep compare` on a schedule and fails on drift. See [drift monitoring](../../docs/drift-monitoring.md) |
| `driftCheck.schedule` / `.suspend` | `17 * * * *` / `false` | |
| `driftCheck.left` / `.right` | | `addr`, `mount`, `prefix`, `namespace`, `name` (metrics label), and `role` + `authMount` (kubernetes auth as the job's service account) or `tokenSecret.name`/`.key` (a Secret with a Vault token) |
| `driftCheck.profile` | `""` | A name from `profiles` |
| `driftCheck.baseline` / `.baselineConfigMap.name` / `.key` | `""` | Accepted drift from `lockstep baseline update`: the JSON itself, or your ConfigMap (one or the other) |
| `driftCheck.failOn` | `""` | `any`, `new` or `changed` (default: `new` with a baseline, `any` without) |
| `driftCheck.waivers` | `[]` | `path`, `key`, `owner`, `reason`, `expires` (`YYYY-MM-DD`); an expired waiver fails the run |
| `driftCheck.pushgateway.url` / `.job` | `""` / `lockstep` | Push the drift gauges to a Prometheus Pushgateway |
| `driftCheck.extraArgs` | `[]` | More `lockstep compare` options |
| `driftCheck.serviceAccount.create` / `.name` / `.annotations` | `true` / `<release>-drift-check` / `{}` | The job's own service account: bind your Vault role to it |
| `driftCheck.egress` | `[]` | With `networkPolicy.enabled`: egress rules for the job beyond DNS and `vaultEgress`, e.g. to the Pushgateway |
| `driftCheck.resources`, `.concurrencyPolicy`, `.activeDeadlineSeconds`, `.successfulJobsHistoryLimit`, `.failedJobsHistoryLimit` | see `values.yaml` | |
| `allowDestroy` | `true` | Offer **Destroy** (every version and the metadata of a secret, can't be undone). Vault policies still decide who may |
| `exportMode` | `encrypted` | Secret-engine exports (they hold values): `encrypted` (only with a one-time key), `any` (users choose encrypted or plain) or `off`. A Vault's own `exportMode` under `vaults` replaces it for that Vault |
| `exportRecipients` | `[]` | Teams an export can be encrypted to: `name` and `recipients` (age public keys) |
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
| `profiles` | `[]` | Shared [comparison profiles](../../docs/usage.md#comparison-profiles), read-only for users: `name`, optional `description`, `leftMount`/`leftPrefix`/`rightMount`/`rightPrefix`, and `rules` (`mappings[].left/right`, `ignoreKeys[].key/path`, `ignorePaths[]`, `rewrites[].left/right`). See the example below |
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
