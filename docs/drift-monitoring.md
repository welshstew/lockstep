# Drift monitoring

Lockstep compares two Vault locations when someone asks it to. To find out about drift without anyone looking, run the comparison on a schedule and alert on what it finds. Lockstep doesn't alert itself: it exits with a code, writes reports and publishes metrics. Your scheduler, Prometheus and Alertmanager do the rest. The server keeps no state for this.

- **A scheduled check:** the Helm chart's `driftCheck` CronJob runs `lockstep compare` on a schedule. It signs in to each Vault with its own service account, and pushes gauges to a Prometheus Pushgateway. A run that finds drift fails, so Kubernetes' own job metrics see it too.
- **A baseline:** checks fail only on drift the [baseline](cli.md#drift-checks-in-ci) doesn't already have, so a difference you've accepted doesn't alert every hour.
- **Server metrics:** `/metrics` on the web app (`LOCKSTEP_METRICS=on`) has requests, Vault calls, sign-ins and refusals, for dashboards and the usual service alerts.

## The drift check CronJob

```yaml
# my-values.yaml
driftCheck:
  enabled: true
  schedule: "17 * * * *"                 # hourly
  left:
    addr: https://vault.prod.example.com
    mount: app-config
    prefix: services
    name: prod                           # the label in metrics and logs
    role: lockstep-drift                 # Vault kubernetes auth role for the job's service account
  right:
    addr: https://vault.staging.example.com
    mount: app-config
    prefix: services
    name: staging
    role: lockstep-drift
  baselineConfigMap: {name: drift-baseline, key: drift.json}
  waivers:
    - {path: billing/*, key: feature_flags, owner: team-billing, reason: staging tries the new checkout, expires: "2027-01-31"}
  pushgateway:
    url: http://pushgateway.monitoring:9091
```

- **Signing in.** The job runs as its own service account, `<release>-drift-check`, separate from the web app's. On each Vault, bind a kubernetes auth role to it, with a read-only policy for the compared paths:

  ```sh
  vault policy write lockstep-drift - <<'EOF'
  path "app-config/metadata/services/*" { capabilities = ["list", "read"] }
  path "app-config/data/services/*"     { capabilities = ["read"] }
  EOF
  vault write auth/kubernetes/role/lockstep-drift \
      bound_service_account_names=lockstep-drift-check bound_service_account_namespaces=lockstep \
      token_policies=lockstep-drift token_ttl=10m
  ```

  A Vault in another cluster needs its own kubernetes auth mount pointed at this cluster (`authMount`). Or give that side `tokenSecret: {name: …, key: token}`: a Secret holding a Vault token, which the job reads as `LOCKSTEP_RIGHT_TOKEN`. Tokens from a login are revoked when the run ends.
- **The baseline.** Write it once, from a machine that can reach both Vaults, and keep it in a ConfigMap. Run the update again whenever you accept the drift as it is now:

  ```sh
  lockstep baseline update drift.json --left-addr … --right-addr … --mount app-config --prefix services
  kubectl -n lockstep create configmap drift-baseline --from-file=drift.json --dry-run=client -o yaml | kubectl apply -f -
  ```

  `baseline: '<the JSON>'` puts it in the values instead, so it's reviewed with the chart's values. Without a baseline, any drift fails the check. `failOn` takes `any`, `new` or `changed`, as `--fail-on` does.
- **What a run leaves.** The job's log has the summary: what differs, and which differences are new. Values never appear. The exit code is 0 for no new drift, 1 for drift, and 2 when the run couldn't compare. `backoffLimit` is 0, because running the check again doesn't change the answer. `profile` names one of the chart's `profiles`, and `extraArgs` adds any other `compare` option.
- **Network policy.** With `networkPolicy.enabled`, the job gets its own policy: no ingress, and egress to DNS, `networkPolicy.vaultEgress` and `driftCheck.egress`. Use `driftCheck.egress` to allow the Pushgateway.
- **Vaults with a private CA** use `vaultTls.caBundle`, like the web app.

Without the chart, run the same command from any scheduler. The image's `lockstep` entrypoint and `--left-auth kubernetes` work in any pod that mounts a service account token.

## Pushgateway gauges

`--pushgateway URL` (or `LOCKSTEP_PUSHGATEWAY_URL`) pushes these after each run. Their labels are `left`, `right`, `mount` and `prefix`. A mount or prefix that differs between the sides is written `left → right`.

| Gauge | |
|---|---|
| `lockstep_drift_keys{status}` | Differences found, by `status`: `different`, `left_only`, `right_only`, `not_compared`. One per key, or one per secret that's on one side only. |
| `lockstep_drift_new_keys` | Differences that fail the check: not in the baseline and not waived. |
| `lockstep_drift_check_failed` | 1 when the run failed the check (exit code 1). |
| `lockstep_compare_success` | 1 when the run compared, 0 when it couldn't (exit code 2: Vault unreachable, login refused…). |
| `lockstep_compare_last_success_timestamp_seconds` | When a run last compared. |
| `lockstep_compare_duration_seconds` | How long the run took. |

The grouping key is the job (`--pushgateway-job`, default `lockstep`) and the four labels, so several checks can share a Pushgateway. A run that compared replaces its group. A run that couldn't compare updates only `lockstep_compare_success` and the duration, so the last drift counts and the last success time stay. If the push itself fails, the run exits 2.

`-o drift.prom` writes the same gauges, labels included, for node_exporter's textfile collector.

## Alert rules

```yaml
groups:
  - name: lockstep-drift
    rules:
      - alert: VaultDrift
        expr: lockstep_drift_new_keys > 0
        labels: {severity: warning}
        annotations:
          summary: "{{ $value }} new differences between {{ $labels.left }} and {{ $labels.right }} ({{ $labels.mount }})"
          description: "See the drift-check job's log, or run lockstep compare with the baseline."
      - alert: VaultDriftCheckFailing
        expr: lockstep_compare_success == 0
        for: 2h
        labels: {severity: warning}
        annotations:
          summary: "The drift check {{ $labels.left }} → {{ $labels.right }} can't compare"
      - alert: VaultDriftCheckStale
        expr: time() - lockstep_compare_last_success_timestamp_seconds > 3 * 3600
        labels: {severity: warning}
        annotations:
          summary: "The drift check {{ $labels.left }} → {{ $labels.right }} hasn't compared for 3 hours"
```

Without a Pushgateway, kube-state-metrics' `kube_job_status_failed{job_name=~".*-drift-check-.*"}` shows failed runs, though it can't tell drift (exit 1) from a check that couldn't run (exit 2).

## Server metrics

`LOCKSTEP_METRICS=on` (chart value `metrics.enabled`) serves Prometheus metrics at `/metrics` on the app's port:

| Metric | Labels |
|---|---|
| `lockstep_http_requests_total`, `lockstep_http_request_duration_seconds` | `route`: the route template (`/api/connections/{conn_id}/tree`), never the real path. `method`, and `status` on the counter |
| `lockstep_vault_requests_total`, `lockstep_vault_request_duration_seconds` | `vault`: the Vault's `host:port`. `status` on the counter: Vault's HTTP status, or 0 when it couldn't be reached |
| `lockstep_signins_total` | `method` (`token`, `userpass`, `ldap`, `oidc`, `jwt`, `kubernetes`) and `outcome` (`success`, `failure`) |
| `lockstep_rate_limited_total` | `limit`: `api` (the per-client limit) or `signin` (the sign-in throttle) |

Labels never include a secret path, a user, a token or a connection ID. Counts are per process; Prometheus adds them up across replicas. Sessions live in cookies, so the server can't count active sessions: use the rate of `lockstep_signins_total` instead.

- **Protecting it.** `LOCKSTEP_METRICS_TOKEN` (chart: `metrics.tokenSecret`) makes `/metrics` require `Authorization: Bearer <token>`. Without a token, anyone who can reach the app's port can read the metrics. They hold no secrets, but they show which Vaults Lockstep talks to and how busy it is. Behind an ingress, you can also keep `/metrics` off the public host.
- **Scraping.** `metrics.serviceMonitor.enabled` creates a ServiceMonitor for the Prometheus Operator, with the bearer token when one is set. With `networkPolicy.enabled`, add Prometheus to `networkPolicy.ingressFrom`.
