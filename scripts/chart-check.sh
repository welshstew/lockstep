#!/usr/bin/env bash
# Static checks for the Helm chart (no cluster needed):
#   - helm lint --strict with the minimal and the everything-on values
#   - render both and validate every object against the Kubernetes schemas (kubeconform)
#   - the chart's own guards must reject bad values, with a clear message
#   make chart-check      SCAN_NATIVE=1 uses helm/kubeconform from PATH (CI)
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck disable=SC1091
source scan/versions.env
ENGINE=${CONTAINER_ENGINE:-$(command -v podman >/dev/null && echo podman || echo docker)}
CHART=charts/lockstep

helm() {
  if [[ ${SCAN_NATIVE:-0} == 1 ]]; then command helm "$@"
  else "$ENGINE" run --rm -i -v "$PWD/charts:/src/charts:Z" -w /src "$HELM_IMG" "$@"; fi
}
kubeconform() {
  if [[ ${SCAN_NATIVE:-0} == 1 ]]; then command kubeconform "$@"
  else "$ENGINE" run --rm -i "$KUBECONFORM_IMG" "$@"; fi
}

fail=0
for v in minimal full; do
  echo "== lint + schema: ci/$v-values.yaml"
  helm lint "$CHART" --strict -f "$CHART/ci/$v-values.yaml" | tail -1
  helm template t "$CHART" -n lockstep -f "$CHART/ci/$v-values.yaml" \
    | kubeconform -strict -summary -ignore-missing-schemas=false -skip ServiceMonitor - || fail=1
done

expect_fail() {  # expect_fail "<message fragment>" <helm template args…>
  local want=$1; shift
  if out=$(helm template t "$CHART" "$@" 2>&1); then
    echo "!! expected failure ($want) but rendering succeeded"; fail=1
  elif grep -q -- "$want" <<<"$out"; then
    echo "ok rejects: $want"
  else
    echo "!! wrong error for ($want):"; echo "$out" | tail -2; fail=1
  fi
}
echo "== guards"
expect_fail "configure at least one entry in vaults"
expect_fail "needs the service account token" -f "$CHART/ci/minimal-values.yaml" \
  --set kubernetesAuth.enabled=true --set serviceAccount.automountToken=false
expect_fail "does not match pattern" -f "$CHART/ci/minimal-values.yaml" --set 'vaults[0].url=ftp://x'
expect_fail "additional properties" -f "$CHART/ci/minimal-values.yaml" --set typo=1
expect_fail "not both" -f "$CHART/ci/minimal-values.yaml" --set vaultTls.caBundle.configMap=a --set vaultTls.caBundle.secret=b

expect_fail "driftCheck.left needs addr and mount" -f "$CHART/ci/minimal-values.yaml" --set driftCheck.enabled=true
expect_fail "driftCheck.right: set role" -f "$CHART/ci/minimal-values.yaml" --set driftCheck.enabled=true \
  --set driftCheck.left.addr=https://a --set driftCheck.left.mount=m --set driftCheck.left.role=r \
  --set driftCheck.right.addr=https://b --set driftCheck.right.mount=m
expect_fail "failOn new needs a baseline" -f "$CHART/ci/full-values.yaml" --set driftCheck.baselineConfigMap.name= \
  --set driftCheck.failOn=new
expect_fail "not both" -f "$CHART/ci/full-values.yaml" --set driftCheck.baseline=x

expect_fail "is used twice" -f "$CHART/ci/minimal-values.yaml" --set 'profiles[0].name=p' --set 'profiles[1].name=p'
expect_fail "additional properties" -f "$CHART/ci/minimal-values.yaml" --set 'profiles[0].name=p' --set 'profiles[0].rules.ignore_paths[0]=x'
expect_fail "missing property 'right'" -f "$CHART/ci/minimal-values.yaml" --set 'profiles[0].name=p' --set 'profiles[0].rules.mappings[0].left=a/*'

# The rendered profiles must be exactly what the app parses (snake_case keys, defaults filled in).
want='[{"left_mount":"app-config","name":"Prod vs staging","description":"services/<name>/prod against services/<name>/staging","right_mount":"app-config","rules":{"ignore_keys":[{"key":"host","path":"services/**"},{"key":"*_url","path":"**"}],"ignore_paths":["legacy/**"],"mappings":[{"left":"services/*/prod/**","right":"services/*/staging/**"}],"rewrites":[{"left":"prod","right":"staging"}]}},{"name":"Whole mount, nothing ignored","rules":{"ignore_keys":[],"ignore_paths":[],"mappings":[],"rewrites":[]}}]'
got=$(helm template t "$CHART" -f "$CHART/ci/full-values.yaml" --show-only templates/deployment.yaml \
  | grep -A1 -- "- name: LOCKSTEP_PROFILES" | sed -n 's/^ *value: //p' \
  | python3 -c 'import sys,json; print(json.dumps(json.loads(json.loads(sys.stdin.read())),sort_keys=True))')
if [[ $got == "$(python3 -c 'import json,sys; print(json.dumps(json.loads(sys.argv[1]),sort_keys=True))' "$want")" ]]; then
  echo "ok profiles render as the app expects"
else
  echo "!! LOCKSTEP_PROFILES rendered as: $got"; fail=1
fi

# The drift check runs the CLI with the options its values give, quoted for YAML
args=$(helm template t "$CHART" -f "$CHART/ci/full-values.yaml" --show-only templates/drift-check.yaml \
  | sed -n '/command: \["lockstep"\]/,/env:/p' | sed -n 's/^ *- //p' \
  | python3 -c 'import sys,json; print(" ".join(["lockstep"] + [json.loads(a) if a.startswith(chr(34)) else a for a in sys.stdin.read().splitlines()]))')
want="lockstep compare --left-addr=https://vault.prod.example.com --left-mount=app-config --left-prefix=services --left-name=prod --left-auth=kubernetes --left-auth-mount=kubernetes --left-role=lockstep-drift --right-addr=https://vault.staging.example.com --right-mount=app-config --right-prefix=services --right-namespace=team-a --right-name=staging: team a --profile=Prod vs staging --baseline=/etc/lockstep/drift/drift.json --waivers=/etc/lockstep/drift/waivers.yaml --pushgateway=http://pushgateway.monitoring:9091 --pushgateway-job=lockstep --custom-metadata"
if [[ $args == "$want" ]]; then echo "ok drift check arguments"; else echo "!! drift check runs: $args"; fail=1; fi

[[ $fail == 0 ]] && echo "CHART CHECK: PASS" || { echo "CHART CHECK: FAIL"; exit 1; }
