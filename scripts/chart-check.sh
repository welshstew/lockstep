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
    | kubeconform -strict -summary -ignore-missing-schemas=false - || fail=1
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

expect_fail "is used twice" -f "$CHART/ci/minimal-values.yaml" --set 'profiles[0].name=p' --set 'profiles[1].name=p'
expect_fail "additional properties" -f "$CHART/ci/minimal-values.yaml" --set 'profiles[0].name=p' --set 'profiles[0].rules.ignore_paths[0]=x'
expect_fail "missing property 'right'" -f "$CHART/ci/minimal-values.yaml" --set 'profiles[0].name=p' --set 'profiles[0].rules.mappings[0].left=a/*'

# The rendered profiles must be exactly what the app parses (snake_case keys, defaults filled in).
want='[{"left_mount":"app-config","name":"Prod vs staging","description":"services/<name>/prod against services/<name>/staging","right_mount":"app-config","rules":{"ignore_keys":[{"key":"host","path":"services/**"},{"key":"*_url","path":"**"}],"ignore_paths":["legacy/**"],"mappings":[{"left":"services/*/prod/**","right":"services/*/staging/**"}]}},{"name":"Whole mount, nothing ignored","rules":{"ignore_keys":[],"ignore_paths":[],"mappings":[]}}]'
got=$(helm template t "$CHART" -f "$CHART/ci/full-values.yaml" --show-only templates/deployment.yaml \
  | grep -A1 -- "- name: LOCKSTEP_PROFILES" | sed -n 's/^ *value: //p' \
  | python3 -c 'import sys,json; print(json.dumps(json.loads(json.loads(sys.stdin.read())),sort_keys=True))')
if [[ $got == "$(python3 -c 'import json,sys; print(json.dumps(json.loads(sys.argv[1]),sort_keys=True))' "$want")" ]]; then
  echo "ok profiles render as the app expects"
else
  echo "!! LOCKSTEP_PROFILES rendered as: $got"; fail=1
fi

[[ $fail == 0 ]] && echo "CHART CHECK: PASS" || { echo "CHART CHECK: FAIL"; exit 1; }
