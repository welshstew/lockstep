#!/usr/bin/env bash
# Install the Helm chart into the dev k3s cluster (podman compose --profile k8s) and test it
# for real: helm test, then an in-cluster check that signs in to the demo Vaults with
# Kubernetes auth as the chart's own service account, and an upgrade that must keep the
# generated session key.   make helm-test
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck disable=SC1091
source scan/versions.env
ENGINE=${CONTAINER_ENGINE:-podman}
K3S=lockstep-k3s-1
NS=lockstep-helm
WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT
log() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
k() { "$ENGINE" exec "$K3S" kubectl "$@"; }

log "Stack with k3s, and the current app image"
"$ENGINE" compose --profile k8s up --build -d >/dev/null 2>&1
"$ENGINE" compose --profile k8s run --rm k8s-vault >/dev/null   # (re)applies the Vault roles
until k get --raw /readyz >/dev/null 2>&1; do sleep 2; done
APP_IMAGE=$("$ENGINE" compose images app --format json 2>/dev/null | python3 -c "import json,sys; d=json.load(sys.stdin); d=d[0] if isinstance(d,list) else d; print(d.get('ID') or d.get('Id'))")
"$ENGINE" tag "$APP_IMAGE" localhost/lockstep:0.1.0
"$ENGINE" save localhost/lockstep:0.1.0 | "$ENGINE" exec -i "$K3S" ctr -n k8s.io images import - >/dev/null

"$ENGINE" exec "$K3S" cat /k3s-out/kubeconfig.yaml | sed 's#https://127.0.0.1:6443#https://k3s:6443#' > "$WORK/kubeconfig"
helm() {
  "$ENGINE" run --rm --network lockstep_default -v "$WORK/kubeconfig:/kube/config:ro,Z" -e KUBECONFIG=/kube/config \
    -v "$PWD/charts:/charts:Z" -v "$PWD/dev/k8s/helm-values.yaml:/values.yaml:ro,Z" "$HELM_IMG" "$@"
}

log "helm upgrade --install (namespace $NS)"
helm upgrade --install lockstep /charts/lockstep -n "$NS" --create-namespace -f /values.yaml --wait --timeout 4m \
  | grep -E 'STATUS|REVISION'
k -n "$NS" rollout restart deploy/lockstep >/dev/null && k -n "$NS" rollout status deploy/lockstep --timeout=180s >/dev/null

log "helm test"
helm test lockstep -n "$NS" --logs | grep -E 'Phase|ok:'

log "In-cluster check (Kubernetes auth as $NS/lockstep, shared sessions, compare, allowlist)"
"$ENGINE" exec -i "$K3S" sh -c 'cat > /tmp/incluster_check.py' < dev/k8s/incluster_check.py
k -n "$NS" delete pod probe --ignore-not-found --now >/dev/null 2>&1 || true
"$ENGINE" exec "$K3S" sh -c "kubectl -n $NS run probe --image=localhost/lockstep:0.1.0 --image-pull-policy=Never \
  --restart=Never --rm -i --quiet --command -- python -c \"\$(cat /tmp/incluster_check.py)\""

log "Upgrade keeps the generated session key"
before=$(k -n "$NS" get secret lockstep-session -o jsonpath='{.data.session-key}')
helm upgrade lockstep /charts/lockstep -n "$NS" -f /values.yaml --set replicaCount=3 --wait --timeout 4m | grep REVISION
after=$(k -n "$NS" get secret lockstep-session -o jsonpath='{.data.session-key}')
[[ "$before" == "$after" ]] || { echo "session key changed on upgrade"; exit 1; }
echo "session key kept"
helm upgrade lockstep /charts/lockstep -n "$NS" -f /values.yaml --wait --timeout 4m >/dev/null   # back to 2 replicas

echo; echo "HELM TEST: PASS   (remove with: podman exec $K3S kubectl delete namespace $NS)"
