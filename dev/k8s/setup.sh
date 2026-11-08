#!/bin/sh
# Dev only: prepare the k3s cluster for Vault's kubernetes auth method.
#   - namespace lockstep with service account "lockstep" (the comparison tool's identity)
#   - service account "vault-reviewer" with system:auth-delegator (lets Vault call TokenReview)
#   - writes the tool's token where a pod would see it (/out/sa), and the reviewer token
#     and cluster CA for Vault's config (/out/priv)
set -eu
until [ -s /k3s-out/kubeconfig.yaml ]; do sleep 2; done
# k3s writes its kubeconfig for 127.0.0.1; reach it by its compose hostname instead.
sed 's#https://127.0.0.1:6443#https://k3s:6443#' /k3s-out/kubeconfig.yaml > /tmp/kubeconfig
export KUBECONFIG=/tmp/kubeconfig
until kubectl get --raw /readyz >/dev/null 2>&1; do sleep 2; done
until kubectl -n default get serviceaccount default >/dev/null 2>&1; do sleep 2; done

apply() { kubectl "$@" --dry-run=client -o yaml | kubectl apply -f - >/dev/null; }
apply create namespace lockstep
apply -n lockstep create serviceaccount lockstep
apply -n lockstep create serviceaccount other-app
apply -n lockstep create serviceaccount vault-reviewer
apply create clusterrolebinding vault-reviewer-auth-delegator \
  --clusterrole=system:auth-delegator --serviceaccount=lockstep:vault-reviewer

mkdir -p /out/sa /out/priv
kubectl -n lockstep create token lockstep --duration=24h > /out/sa/token
printf lockstep > /out/sa/namespace
kubectl -n lockstep create token vault-reviewer --duration=48h > /out/priv/reviewer.jwt
kubectl -n lockstep create token other-app --duration=24h > /out/priv/other-app.jwt
kubectl config view --raw -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' | base64 -d > /out/priv/ca.crt
cp /out/priv/ca.crt /out/sa/ca.crt
chmod 644 /out/sa/* /out/priv/*
echo "k8s setup complete: service account lockstep/lockstep, token mounted for the app"
