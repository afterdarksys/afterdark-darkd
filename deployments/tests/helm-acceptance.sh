#!/usr/bin/env bash
# Requires an already built local Docker image. Uses only its own kind cluster.
set -euo pipefail
image=${1:?usage: helm-acceptance.sh local-image:tag}
root=$(cd "$(dirname "$0")/../.." && pwd)
work=$(mktemp -d)
cluster="ads-test-$$"
export KUBECONFIG="$work/kubeconfig"
cleanup() { kind delete cluster --name "$cluster"; rm -rf "$work"; }
trap cleanup EXIT
kind create cluster --name "$cluster" --wait 120s
kind load docker-image "$image" --name "$cluster"
helm install acceptance "$root/deployments/helm/darkd" --namespace ads-test --create-namespace \
  --set "image.repository=${image%:*}" --set "image.tag=${image##*:}" --wait --timeout 180s
pod=acceptance-darkd-0
kubectl -n ads-test exec "$pod" -- afterdark-darkdadm status --json \
  --socket /var/run/afterdark/ipc/darkd.sock --token-file /var/lib/afterdark/auth/.auth_token > "$work/status.json"
python3 - "$work/status.json" <<'PY'
import json,sys
status=json.load(open(sys.argv[1]))
assert status['daemon']['state']=='running', status
print('Authenticated IPC works; aggregate service health:',status['health']['status'])
PY
kubectl -n ads-test exec "$pod" -- sh -c 'sha256sum /var/lib/afterdark/auth/.auth_token > /var/lib/afterdark/token.sha'
kubectl -n ads-test delete pod "$pod"
kubectl -n ads-test rollout status statefulset/acceptance-darkd --timeout=120s
kubectl -n ads-test exec "$pod" -- sha256sum -c /var/lib/afterdark/token.sha
helm uninstall acceptance --namespace ads-test
kubectl -n ads-test wait --for=delete pod/"$pod" --timeout=90s
# StatefulSet PVCs deliberately survive uninstall; remove only this disposable cluster's claim.
kubectl -n ads-test delete pvc data-acceptance-darkd-0
