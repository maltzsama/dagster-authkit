#!/usr/bin/env bash
# Lints the Helm chart, renders it for every scenario under ci/ and validates
# the output against Kubernetes schemas. Run from the repository root.
set -euo pipefail

CHART=helm/dagster-authkit
BASE="$CHART/ci/default-values.yaml"
KUBE_VERSIONS=${KUBE_VERSIONS:-"1.29.0 1.33.0"}

render() { helm template release "$CHART" -f "$BASE" "$@"; }

echo "==> helm lint"
helm lint "$CHART" -f "$BASE"

if ! command -v kubeconform >/dev/null 2>&1; then
  echo "!! kubeconform not found: rendering only, schemas are not validated"
fi

for values in "$CHART"/ci/*-values.yaml "$CHART"/ci/render/*.yaml; do
  echo "==> render $values"
  manifests=$(render -f "$values")
  if command -v kubeconform >/dev/null 2>&1; then
    for version in $KUBE_VERSIONS; do
      echo "$manifests" | kubeconform -strict -summary -kubernetes-version "$version"
    done
  fi
done

# Configurations the chart must refuse to render.
expect_failure() {
  local name=$1
  shift
  if render "$@" >/dev/null 2>&1; then
    echo "!! expected the render to fail: $name"
    exit 1
  fi
  echo "==> refused as expected: $name"
}

expect_failure "missing image.tag" --set image.tag=
expect_failure "missing secretKey" --set authkit.secretKey=
expect_failure "SQLite with several replicas" --set replicaCount=3
expect_failure "SQLite with several replicas and Redis" --set replicaCount=3 --set authkit.redisUrl=redis://redis:6379
expect_failure "SQLite with autoscaling" --set autoscaling.enabled=true
expect_failure "proxy backend without logoutUrl" --set authkit.backend=proxy
