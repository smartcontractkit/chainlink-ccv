#!/usr/bin/env bash
# Deletes pods chainlink-ccv-0..20 so their controller recreates them.
# Usage: ./restart-ccv-pods.sh [--dry-run] [--yes]
set -euo pipefail

NAMESPACE="${NAMESPACE:-chainlink-ccv}"
FIRST=0
LAST=20
DRY_RUN=false
ASSUME_YES=false
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=true ;;
    --yes) ASSUME_YES=true ;;
    *) echo "unknown argument: $arg" >&2; exit 1 ;;
  esac
done

pods=()
for i in $(seq "$FIRST" "$LAST"); do
  pod=$(kubectl get pods -n "$NAMESPACE" -o name \
    | grep -E "^pod/chainlink-ccv-${i}-[a-z0-9]+-[a-z0-9]+$" | head -n1 | sed 's#^pod/##' || true)
  if [[ -z "$pod" ]]; then
    echo "chainlink-ccv-${i}: no pod found, skipping" >&2
    continue
  fi
  pods+=("$pod")
done

if [[ ${#pods[@]} -eq 0 ]]; then
  echo "no pods found" >&2
  exit 1
fi

echo "Pods to delete in namespace $NAMESPACE:"
printf '  %s\n' "${pods[@]}"

if $DRY_RUN; then
  echo "dry run, nothing deleted"
  exit 0
fi

if ! $ASSUME_YES; then
  read -r -p "Delete ${#pods[@]} pods? [y/N] " answer
  [[ "$answer" =~ ^[Yy]$ ]] || { echo "aborted"; exit 1; }
fi

for pod in "${pods[@]}"; do
  kubectl delete pod "$pod" -n "$NAMESPACE" --wait=false
done
