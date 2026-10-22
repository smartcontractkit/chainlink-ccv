#!/usr/bin/env bash
# Sets disabled=false in ccv_chain_statuses for the given chain/verifiers on chainlink-ccv-0..20.
# Usage: ./enable-chain-status.sh [--dry-run]
set -euo pipefail

NAMESPACE="${NAMESPACE:-chainlink-ccv}"
CONTAINER="${CONTAINER:-chainlink-cluster}"
SECRET_PATH="${SECRET_PATH:-/v2Secret/secret.toml}"
CHAIN_SELECTOR="${CHAIN_SELECTOR:-16015286601757825753}"
VERIFIER_IDS=("aggregator-1-default-verifier" "aggregator-2-default-verifier")
FIRST=0
LAST=20
DRY_RUN=false
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=true

in_list=$(printf "'%s'," "${VERIFIER_IDS[@]}")
in_list="${in_list%,}"

for i in $(seq "$FIRST" "$LAST"); do
  name="chainlink-ccv-${i}"
  pod=$(kubectl get pods -n "$NAMESPACE" -o name \
    | grep -E "^pod/${name}-[a-z0-9]+-[a-z0-9]+$" | head -n1 | sed 's#^pod/##' || true)
  if [[ -z "$pod" ]]; then
    echo "[$name] no pod found, skipping" >&2
    continue
  fi

  # Reads [Database] URL from the secrets file; the value is never printed.
  db_url=$(kubectl exec "$pod" -c "$CONTAINER" -n "$NAMESPACE" -- cat "$SECRET_PATH" \
    | awk '/^\[/{s=($0=="[Database]")} s && /^[[:space:]]*URL[[:space:]]*=/{sub(/^[^=]*=[[:space:]]*/,""); gsub(/^"|"$/,""); print; exit}')
  if [[ -z "$db_url" ]]; then
    echo "[$name] no [Database] URL in $SECRET_PATH, skipping" >&2
    continue
  fi

  # Locate the schema that holds ccv_chain_statuses (default search_path first).
  table=$(psql "$db_url" -Atqc "SELECT format('%I.%I', schemaname, tablename) FROM pg_tables WHERE tablename='ccv_chain_statuses' ORDER BY (schemaname='public') DESC LIMIT 1" || true)
  if [[ -z "$table" ]]; then
    echo "[$name] ccv_chain_statuses not found, skipping" >&2
    continue
  fi

  if $DRY_RUN; then
    echo "[$name] ($table) dry run, current rows:"
    psql "$db_url" -c "SELECT chain_selector, verifier_id, finalized_block_height, disabled FROM $table WHERE chain_selector::text = '$CHAIN_SELECTOR' AND verifier_id IN ($in_list)"
  else
    echo "[$name] ($table) updating:"
    psql "$db_url" -c "UPDATE $table SET disabled = false, updated_at = NOW() WHERE chain_selector::text = '$CHAIN_SELECTOR' AND verifier_id IN ($in_list) RETURNING chain_selector, verifier_id, finalized_block_height, disabled"
  fi
done
