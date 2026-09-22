#!/usr/bin/env bash
# Derive the authoritative end-state `evm` logpoller schema from the Chainlink node's
# migrations, by applying them to a scratch Postgres and dumping the result.
#
# Step 1 of two. This produces the raw dump; `just logpoller-schema` filters it down to the
# LogPoller objects and wraps it as a goose migration. Re-run both on every
# chainlink-evm bump when you need to see what moved upstream.
#
# Usage:
#   ./tools/logpollerschema/derive.sh /path/to/chainlink
#
# Requires: docker, pg_dump, and a chainlink checkout. The migrator that runs inside that
# checkout is copied in from migrator.go beside this script and removed again afterwards,
# so nothing is left behind in the chainlink repo.
#
# NOTE: the migrations applied are whatever the chainlink working tree is currently on.
# This script does NOT check out a ref
set -euo pipefail

CHAINLINK_REPO="${1:?usage: derive.sh /path/to/chainlink}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

CONTAINER="logpoller-schema-pg"
PGPORT="${PGPORT:-55432}"
DSN="postgres://postgres:postgres@localhost:${PGPORT}/logpollerschema?sslmode=disable"
OUT="${OUT:-${REPO_ROOT}/evm-schema}"

mkdir -p "$OUT"

cleanup() { docker rm -f "$CONTAINER" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "==> starting scratch postgres on :${PGPORT}"
cleanup
docker run -d --name "$CONTAINER" \
  -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=logpollerschema \
  -p "${PGPORT}:5432" \
  postgres:14-alpine >/dev/null

echo -n "==> waiting for postgres"
for _ in $(seq 1 60); do
  if docker exec "$CONTAINER" pg_isready -U postgres -d logpollerschema >/dev/null 2>&1; then break; fi
  echo -n "."
  sleep 1
done
echo " ready"

CHAINLINK_REF="$(cd "$CHAINLINK_REPO" && git rev-parse --short HEAD)"
if [ -n "$(cd "$CHAINLINK_REPO" && git status --porcelain --untracked-files=no)" ]; then
  CHAINLINK_REF="${CHAINLINK_REF}-dirty"
fi
echo "==> applying the node's migrations from ${CHAINLINK_REF}"
# The node's own provider is used deliberately: four Go migrations are in the set, and
# Migration56 creates evm_chains which 0115's foreign key needs, so a SQL-only goose run
# fails. It must be compiled inside the chainlink module, so copy it in and remove it
# after -- an untracked directory there vanishes on the next checkout.
MIGRATOR_DIR="${CHAINLINK_REPO}/tools/logpollerschema"
# Never recursive: MIGRATOR_DIR comes from caller input.
remove_migrator() {
  rm -f "${MIGRATOR_DIR}/main.go"
  rmdir "$MIGRATOR_DIR" 2>/dev/null || true
}
trap 'cleanup; remove_migrator' EXIT

mkdir -p "$MIGRATOR_DIR"
# The build tag keeps CCV from compiling this file; the chainlink module must, so strip it.
grep -v '^//go:build ignore$' "${SCRIPT_DIR}/migrator.go" > "${MIGRATOR_DIR}/main.go"

(
  cd "$CHAINLINK_REPO"
  go run ./tools/logpollerschema -dsn "$DSN"
)

echo "==> dumping the evm schema"
docker exec "$CONTAINER" pg_dump -U postgres -d logpollerschema \
  --schema-only --no-owner --no-privileges --schema=evm \
  >"$OUT/evm-full.sql"

# The only provenance that survives: `chainlink` has no go.mod entry to record.
echo "$CHAINLINK_REF" >"$OUT/chainlink-ref.txt"

echo
echo "==> done"
echo "    chainlink ref   : ${CHAINLINK_REF}"
echo "    full evm schema : $OUT/evm-full.sql"
echo
echo "Next: turn it into the goose migration with"
echo "    just logpoller-schema"
