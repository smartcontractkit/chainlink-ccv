#!/usr/bin/env bash
# Run chainlink-evm's own LogPoller ORM test suite against CCV's generated schema.
#
# CCV pins the ORM in go.mod but generates its schema from `chainlink`, which is not a CCV
# dependency -- so the two can drift on any chainlink-evm bump with nothing to catch it.
# chainlink-evm ships no migrations and its tests take an already-migrated database from
# CL_DATABASE_URL (pkg/testutils/sql.go), so we hand it one built by RunEVMMigrations.
# Each test runs in a txdb transaction and rolls back, so the database is reusable.
#
# Usage:
#   ./tools/logpollerschema/orm-contract.sh            # run the contract suite
#   VERBOSE=1 ./tools/logpollerschema/orm-contract.sh  # with -v
#
# Requires: docker and the module cache (go mod download).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

CONTAINER="logpoller-orm-test-pg"
PGPORT="${PGPORT:-55433}"

# The database name MUST end in `_test`. chainlink-common's RegisterTxDB refuses anything
# else, as a guard against ever pointing a test suite at a production database.
TESTDB="chainlink_test"

# TestInsertLogsWithBlock and TestInsertLogsInTx test transaction rollback, so they cannot
# run inside txdb; they copy this database instead. The name is hardcoded upstream
# (pkg/testutils/sql.go, `pristineDBName`) -- do not change the literal.
TEMPLATE_DB="chainlink_test_pristine"

dsn_for() { echo "postgres://postgres:postgres@localhost:${PGPORT}/$1?sslmode=disable"; }
DSN="$(dsn_for "$TESTDB")"

UPSTREAM_PKG="github.com/smartcontractkit/chainlink-evm/pkg/logpoller"

# The ORM and observability tests -- those that exercise SQL against the schema.
#
# Deliberately not the whole package: log_poller_test.go drives poller behaviour against
# mocked chain clients, which tests upstream's logic rather than our schema, and is slow.
# Derived from the test names in orm_test.go and observability_test.go; re-check on a
# chainlink-evm bump, since new ORM tests will not be picked up by a stale filter.
FILTER='^(TestORM|TestORM_.*|TestDSORM_.*|TestLogPoller_Batching|TestLogPoller_Blocks_Batching|TestLogPoller_Logs|TestLogPollerFilters|TestSelect.*|TestInsertLogs.*|TestNestedLogPollerBlocksQuery|Test_ExecPagedQuery|TestMultipleMetricsArePublished|TestShouldPublishDurationInCaseOfError|TestMetricsAreProperlyPopulated.*|TestNotPublishingDatasetSizeInCaseOfError|TestCountersAreProperlyPopulatedForWrites)$'

cleanup() { docker rm -f "$CONTAINER" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "==> starting scratch postgres on :${PGPORT}"
cleanup
docker run -d --name "$CONTAINER" \
  -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB="${TESTDB}" \
  -p "${PGPORT}:5432" \
  postgres:15-alpine >/dev/null

echo -n "==> waiting for postgres"
for _ in $(seq 1 60); do
  if docker exec "$CONTAINER" pg_isready -U postgres -d "${TESTDB}" >/dev/null 2>&1; then break; fi
  echo -n "."
  sleep 1
done
echo " ready"

echo "==> creating the database that the rollback tests copy"
docker exec "$CONTAINER" createdb -U postgres "$TEMPLATE_DB"

echo "==> applying CCV's generated schema via RunEVMMigrations (test db + clone template)"
# Both get the schema. The migrate command exits between runs on purpose: copying a
# database fails if anything is still connected to it.
(
  cd "$REPO_ROOT"
  go run ./tools/logpollerschema/cmd/migrate -dsn "$DSN"
  go run ./tools/logpollerschema/cmd/migrate -dsn "$(dsn_for "$TEMPLATE_DB")"
)

echo "==> running upstream's ORM suite against it"
(
  cd "$REPO_ROOT"
  export CL_DATABASE_URL="$DSN"
  go test "$UPSTREAM_PKG" -run "$FILTER" -count=1 ${VERBOSE:+-v}
)

echo
echo "==> the pinned chainlink-evm ORM can operate against the generated schema"
