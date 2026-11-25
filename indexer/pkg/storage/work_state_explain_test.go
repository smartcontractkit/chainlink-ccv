package storage

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/indexer/testutil"
)

const (
	explainLeaseSecs = 90.0
)

// seedWorkStateExplainData loads indexer.messages with a mix of final, due, leased and expired rows.
// PROCESSING rows get retry_deadline = ingestion + 8 hours, as the insert stamps it.
func seedWorkStateExplainData(t *testing.T, db *sqlx.DB) {
	t.Helper()
	insert := func(n int, prefix, status, ingestion, nextAttempt string) {
		_, err := db.ExecContext(t.Context(), fmt.Sprintf(`
			INSERT INTO indexer.messages (message_id, message, status, source_chain_selector, dest_chain_selector,
			                              ingestion_timestamp, attempt_count, next_attempt_at, retry_deadline)
			SELECT '%[1]s-' || i, '{}'::jsonb, '%[2]s', 1, 2, (NOW() AT TIME ZONE 'UTC') - %[3]s, 1, %[4]s,
			       CASE WHEN '%[2]s' = '%[6]s' THEN NOW() - %[3]s + interval '8 hours' END
			FROM generate_series(1, %[5]d) AS i`, prefix, status, ingestion, nextAttempt, n, common.MessageProcessingString))
		require.NoError(t, err, "seed %s", prefix)
	}
	// 200,000 final rows: the table is mostly SUCCESS, so the partial index must skip them.
	insert(190000, "success", common.MessageSuccessfulString, "interval '1 day' * random() * 30", "NULL")
	insert(10000, "timeout", common.MessageTimeout.String(), "interval '1 day' * random() * 30", "NULL")
	// 5,000 due rows, 1,000 leased rows and 500 rows past their deadline.
	insert(2500, "new", common.MessageProcessingString, "interval '1 second' * i", "NULL")
	insert(2500, "retry", common.MessageProcessingString, "interval '1 second' * i", "NOW() - interval '1 second' * i")
	insert(1000, "leased", common.MessageProcessingString, "interval '1 second' * i", "NOW() + interval '1 minute'")
	insert(500, "expired", common.MessageProcessingString, "interval '9 hours'", "NULL")
	_, err := db.ExecContext(t.Context(), "VACUUM ANALYZE indexer.messages")
	require.NoError(t, err)
}

// explainWorkState runs EXPLAIN ANALYZE in a rolled back transaction and writes the plan to testdata.
func explainWorkState(t *testing.T, db *sqlx.DB, name, query string, args ...any) {
	t.Helper()
	tx, err := db.BeginTxx(t.Context(), nil)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()

	var lines []string
	require.NoError(t, tx.SelectContext(t.Context(), &lines, "EXPLAIN (ANALYZE, BUFFERS, VERBOSE, FORMAT TEXT) "+query, args...))
	out := fmt.Sprintf("=== EXPLAIN ANALYZE: %s ===\n%s\n", name, strings.Join(lines, "\n"))
	t.Log(out)
	require.NoError(t, os.MkdirAll("testdata", 0o755))
	require.NoError(t, os.WriteFile(filepath.Join("testdata", "explain_work_state_"+name+".txt"), []byte(out), 0o644))
}

// TestExplainWorkStateQueryPlans writes the plan of each work state query to testdata for review.
func TestExplainWorkStateQueryPlans(t *testing.T) {
	db, cleanup := testutil.SetupTestPostgresDB(t)
	t.Cleanup(cleanup)
	require.NoError(t, RunMigrationsContext(t.Context(), db))
	seedWorkStateExplainData(t, db)

	processing := common.MessageProcessingString

	explainWorkState(t, db, "claim", claimWorkSQL, processing, explainLeaseSecs, 50)
	explainWorkState(t, db, "settle_final", settleFinalSQL,
		common.MessageSuccessfulString, "", "new-1", processing, 1)
	explainWorkState(t, db, "settle_retry", settleRetrySQL,
		4.0, common.MessageTimeout.String(), "retry", "retry-1", processing, 1)
	explainWorkState(t, db, "expire", expireWorkSQL,
		common.MessageTimeout.String(), "retry deadline passed", processing, 1000)
	explainWorkState(t, db, "count_processing", countProcessingSQL, processing)
	explainWorkState(t, db, "backfill_retry_deadline", retryDeadlineBackfillSQL(t))
}

// retryDeadlineBackfillSQL reads the backfill UPDATE from its migration, so the plan is of the deployed SQL.
func retryDeadlineBackfillSQL(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "migrations", "postgres", "20261123000002_messages_retry_deadline.sql"))
	require.NoError(t, err)
	sql := string(b)
	start := strings.Index(sql, "UPDATE indexer.messages")
	require.GreaterOrEqual(t, start, 0)
	end := strings.Index(sql[start:], ";")
	require.Positive(t, end)
	return sql[start : start+end]
}
