package postgres

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/require"
)

const (
	explainMessages         = 20000
	explainSignersPerKey    = 16
	explainTargetMessageID  = "0xexplain-target"
	explainTargetKeyCount   = 2
	explainSeedVerification = `
		INSERT INTO commit_verification_records
			(message_id, signer_identifier, aggregation_key, message_data, ccv_version, signature,
			 message_ccv_addresses, message_executor_address)
		SELECT 'msg-' || m, 'signer-' || s, 'key-' || m, '{}'::jsonb, '\x01020304'::bytea, '\x00'::bytea,
			ARRAY['0x00'], '0x00'
		FROM generate_series(1, $1) AS m, generate_series(1, $2) AS s`
	explainSeedTarget = `
		INSERT INTO commit_verification_records
			(message_id, signer_identifier, aggregation_key, message_data, ccv_version, signature,
			 message_ccv_addresses, message_executor_address)
		SELECT $1, 'signer-' || s, 'key-' || k, '{}'::jsonb, '\x01020304'::bytea, '\x00'::bytea,
			ARRAY['0x00'], '0x00'
		FROM generate_series(1, $2) AS k, generate_series(1, $3) AS s`
)

// runExplainAnalyze runs EXPLAIN (ANALYZE, BUFFERS, VERBOSE) on query in a transaction that is rolled back.
func runExplainAnalyze(t *testing.T, db *sqlx.DB, label, query string, args ...any) string {
	t.Helper()
	txn, err := db.BeginTxx(context.Background(), nil)
	require.NoError(t, err)
	defer func() { _ = txn.Rollback() }()

	var lines []string
	require.NoError(t, txn.Select(&lines, "EXPLAIN (ANALYZE, BUFFERS, VERBOSE, FORMAT TEXT) "+query, args...))
	return fmt.Sprintf("=== EXPLAIN ANALYZE: %s ===\n%s\n", label, strings.Join(lines, "\n"))
}

// writeExplainOutput logs the plan and writes it to testdata/explain_<name>.txt so runs can be compared.
func writeExplainOutput(t *testing.T, name, output string) {
	t.Helper()
	t.Log(output)
	require.NoError(t, os.MkdirAll("testdata", 0o755))
	require.NoError(t, os.WriteFile(filepath.Join("testdata", fmt.Sprintf("explain_%s.txt", name)), []byte(output), 0o644))
}

// TestExplainQueryPlans seeds 320k verification records and checks the plans of the message status queries.
// Expected: an index scan on message_id, with no Seq Scan.
func TestExplainQueryPlans(t *testing.T) {
	_, db, cleanup := setupTestDBWithDatabase(t)
	defer cleanup()
	ctx := context.Background()

	_, err := db.ExecContext(ctx, explainSeedVerification, explainMessages, explainSignersPerKey)
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, explainSeedTarget, explainTargetMessageID, explainTargetKeyCount, explainSignersPerKey)
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, "VACUUM ANALYZE commit_verification_records")
	require.NoError(t, err)

	t.Run("ListCommitVerificationByMessageID", func(t *testing.T) {
		plan := runExplainAnalyze(t, db, "ListCommitVerificationByMessageID",
			listCommitVerificationByMessageIDQuery, explainTargetMessageID, maxVerificationRecordsPerMessage+1)
		writeExplainOutput(t, "list_commit_verification_by_message_id", plan)

		require.NotContains(t, plan, "Seq Scan", "the query must not scan the full table")
		require.Contains(t, plan, "Index", "the query must use an index on message_id")
		require.Contains(t, plan, fmt.Sprintf("rows=%d", explainTargetKeyCount*explainSignersPerKey))
	})
}
