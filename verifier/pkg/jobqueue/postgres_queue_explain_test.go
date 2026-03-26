package jobqueue_test

import (
	"context"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/stretchr/testify/require"

	verifierdb "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/db"
	vtypes "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vtypes"
	"github.com/smartcontractkit/chainlink-ccv/verifier/testutil"
)

// explainEpoch is the fixed reference time used for all seed data and query parameters in
// EXPLAIN tests. A stable epoch ensures VACUUM ANALYZE always sees identical data, producing
// consistent histogram bounds and therefore reproducible query plans across runs.
var explainEpoch = time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)

// deterministicUUID returns a SHA-1 name-based UUID that is identical for the same (ns, i)
// pair across runs. This replaces uuid.New() in seed data to keep seeded rows byte-for-byte
// stable so EXPLAIN plan output can be meaningfully diffed over time.
func deterministicUUID(ns string, i int) string {
	return uuid.NewSHA1(uuid.NameSpaceURL, fmt.Appendf(nil, "%s-%d", ns, i)).String()
}

const (
	explainOwner   = "explain-owner"
	explainTable   = vtypes.TaskVerifierJobsTableName
	explainArchive = vtypes.TaskVerifierJobsTableName + "_archive"
)

// getExplainDB returns a database connection for EXPLAIN ANALYZE tests.
// If TEST_POSTGRES_URL is set, it connects to a local Postgres instance and truncates the
// job queue tables to ensure a clean slate. Otherwise it spins up a testcontainer.
//
// Run against a local Postgres:
//
//	TEST_POSTGRES_URL="postgres://user:pass@localhost:5432/ccv_test?sslmode=disable" \
//	  go test -v -run TestExplainQueryPlans -timeout 120s ./verifier/pkg/jobqueue/
//
// Run with testcontainer (no env var needed):
//
//	go test -v -run TestExplainQueryPlans -timeout 120s ./verifier/pkg/jobqueue/
func getExplainDB(t *testing.T) *sqlx.DB {
	t.Helper()
	if url := os.Getenv("TEST_POSTGRES_URL"); url != "" {
		sdb, err := sqlx.Open("postgres", url)
		require.NoError(t, err, "open local postgres")
		require.NoError(t, verifierdb.RunPostgresMigrations(sdb), "run migrations")
		_, err = sdb.ExecContext(context.Background(),
			"TRUNCATE ccv_task_verifier_jobs, ccv_task_verifier_jobs_archive CASCADE")
		require.NoError(t, err, "truncate tables")
		t.Cleanup(func() { _ = sdb.Close() })
		return sdb
	}
	return testutil.NewTestDB(t)
}

// explainChainSelectorStr converts a uint64 to the NUMERIC(20,0) string representation
// used when storing chain selectors in the database (mirrors postgres_queue.go).
func explainChainSelectorStr(n uint64) string {
	return new(big.Int).SetUint64(n).String()
}

// seedExplainData bulk-loads the job queue tables with a realistic dataset using
// PostgreSQL COPY, producing enough rows for the planner to choose index scans.
//
// Active table (ccv_task_verifier_jobs):
//   - 50,000 pending jobs for "explain-owner" (available_at spread across the past ~14h)
//   - 500 stale processing jobs for "explain-owner" (started_at = 2h ago)
//   - 200 fresh processing jobs for "explain-owner" (started_at = now)
//   - 5,000 pending jobs across 5 other owner_ids (1,000 each)
//
// Archive table (ccv_task_verifier_jobs_archive):
//   - 20,000 completed rows for "explain-owner" (completed_at spread across the past ~14 days)
func seedExplainData(t *testing.T, db *sqlx.DB) {
	t.Helper()
	ctx := context.Background()
	now := explainEpoch
	// Pass as string, not []byte: pq.CopyIn uses the COPY text protocol, so a []byte
	// value for a JSONB column is encoded as bytea hex (\x7b…7d) which Postgres
	// cannot parse as JSON. A string is transmitted as-is and parsed correctly.
	jsonData := `{"chain":1,"data":"explain-test"}`

	// -------------------------------------------------------------------------
	// Active table
	// -------------------------------------------------------------------------
	activeTxn, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	activeCommitted := false
	defer func() {
		if !activeCommitted {
			_ = activeTxn.Rollback()
		}
	}()

	activeStmt, err := activeTxn.Prepare(pq.CopyIn(explainTable,
		"job_id", "owner_id", "chain_selector", "message_id", "task_data",
		"status", "created_at", "available_at", "started_at",
		"attempt_count", "retry_deadline",
	))
	require.NoError(t, err)

	// 50,000 pending jobs — available_at spread over the past ~14h so ORDER BY
	// available_at exercises a real range of index pages rather than a single leaf.
	for i := range 50000 {
		availableAt := now.Add(-time.Duration(i) * time.Second)
		_, err = activeStmt.Exec(
			deterministicUUID("pending", i), explainOwner,
			explainChainSelectorStr(1),
			fmt.Appendf(nil, "msg-pending-%d", i),
			jsonData, "pending",
			now, availableAt,
			nil, // started_at NULL for pending jobs
			0, now.Add(time.Hour),
		)
		require.NoError(t, err)
	}

	// 500 stale processing jobs — started_at 2h ago so the Consume stale path
	// (staleBefore = now - 1min) reclaims them during the EXPLAIN ANALYZE run.
	for i := range 500 {
		startedAt := now.Add(-2 * time.Hour)
		_, err = activeStmt.Exec(
			deterministicUUID("stale", i), explainOwner,
			explainChainSelectorStr(2),
			fmt.Appendf(nil, "msg-stale-%d", i),
			jsonData, "processing",
			now.Add(-3*time.Hour), now.Add(-3*time.Hour),
			startedAt,
			1, now.Add(time.Hour),
		)
		require.NoError(t, err)
	}

	// 200 fresh processing jobs — started_at = now so the stale path skips them.
	for i := range 200 {
		_, err = activeStmt.Exec(
			deterministicUUID("fresh", i), explainOwner,
			explainChainSelectorStr(3),
			fmt.Appendf(nil, "msg-fresh-%d", i),
			jsonData, "processing",
			now, now,
			now, // started_at = now (fresh, not stale)
			1, now.Add(time.Hour),
		)
		require.NoError(t, err)
	}

	// 5,000 pending jobs for 5 other owner_ids (1,000 each) — validates that the
	// leading owner_id column in idx_consume provides good selectivity.
	for ownerIdx := range 5 {
		ownerID := fmt.Sprintf("other-owner-%d", ownerIdx)
		for i := range 1000 {
			availableAt := now.Add(-time.Duration(i) * time.Second)
			_, err = activeStmt.Exec(
				deterministicUUID(fmt.Sprintf("other-%d", ownerIdx), i), ownerID,
				explainChainSelectorStr(uint64(ownerIdx+10)),
				fmt.Appendf(nil, "msg-other-%d-%d", ownerIdx, i),
				jsonData, "pending",
				now, availableAt,
				nil,
				0, now.Add(time.Hour),
			)
			require.NoError(t, err)
		}
	}

	_, err = activeStmt.Exec() // flush COPY buffer
	require.NoError(t, err)
	require.NoError(t, activeStmt.Close())
	require.NoError(t, activeTxn.Commit())
	activeCommitted = true

	// -------------------------------------------------------------------------
	// Archive table — id is BIGINT PK (not BIGSERIAL), must be supplied explicitly
	// -------------------------------------------------------------------------
	archiveTxn, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	archiveCommitted := false
	defer func() {
		if !archiveCommitted {
			_ = archiveTxn.Rollback()
		}
	}()

	archiveStmt, err := archiveTxn.Prepare(pq.CopyIn(explainArchive,
		"id", "job_id", "owner_id", "chain_selector", "message_id", "task_data",
		"status", "created_at", "available_at", "started_at",
		"attempt_count", "retry_deadline", "last_error", "completed_at",
	))
	require.NoError(t, err)

	// 20,000 completed rows — completed_at spread across the past ~14 days so the
	// Cleanup DELETE exercises a meaningful range of the archive index.
	//
	// IDs start at 1,000,001 to avoid conflicting with the active table's BIGSERIAL
	// range (~1..55,700): the Complete and Fail EXPLAIN ANALYZE queries move active
	// rows (with their original id) into the archive, so the pre-seeded archive IDs
	// must not overlap with any active table id.
	for i := range 20000 {
		completedAt := now.Add(-time.Duration(i) * time.Minute)
		_, err = archiveStmt.Exec(
			int64(1_000_001+i), // explicit PK (archive table has BIGINT, not BIGSERIAL)
			deterministicUUID("archive", i), explainOwner,
			explainChainSelectorStr(1),
			fmt.Appendf(nil, "msg-archive-%d", i),
			jsonData, "completed",
			completedAt, completedAt,
			nil, // started_at
			1, now.Add(time.Hour),
			nil, // last_error
			completedAt,
		)
		require.NoError(t, err)
	}

	_, err = archiveStmt.Exec() // flush COPY buffer
	require.NoError(t, err)
	require.NoError(t, archiveStmt.Close())
	require.NoError(t, archiveTxn.Commit())
	archiveCommitted = true

	t.Logf("Seed complete: %d active rows (%d explain-owner pending, 500 stale, 200 fresh, 5,000 other), %d archive rows",
		55700, 50000, 20000)
}

// runExplainAnalyze wraps query in EXPLAIN (ANALYZE, BUFFERS, VERBOSE, FORMAT TEXT) and
// executes it inside a transaction that is always rolled back, leaving the data intact.
func runExplainAnalyze(t *testing.T, db *sqlx.DB, label, query string, args ...any) string {
	t.Helper()
	ctx := context.Background()

	txn, err := db.BeginTxx(ctx, nil)
	require.NoError(t, err)
	defer func() { _ = txn.Rollback() }()

	rows, err := txn.QueryxContext(ctx,
		"EXPLAIN (ANALYZE, BUFFERS, VERBOSE, FORMAT TEXT) "+query, args...)
	require.NoError(t, err, "EXPLAIN ANALYZE failed for %q", label)
	defer rows.Close()

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("=== EXPLAIN ANALYZE: %s ===\n", label))
	for rows.Next() {
		var line string
		require.NoError(t, rows.Scan(&line))
		sb.WriteString(line)
		sb.WriteByte('\n')
	}
	require.NoError(t, rows.Err())
	return sb.String()
}

// writeExplainOutput logs the plan to the test output (-v) and persists it to
// testdata/explain_<name>.txt so successive runs can be diffed.
func writeExplainOutput(t *testing.T, name, output string) {
	t.Helper()
	t.Log(output)

	dir := "testdata"
	require.NoError(t, os.MkdirAll(dir, 0o755))
	path := filepath.Join(dir, fmt.Sprintf("explain_%s.txt", name))
	require.NoError(t, os.WriteFile(path, []byte(output), 0o644))
	t.Logf("Plan written to %s", path)
}

// TestExplainQueryPlans seeds a realistic dataset (~56k active + 20k archive rows) and
// runs EXPLAIN (ANALYZE, BUFFERS, VERBOSE) on every query issued by postgres_queue.go.
// Use -v to see plan output; each plan is also written to testdata/explain_<query>.txt.
//
// Key things to look for after the optimization fixes:
//   - Consume_pending: "Index Scan using idx_ccv_task_verifier_jobs_consume" — no Seq Scan,
//     no Sort node, no "external merge  Disk:" spill.
//   - Consume_stale:   "Index Scan using idx_ccv_task_verifier_jobs_stale".
//   - Size:            "Index Only Scan" on idx_status with zero heap fetches.
//   - Retry/Fail:      bulk UNNEST plans; DELETE still uses "Index Scan" on the job_id key.
//   - Cleanup:         Seq Scan is expected at test scale (50% selectivity); the ASC index
//     direction will be beneficial in production at low selectivity.
func TestExplainQueryPlans(t *testing.T) {
	t.Skip("skipping explain test - comment to run it - it will overwrite testdata files")

	sdb := getExplainDB(t)
	ctx := context.Background()

	t.Log("Seeding data (may take several seconds)…")
	seedExplainData(t, sdb)

	// VACUUM ANALYZE refreshes planner statistics so the optimizer has accurate
	// row counts and correlation data. Must run outside any transaction block.
	for _, tbl := range []string{explainTable, explainArchive} {
		_, err := sdb.ExecContext(ctx, "VACUUM ANALYZE "+tbl)
		require.NoError(t, err, "VACUUM ANALYZE %s", tbl)
	}
	t.Log("VACUUM ANALYZE complete — planner statistics updated")

	// Pre-fetch existing job_ids to use as parameters in write-path queries so
	// the planner encounters real values rather than dummy literals.
	var sampleJobIDs []string
	require.NoError(t,
		sdb.SelectContext(ctx, &sampleJobIDs,
			fmt.Sprintf(
				"SELECT job_id FROM %s WHERE owner_id = $1 AND status = 'pending' LIMIT 20",
				explainTable),
			explainOwner),
	)
	require.GreaterOrEqual(t, len(sampleJobIDs), 2, "need ≥2 pending job_ids from seeded data")

	now := explainEpoch
	// staleBefore with a 1-minute LockDuration: the seeded stale jobs (started_at = 2h ago)
	// satisfy started_at <= staleBefore, so the stale path in Consume returns rows.
	staleBefore := now.Add(-time.Minute)

	// -----------------------------------------------------------------
	// 1a. Consume — pending path.
	//
	// Uses idx_consume (owner_id, available_at, id) WHERE status='pending'.
	// Expected: Index Scan using idx_ccv_task_verifier_jobs_consume — no Seq
	// Scan, no Sort node, no "external merge  Disk:" spill.
	// -----------------------------------------------------------------
	t.Run("Consume_pending", func(t *testing.T) {
		query := fmt.Sprintf(`
			UPDATE %[1]s
			SET status = $1,
			    started_at = $2,
			    attempt_count = attempt_count + 1
			WHERE id IN (
			    SELECT id FROM %[1]s
			    WHERE owner_id = $3
			      AND status = $4
			      AND available_at <= $5
			    ORDER BY available_at ASC, id ASC
			    LIMIT $6
			    FOR UPDATE SKIP LOCKED
			)
			RETURNING id, job_id, task_data, attempt_count, retry_deadline, created_at,
			          started_at, chain_selector, message_id`,
			explainTable)
		out := runExplainAnalyze(t, sdb, "consume_pending", query,
			"processing", // $1 new status
			now,          // $2 started_at
			explainOwner, // $3
			"pending",    // $4
			now,          // $5 available_at <=
			50,           // $6 batchSize
		)
		writeExplainOutput(t, "consume_pending", out)
	})

	// -----------------------------------------------------------------
	// 1b. Consume — stale processing path (crashed-worker recovery).
	//
	// Uses idx_stale (owner_id, started_at, id) WHERE status='processing'
	// AND started_at IS NOT NULL.
	// Expected: Index Scan using idx_ccv_task_verifier_jobs_stale.
	// -----------------------------------------------------------------
	t.Run("Consume_stale", func(t *testing.T) {
		query := fmt.Sprintf(`
			UPDATE %[1]s
			SET status = $1,
			    started_at = $2,
			    attempt_count = attempt_count + 1
			WHERE id IN (
			    SELECT id FROM %[1]s
			    WHERE owner_id = $3
			      AND status = $4
			      AND started_at IS NOT NULL
			      AND started_at <= $5
			    ORDER BY started_at ASC, id ASC
			    LIMIT $6
			    FOR UPDATE SKIP LOCKED
			)
			RETURNING id, job_id, task_data, attempt_count, retry_deadline, created_at,
			          started_at, chain_selector, message_id`,
			explainTable)
		out := runExplainAnalyze(t, sdb, "consume_stale", query,
			"processing", // $1 new status
			now,          // $2 started_at
			explainOwner, // $3
			"processing", // $4
			staleBefore,  // $5 started_at <=
			50,           // $6 batchSize
		)
		writeExplainOutput(t, "consume_stale", out)
	})

	// -----------------------------------------------------------------
	// 2. Size — COUNT(*) with owner_id + status IN.
	//    Expected: Index Only Scan on idx_status (owner_id, status).
	// -----------------------------------------------------------------
	t.Run("Size", func(t *testing.T) {
		query := fmt.Sprintf(`
			SELECT COUNT(*)
			FROM %s
			WHERE owner_id = $1
			  AND status IN ($2, $3)`,
			explainTable)
		out := runExplainAnalyze(t, sdb, "size", query,
			explainOwner, "pending", "processing")
		writeExplainOutput(t, "size", out)
	})

	// -----------------------------------------------------------------
	// 3a. Publish — no-conflict path (brand-new message_id).
	//     Expected: Index Scan on unique constraint to check for duplicates.
	// -----------------------------------------------------------------
	t.Run("Publish_no_conflict", func(t *testing.T) {
		query := fmt.Sprintf(`
			INSERT INTO %s (
			    job_id, task_data, status, available_at, created_at, attempt_count, retry_deadline,
			    chain_selector, message_id, owner_id
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
			ON CONFLICT (owner_id, chain_selector, message_id) DO NOTHING`,
			explainTable)
		out := runExplainAnalyze(t, sdb, "publish_no_conflict", query,
			deterministicUUID("publish-noconflict", 0),
			[]byte(`{"chain":99,"data":"new"}`),
			"pending", now, now,
			0, now.Add(time.Hour),
			explainChainSelectorStr(99),
			[]byte("brand-new-message-that-does-not-exist"),
			explainOwner,
		)
		writeExplainOutput(t, "publish_no_conflict", out)
	})

	// -----------------------------------------------------------------
	// 3b. Publish — conflict path (duplicate owner/chain/message).
	//     Expected: "Conflict" node shows the unique constraint index being hit.
	// -----------------------------------------------------------------
	t.Run("Publish_conflict", func(t *testing.T) {
		var csStr string
		var existingMsgID []byte
		row := sdb.QueryRowxContext(ctx,
			fmt.Sprintf(
				"SELECT chain_selector::text, message_id FROM %s WHERE owner_id = $1 LIMIT 1",
				explainTable),
			explainOwner)
		require.NoError(t, row.Scan(&csStr, &existingMsgID))

		query := fmt.Sprintf(`
			INSERT INTO %s (
			    job_id, task_data, status, available_at, created_at, attempt_count, retry_deadline,
			    chain_selector, message_id, owner_id
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
			ON CONFLICT (owner_id, chain_selector, message_id) DO NOTHING`,
			explainTable)
		out := runExplainAnalyze(t, sdb, "publish_conflict", query,
			deterministicUUID("publish-conflict", 0),
			[]byte(`{"chain":1,"data":"dup"}`),
			"pending", now, now,
			0, now.Add(time.Hour),
			csStr,
			existingMsgID,
			explainOwner,
		)
		writeExplainOutput(t, "publish_conflict", out)
	})

	// -----------------------------------------------------------------
	// 4. Complete — bulk DELETE active + INSERT archive (job_id = ANY).
	//    Expected: Index Scan on the job_id unique index for DELETE.
	// -----------------------------------------------------------------
	t.Run("Complete", func(t *testing.T) {
		batchIDs := sampleJobIDs[:min(10, len(sampleJobIDs))]
		query := fmt.Sprintf(`
			WITH completed AS (
			    DELETE FROM %[1]s
			    WHERE job_id = ANY($1)
			      AND owner_id = $2
			    RETURNING id, job_id, owner_id, chain_selector, message_id, task_data,
			              created_at, available_at, started_at, attempt_count, retry_deadline, last_error
			)
			INSERT INTO %[2]s (
			    id, job_id, owner_id, chain_selector, message_id, task_data,
			    status, created_at, available_at, started_at, attempt_count, retry_deadline, last_error,
			    completed_at
			)
			SELECT id, job_id, owner_id, chain_selector, message_id, task_data,
			       $3, created_at, available_at, started_at, attempt_count, retry_deadline, last_error,
			       NOW()
			FROM completed`,
			explainTable, explainArchive)
		out := runExplainAnalyze(t, sdb, "complete", query,
			pq.Array(batchIDs), explainOwner, "completed")
		writeExplainOutput(t, "complete", out)
	})

	// -----------------------------------------------------------------
	// 5. Retry — bulk UNNEST UPDATE by job_id + owner_id.
	//    Expected: Index Scan on the job_id unique index (Nested Loop over UNNEST).
	// -----------------------------------------------------------------
	t.Run("Retry", func(t *testing.T) {
		jobIDsBatch := sampleJobIDs[:min(5, len(sampleJobIDs))]
		errMsgs := make([]string, len(jobIDsBatch))
		for i := range errMsgs {
			errMsgs[i] = "transient error"
		}
		query := fmt.Sprintf(`
			UPDATE %s AS t
			SET status = CASE
			        WHEN NOW() >= t.retry_deadline THEN $1
			        ELSE $2
			    END,
			    available_at = $3,
			    last_error = v.error_msg
			FROM UNNEST($4::text[], $5::text[]) AS v(job_id, error_msg)
			WHERE t.job_id = v.job_id::uuid
			  AND t.owner_id = $6
			RETURNING t.job_id, t.status`,
			explainTable)
		out := runExplainAnalyze(t, sdb, "retry", query,
			"failed",              // $1
			"pending",             // $2
			now.Add(time.Minute),  // $3 available_at
			pq.Array(jobIDsBatch), // $4
			pq.Array(errMsgs),     // $5
			explainOwner,          // $6
		)
		writeExplainOutput(t, "retry", out)
	})

	// -----------------------------------------------------------------
	// 6. Fail — bulk UNNEST CTE: DELETE active → INSERT archive.
	//    Expected: Index Scan on the job_id unique index in the DELETE CTE.
	// -----------------------------------------------------------------
	t.Run("Fail", func(t *testing.T) {
		jobIDsBatch := sampleJobIDs[2:min(7, len(sampleJobIDs))]
		errMsgs := make([]string, len(jobIDsBatch))
		for i := range errMsgs {
			errMsgs[i] = "permanent error"
		}
		query := fmt.Sprintf(`
			WITH jobs_input AS (
			    SELECT v.job_id::uuid AS job_id, v.error_msg
			    FROM UNNEST($1::text[], $2::text[]) AS v(job_id, error_msg)
			),
			to_fail AS (
			    DELETE FROM %[1]s t
			    WHERE t.job_id IN (SELECT job_id FROM jobs_input)
			      AND t.owner_id = $3
			    RETURNING t.id, t.job_id, t.owner_id, t.chain_selector, t.message_id, t.task_data,
			              t.created_at, t.available_at, t.started_at, t.attempt_count, t.retry_deadline
			)
			INSERT INTO %[2]s (
			    id, job_id, owner_id, chain_selector, message_id, task_data,
			    status, created_at, available_at, started_at, attempt_count, retry_deadline,
			    last_error, completed_at
			)
			SELECT f.id, f.job_id, f.owner_id, f.chain_selector, f.message_id, f.task_data,
			       $4, f.created_at, f.available_at, f.started_at, f.attempt_count, f.retry_deadline,
			       i.error_msg, NOW()
			FROM to_fail f
			JOIN jobs_input i ON f.job_id = i.job_id`,
			explainTable, explainArchive)
		out := runExplainAnalyze(t, sdb, "fail", query,
			pq.Array(jobIDsBatch), // $1
			pq.Array(errMsgs),     // $2
			explainOwner,          // $3
			"failed",              // $4
		)
		writeExplainOutput(t, "fail", out)
	})

	// -----------------------------------------------------------------
	// 7. Cleanup — DELETE from archive by owner_id + completed_at range.
	//    Expected: Index Scan on idx_archive_completed (owner_id, completed_at ASC).
	//    Watch for: a forward Index Scan using this index, confirming the ASC
	//    direction is optimal for a range-DELETE targeting old rows (completed_at < cutoff).
	// -----------------------------------------------------------------
	t.Run("Cleanup", func(t *testing.T) {
		cutoff := now.Add(-7 * 24 * time.Hour) // delete anything older than 7 days
		query := fmt.Sprintf(`
			DELETE FROM %s
			WHERE completed_at < $1
			  AND owner_id = $2`,
			explainArchive)
		out := runExplainAnalyze(t, sdb, "cleanup", query, cutoff, explainOwner)
		writeExplainOutput(t, "cleanup", out)
	})
}
