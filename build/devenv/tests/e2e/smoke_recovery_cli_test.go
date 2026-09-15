package e2e

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	ccv "github.com/smartcontractkit/chainlink-ccv/build/devenv"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/verifiercli"
)

func recoveryCLIEnvironment(t *testing.T) (*verifiercli.Client, *sql.DB, string, string, uint64) {
	t.Helper()
	if testing.Short() {
		t.Skip("requires a running devenv")
	}
	in, err := ccv.LoadOutput[ccv.Cfg](GetSmokeTestConfig())
	require.NoError(t, err)
	require.NotEmpty(t, in.Verifier)
	require.NotNil(t, in.Verifier[0].Out)
	out := in.Verifier[0].Out
	db, err := sql.Open("postgres", out.DBConnectionString)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	var chain string
	var head uint64
	require.Eventually(t, func() bool {
		return db.QueryRowContext(t.Context(), `SELECT chain_selector::text, latest_block::text FROM ccv_recovery_readers
			WHERE owner_id=$1 AND NOT disabled AND head_observed_at > NOW()-INTERVAL '1 minute'
			ORDER BY latest_block DESC LIMIT 1`, out.VerifierID).Scan(&chain, &head) == nil
	}, time.Minute, time.Second, "running readers must register their recovery capability")
	return verifiercli.NewClient(out.ContainerName), db, out.VerifierID, chain, head
}

func TestE2ESmoke_RecoveryCLI(t *testing.T) {
	vc, _, owner, chain, head := recoveryCLIEnvironment(t)
	ctx := t.Context()
	identity, err := vc.ProcessIdentity(ctx)
	require.NoError(t, err)
	from, to := head+1000000, head+1000001
	key := uuid.NewString()
	o, err := vc.Recovery().Submit(ctx, "replay", owner, chain, from, &to, key)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = vc.Recovery().Action(context.Background(), "cancel", o.ID) })
	repeated, err := vc.Recovery().Submit(ctx, "replay", owner, chain, from, &to, key)
	require.NoError(t, err)
	require.Equal(t, o.ID, repeated.ID)
	require.Eventually(t, func() bool {
		current, err := vc.Recovery().Action(ctx, "status", o.ID)
		return err == nil && current.State == "running" && strings.Contains(current.LastError, "waiting for source head")
	}, time.Minute, time.Second)
	cancelled, err := vc.Recovery().Action(ctx, "cancel", o.ID)
	require.NoError(t, err)
	require.Equal(t, "cancelled", cancelled.State)
	require.Equal(t, from, cancelled.NextBlock)
	resumed, err := vc.Recovery().Action(ctx, "resume", o.ID)
	require.NoError(t, err)
	require.Equal(t, from, resumed.NextBlock)
	repeated, err = vc.Recovery().Action(ctx, "resume", o.ID)
	require.NoError(t, err, "repeated resume is idempotent")
	require.Equal(t, to, repeated.ToBlock)
	after, err := vc.ProcessIdentity(ctx)
	require.NoError(t, err)
	require.Equal(t, identity, after, "submit/cancel/resume must leave the service running")
}

// The restart here injects a process failure after a committed chunk. It is a
// separate durability scenario, not part of the live recovery workflow.
func TestE2ESmoke_RecoverySurvivesProcessFailure(t *testing.T) {
	vc, _, owner, chain, head := recoveryCLIEnvironment(t)
	ctx := t.Context()
	to := head + 1000000
	o, err := vc.Recovery().Submit(ctx, "replay", owner, chain, 0, &to, "")
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = vc.Recovery().Action(context.Background(), "cancel", o.ID) })
	var progress uint64
	var updatedAt time.Time
	require.Eventually(t, func() bool {
		current, err := vc.Recovery().Action(ctx, "status", o.ID)
		if err != nil {
			return false
		}
		progress = current.NextBlock
		updatedAt = current.UpdatedAt
		return current.State == "running" && progress > 0
	}, 90*time.Second, time.Second, "at least one chunk must commit before failure injection")
	identity, err := vc.ProcessIdentity(ctx)
	require.NoError(t, err)
	require.NoError(t, vc.CrashAndWaitReady(ctx))
	after, err := vc.ProcessIdentity(ctx)
	require.NoError(t, err)
	require.NotEqual(t, identity, after, "failure injection must replace the service process")
	require.Eventually(t, func() bool {
		current, err := vc.Recovery().Action(ctx, "status", o.ID)
		return err == nil && current.State == "running" && current.NextBlock >= progress &&
			current.ToBlock == to && current.UpdatedAt.After(updatedAt)
	}, 90*time.Second, time.Second, "the same durable operation must survive a process failure")
}

// Requires the full devenv observability stack (VictoriaMetrics on port 8428).
func TestE2ESmoke_RecoveryArchiveInventory(t *testing.T) {
	vc, db, owner, _, _ := recoveryCLIEnvironment(t)
	ctx := t.Context()
	const chain = "18446744073709551614"
	message := strings.ReplaceAll(uuid.NewString(), "-", "") + strings.ReplaceAll(uuid.NewString(), "-", "")
	messageID := "0x" + message
	fullError := strings.Repeat("retained diagnostic ", 20)
	jobIDs := []string{uuid.NewString(), uuid.NewString()}
	t.Cleanup(func() {
		for i, queue := range []string{"ccv_task_verifier_jobs", "ccv_storage_writer_jobs"} {
			_, _ = db.ExecContext(context.Background(), "DELETE FROM "+queue+" WHERE job_id=$1", jobIDs[i])
			_, _ = db.ExecContext(context.Background(), "DELETE FROM "+queue+"_archive WHERE job_id=$1", jobIDs[i])
		}
	})
	for i, queue := range []string{"ccv_task_verifier_jobs", "ccv_storage_writer_jobs"} {
		_, err := db.ExecContext(ctx, `INSERT INTO `+queue+`_archive
			(id,job_id,owner_id,chain_selector,message_id,task_data,status,created_at,available_at,attempt_count,retry_deadline,last_error,completed_at)
			VALUES ($1,$2,$3,$4,decode($5,'hex'),'{}','failed',NOW()-INTERVAL '25 days',NOW(),3,NOW(),$6,NOW()-INTERVAL '24 days')`,
			-time.Now().UnixNano(), jobIDs[i], owner, chain, message, fullError)
		require.NoError(t, err)
	}
	rows, err := vc.JobQueue().ListJSON(ctx, "", "", strings.ToUpper(messageID), messageID)
	require.NoError(t, err)
	require.Len(t, rows, 2, "exact lookup spans both queues without an owner filter")
	for _, row := range rows {
		require.Equal(t, chain, row.SourceChain)
		require.Equal(t, fullError, row.LastError)
		require.NotNil(t, row.ArchivedAt)
	}
	selector := fmt.Sprintf(`{verifier_id=%q,source_chain=%q,reason="unknown"}`, owner, chain)
	requireRecoveryMetric(t, ctx, "sum(verifier_archive_failed_jobs"+selector+")", 2)
	requireRecoveryMetric(t, ctx, "sum(verifier_archive_expiring_jobs"+selector+")", 2)
	out, err := vc.CLI(ctx, verifiercli.JobQueueSubcommand, "reschedule", "--queue", "task-verifier", "--job-id", jobIDs[0])
	require.NoError(t, err, "%s", out)
	require.Contains(t, out, owner)
	requireRecoveryMetric(t, ctx, "sum(verifier_archive_expiring_jobs"+selector+")", 1)
	_, err = db.ExecContext(ctx, "DELETE FROM ccv_storage_writer_jobs_archive WHERE job_id=$1", jobIDs[1])
	require.NoError(t, err)
	requireRecoveryMetric(t, ctx, "sum(verifier_archive_expiring_jobs"+selector+")", 0)
}

func requireRecoveryMetric(t *testing.T, ctx context.Context, query string, expected float64) {
	t.Helper()
	client := &http.Client{Timeout: 5 * time.Second}
	require.Eventually(t, func() bool {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost:8428/api/v1/query?query="+url.QueryEscape(query), nil)
		if err != nil {
			return false
		}
		response, err := client.Do(req)
		if err != nil {
			return false
		}
		defer func() { _ = response.Body.Close() }()
		var result struct {
			Status string `json:"status"`
			Data   struct {
				Result []struct {
					Value []json.RawMessage `json:"value"`
				} `json:"result"`
			} `json:"data"`
		}
		if json.NewDecoder(response.Body).Decode(&result) != nil || result.Status != "success" || len(result.Data.Result) != 1 || len(result.Data.Result[0].Value) != 2 {
			return false
		}
		var text string
		if json.Unmarshal(result.Data.Result[0].Value[1], &text) != nil {
			return false
		}
		value, err := strconv.ParseFloat(text, 64)
		return err == nil && value == expected
	}, 2*time.Minute, 2*time.Second, "metric %s must be %v after collection/export", query, expected)
}
