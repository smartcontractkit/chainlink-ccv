package e2e

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"github.com/stretchr/testify/require"

	ccv "github.com/smartcontractkit/chainlink-ccv/build/devenv"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/verifiercli"
	"github.com/smartcontractkit/chainlink-testing-framework/framework"
)

// TestE2ESmoke_JobQueueCLI verifies the job-queue CLI commands:
//   - list     shows a failed job from the archive
//   - reschedule moves it back to the active queue (pending)
//
// The test seeds one fake failed job directly in the archive table, stops the
// verifier process so it cannot race with the CLI assertions, then resumes it
// once the checks are done.
func TestE2ESmoke_JobQueueCLI(t *testing.T) {
	smokeTestConfig := GetSmokeTestConfig()
	in, err := ccv.LoadOutput[ccv.Cfg](smokeTestConfig)
	require.NoError(t, err)

	require.GreaterOrEqual(t, len(in.Verifier), 1, "expected at least one verifier in the environment")
	require.NotNil(t, in.Verifier[0].Out, "first verifier must have output")
	require.NotEmpty(t, in.Verifier[0].Out.ContainerName, "verifier container name must be set")
	verifierID := in.Verifier[0].Out.VerifierID
	require.NotEmpty(t, verifierID, "verifier ID must be set")
	dbConnStr := in.Verifier[0].Out.DBConnectionString
	require.NotEmpty(t, dbConnStr, "verifier DB connection string must be set")

	const (
		fakeJobID  = "f47ac10b-58cc-4372-a567-0e02b2c3d479"
		fakeArchID = int64(9_000_000_001)
		fakeSel    = "12345"
		fakeError  = "injected test failure"
	)
	fakeMessageID := make([]byte, 32)
	fakeMessageID[0] = 0xf4
	fakeMessageID[1] = 0x7a

	db, err := sql.Open("postgres", dbConnStr)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	require.NoError(t, db.Ping(), "must be able to reach the verifier DB")

	vc := verifiercli.NewClient(in.Verifier[0].Out.ContainerName)
	ctx := context.Background()

	t.Cleanup(func() {
		bg := context.Background()
		_, _ = db.ExecContext(bg, "DELETE FROM ccv_task_verifier_jobs_archive WHERE job_id = $1", fakeJobID)
		_, _ = db.ExecContext(bg, "DELETE FROM ccv_task_verifier_jobs WHERE job_id = $1", fakeJobID)
		vc.ResumeBestEffort(ctx)
		_, _ = framework.SaveContainerLogs(fmt.Sprintf("%s-%s", framework.DefaultCTFLogsDir, t.Name()))
	})

	seedTime := time.Now()
	_, err = db.ExecContext(ctx, `
		INSERT INTO ccv_task_verifier_jobs_archive (
			id, job_id, owner_id, chain_selector, message_id, task_data,
			status, created_at, available_at,
			attempt_count, retry_deadline,
			last_error, completed_at
		) VALUES (
			$1, $2, $3, $4, $5, '{}'::jsonb,
			'failed', $7::timestamptz, $7::timestamptz,
			3, $7::timestamptz - INTERVAL '1 hour',
			$6, $7::timestamptz
		)`,
		fakeArchID, fakeJobID, verifierID, fakeSel, fakeMessageID, fakeError, seedTime,
	)
	require.NoError(t, err, "seeding fake failed job into archive")

	require.NoError(t, vc.Pause(ctx), "pausing verifier process before CLI mutations")

	listOut, err := vc.JobQueue().List(ctx, verifiercli.QueueTaskVerifier, verifierID)
	require.NoError(t, err, "list should succeed; output: %s", listOut)
	require.Contains(t, listOut, fakeJobID, "list output must contain the seeded job ID; output: %s", listOut)
	require.Contains(t, listOut, fakeError, "list output must contain the error message; output: %s", listOut)

	rescheduleOut, err := vc.JobQueue().Reschedule(ctx, verifiercli.QueueTaskVerifier, verifierID, fakeJobID, verifiercli.RetryDuration("1h"))
	require.NoError(t, err, "reschedule should succeed; output: %s", rescheduleOut)
	require.Contains(t, rescheduleOut, fakeJobID, "reschedule output must mention job ID; output: %s", rescheduleOut)

	listOut2, err := vc.JobQueue().List(ctx, verifiercli.QueueTaskVerifier, verifierID)
	require.NoError(t, err, "second list should succeed; output: %s", listOut2)
	require.NotContains(t, listOut2, fakeJobID,
		"job must no longer appear in failed archive after reschedule; output: %s", listOut2)

	var pendingCount int
	require.NoError(t, db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM ccv_task_verifier_jobs WHERE job_id = $1 AND status = 'pending'",
		fakeJobID,
	).Scan(&pendingCount))
	require.Equal(t, 1, pendingCount, "rescheduled job must be in the active queue with pending status")

	require.NoError(t, vc.Resume(ctx), "resuming verifier process")
}
