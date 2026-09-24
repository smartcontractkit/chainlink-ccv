package jobqueue

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/jobqueue/archivecategory"
	"github.com/smartcontractkit/chainlink-ccv/verifier/testutil"
)

// The vocabulary lives in SQL, so it is pinned against real rows rather than a Go
// helper: precedence, the timestamp-derived retry expiry, and the closed "unknown"
// fallback.
func TestArchiveFailureCategory(t *testing.T) {
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	for i, tc := range []struct {
		name, table, message string
		expired              bool
		want                 string
	}{
		{"policy beats validation", "ccv_task_verifier_jobs", "policy hook rejected: unmarshal failure", false, "policy_rejected"},
		{"validation beats storage queue", "ccv_storage_writer_jobs", "failed to unmarshal task", false, "validation_error"},
		{"storage queue fallback", "ccv_storage_writer_jobs", "connection refused", false, "storage_failure"},
		{"validation on task queue", "ccv_task_verifier_jobs", "unsupported message version", false, "validation_error"},
		{"unmatched error is unknown", "ccv_task_verifier_jobs", "legacy error", false, "unknown"},
		// Expiry is decided by the timestamps, so it outranks whatever error last failed the job.
		{"deadline passed wins", "ccv_task_verifier_jobs", "policy hook rejected: blocked", true, "retry_window_expired"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			archive := tc.table + "_archive"
			deadline := "NOW() + INTERVAL '1 hour'"
			if tc.expired {
				deadline = "NOW() - INTERVAL '1 hour'"
			}
			_, err := db.ExecContext(ctx, fmt.Sprintf(`INSERT INTO %s
				(id,job_id,owner_id,chain_selector,message_id,task_data,status,created_at,available_at,
				 attempt_count,retry_deadline,last_error,completed_at)
				VALUES ($1::bigint,md5($1::bigint::text)::uuid,'owner-cat',42,
				        decode(md5($1::bigint::text),'hex'),'{}','failed',
				        NOW(),NOW(),1,%s,$2,NOW())`, archive, deadline), i+1, tc.message)
			require.NoError(t, err)

			var got string
			require.NoError(t, db.QueryRowxContext(ctx, fmt.Sprintf(
				"SELECT %s FROM %s WHERE id = $1::bigint", archivecategory.SQL(tc.table), archive), i+1).Scan(&got))
			require.Equal(t, tc.want, got)
		})
	}
}
