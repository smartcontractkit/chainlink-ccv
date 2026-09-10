package jobqueue

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	cliqueue "github.com/smartcontractkit/chainlink-ccv/cli/jobqueue"
	"github.com/smartcontractkit/chainlink-ccv/verifier/testutil"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/metric"
)

type archiveTestJob struct { Message []byte }
func (j archiveTestJob) JobKey() (uint64, []byte) { return 42, j.Message }

type recordedIntGauge struct {
	metric.Int64Gauge
	values []int64
}
func (g *recordedIntGauge) Record(_ context.Context, value int64, _ ...metric.RecordOption) { g.values = append(g.values, value) }
type ignoredFloatGauge struct { metric.Float64Gauge }
func (*ignoredFloatGauge) Record(context.Context, float64, ...metric.RecordOption) {}
type unavailableArchive struct { sqlutil.DataSource }
func (unavailableArchive) QueryContext(context.Context, string, ...any) (*sql.Rows, error) { return nil, errors.New("archive unavailable") }

func TestArchiveInventoryLifecycle(t *testing.T) {
	ctx := context.Background()
	db := testutil.NewTestDB(t)
	q, err := NewPostgresJobQueue[archiveTestJob](db, QueueConfig{Name: "ccv_task_verifier_jobs", OwnerID: "owner", RetryDuration: time.Hour}, logger.Test(t))
	require.NoError(t, err)
	count, health := &recordedIntGauge{}, &recordedIntGauge{}
	q.archiveMetrics = &archiveMetrics{previous: make(map[archiveKey]archiveSnapshot), count: count, expiring: &recordedIntGauge{},
		age: &ignoredFloatGauge{}, success: health, lastSuccess: &ignoredFloatGauge{}}
	require.NoError(t, q.Publish(ctx, archiveTestJob{Message: []byte{1}}, archiveTestJob{Message: []byte{2}}))
	jobs, err := q.ConsumePending(ctx, 2)
	require.NoError(t, err)
	require.Len(t, jobs, 2)
	require.NoError(t, q.Fail(ctx, map[string]error{jobs[0].ID: errors.New("policy hook rejected: test")}, jobs[0].ID))
	require.NoError(t, q.Complete(ctx, jobs[1].ID))
	_, err = db.ExecContext(ctx, "UPDATE ccv_task_verifier_jobs_archive SET completed_at=NOW()-INTERVAL '24 days' WHERE status='failed'")
	require.NoError(t, err)
	require.NoError(t, q.CollectArchiveMetrics(ctx))
	key := archiveKey{chain: "42", category: "policy_rejected"}
	require.Equal(t, int64(1), q.archiveMetrics.previous[key].Count)
	require.Equal(t, int64(1), q.archiveMetrics.previous[key].Expiring)
	require.GreaterOrEqual(t, q.archiveMetrics.previous[key].OldestAge, (24*24*time.Hour).Seconds())
	q.ds = unavailableArchive{db}
	require.Error(t, q.CollectArchiveMetrics(ctx))
	require.Equal(t, int64(0), health.values[len(health.values)-1])
	require.Equal(t, int64(1), count.values[len(count.values)-1], "failed collection must not clear inventory")
	q.ds = db
	store := cliqueue.NewPostgresStore(db)
	require.NoError(t, store.RescheduleByJobID(ctx, cliqueue.QueueTypeTaskVerifier, "owner", jobs[0].ID, time.Hour))
	require.NoError(t, q.CollectArchiveMetrics(ctx))
	require.Zero(t, count.values[len(count.values)-1], "reschedule clears the retained count")
	require.Empty(t, q.archiveMetrics.previous)
	_, err = db.ExecContext(ctx, "UPDATE ccv_task_verifier_jobs SET retry_deadline=NOW()-INTERVAL '1 second' WHERE owner_id='owner'")
	require.NoError(t, err)
	require.NoError(t, q.Retry(ctx, 0, nil, jobs[0].ID))
	restarted, err := NewPostgresJobQueue[archiveTestJob](db, q.config, logger.Test(t))
	require.NoError(t, err)
	snapshot, err := restarted.archiveSnapshot(ctx)
	require.NoError(t, err)
	require.Equal(t, int64(1), snapshot[archiveKey{chain: "42", category: "retry_window_expired"}].Count)
	_, err = db.ExecContext(ctx, "UPDATE ccv_task_verifier_jobs_archive SET completed_at=NOW()-INTERVAL '31 days'")
	require.NoError(t, err)
	_, err = q.Cleanup(ctx, ArchiveRetention)
	require.NoError(t, err)
	snapshot, err = q.archiveSnapshot(ctx)
	require.NoError(t, err)
	require.Empty(t, snapshot)
}

func TestFailureCategoryPrecedence(t *testing.T) {
	for _, tc := range []struct {
		queue, message, want string
	}{
		{"ccv_task_verifier_jobs", "policy hook rejected: unmarshal failure", "policy_rejected"},
		{"ccv_storage_writer_jobs", "failed to unmarshal task", "validation_error"},
		{"ccv_storage_writer_jobs", "connection refused", "storage_failure"},
		{"ccv_task_verifier_jobs", "unsupported message version", "validation_error"},
		{"ccv_task_verifier_jobs", "legacy error", "unknown"},
	} { require.Equal(t, tc.want, FailureCategory(tc.queue, errors.New(tc.message))) }
}

// Cost fixture: 100k retained rows, 100 owners, JSON payloads deliberately omitted
// from the covering query. CI logs the actual plan, buffers and elapsed time.
func TestArchiveInventoryRepresentativePlan(t *testing.T) {
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, err := db.ExecContext(ctx, `INSERT INTO ccv_task_verifier_jobs_archive
		(id,job_id,owner_id,chain_selector,message_id,task_data,status,created_at,available_at,attempt_count,retry_deadline,completed_at)
		SELECT n,md5(n::text)::uuid,'owner-'||(n%100),42,decode(md5(n::text),'hex'),'{}','failed',NOW(),NOW(),1,NOW(),NOW()-INTERVAL '24 days'
		FROM generate_series(1,100000) n`)
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, "VACUUM (ANALYZE) ccv_task_verifier_jobs_archive")
	require.NoError(t, err)
	rows, err := db.QueryContext(ctx, `EXPLAIN (ANALYZE, BUFFERS) SELECT chain_selector, failure_category, COUNT(*),
		COUNT(*) FILTER (WHERE completed_at <= NOW()-INTERVAL '23 days'), MIN(completed_at)
		FROM ccv_task_verifier_jobs_archive WHERE owner_id='owner-1' AND status='failed' GROUP BY chain_selector,failure_category`)
	require.NoError(t, err)
	defer func() { _ = rows.Close() }()
	var plan strings.Builder
	for rows.Next() {
		var line string
		require.NoError(t, rows.Scan(&line))
		plan.WriteString(line+"\n")
	}
	require.NoError(t, rows.Err())
	t.Log(plan.String())
	require.Contains(t, plan.String(), "idx_ccv_task_archive_inventory")
}
