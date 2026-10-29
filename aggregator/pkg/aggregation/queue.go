package aggregation

import (
	"context"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/common/jobqueue"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
)

const (
	// QueueTableName is the table backing the aggregation job queue.
	QueueTableName = "ccv_aggregation_jobs"
	// queueOwnerID is shared by every aggregator replica so they all consume from the
	// same logical queue and a request is processed exactly once.
	queueOwnerID = "aggregator"
	// queueRetryDuration is how long from creation an aggregation job stays eligible for retry.
	queueRetryDuration = 30 * time.Minute
	// queueLockDuration is how long a job may stay in 'processing' before another replica
	// may reclaim it.
	queueLockDuration = 2 * time.Minute
	// queueObservabilityInterval is how often queue size metrics are logged and recorded.
	queueObservabilityInterval = 10 * time.Second
)

// Queue is the durable queue carrying aggregation requests.
type Queue = jobqueue.JobQueue[aggregationRequest]

// NewQueue creates the aggregation request queue.
func NewQueue(ds sqlutil.DataSource, lggr logger.Logger, recordSizeMetric func(ctx context.Context, size int64)) (*jobqueue.ObservabilityDecorator[aggregationRequest], error) {
	queue, err := jobqueue.NewPostgresJobQueue[aggregationRequest](ds, jobqueue.QueueConfig{
		Name:          QueueTableName,
		OwnerID:       queueOwnerID,
		RetryDuration: queueRetryDuration,
		LockDuration:  queueLockDuration,
		// A publish arriving while an earlier job for the same message is 'processing'
		// must queue a fresh pending job rather than be dropped; see the migration's
		// ccv_aggregation_jobs_unique_job index.
		UniqueWhilePending: true,
	}, lggr)
	if err != nil {
		return nil, err
	}
	return jobqueue.NewObservabilityDecorator(queue, lggr, queueObservabilityInterval, recordSizeMetric)
}
