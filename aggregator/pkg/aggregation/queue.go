package aggregation

import (
	"context"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/common/jobqueue"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
)

const (
	queueTableName = "ccv_aggregation_jobs"
	// queueOwnerID is shared by every replica, so they all consume one logical queue. Delivery is
	// at least once (retries, stale reclaim); aggregation is idempotent.
	queueOwnerID = "aggregator"
	// queueRetryDuration is how long from creation an aggregation job stays eligible for retry.
	queueRetryDuration = 30 * time.Minute
	// queueObservabilityInterval is how often queue size metrics are logged and recorded.
	queueObservabilityInterval = 10 * time.Second
)

// NewQueue creates the aggregation request queue.
func NewQueue(ds sqlutil.DataSource, lggr logger.Logger, recordSizeMetric func(ctx context.Context, size int64)) (*jobqueue.ObservabilityDecorator[aggregationRequest], error) {
	queue, err := jobqueue.NewPostgresJobQueue[aggregationRequest](ds, jobqueue.QueueConfig{
		Name:          queueTableName,
		OwnerID:       queueOwnerID,
		RetryDuration: queueRetryDuration,
		LockDuration:  model.AggregationJobLockDuration,
		// One replica aggregates a key at a time; writes during that run queue one re-run behind it.
		SerializePerKey: true,
	}, lggr)
	if err != nil {
		return nil, err
	}
	return jobqueue.NewObservabilityDecorator(queue, lggr, queueObservabilityInterval, recordSizeMetric)
}
