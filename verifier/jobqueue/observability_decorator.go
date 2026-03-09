package jobqueue

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/services"
)

const (
	// DefaultObservabilityInterval is how often to log queue size metrics.
	DefaultObservabilityInterval = 10 * time.Second
	// queueSizeQueryTimeout is the maximum time to wait for a queue size query.
	// This prevents the monitoring loop from hanging if the database is under high pressure.
	queueSizeQueryTimeout = 2 * time.Second
)

// ObservabilityDecorator wraps a JobQueue and adds observability capabilities.
// It implements both JobQueue and Service interfaces.
// It periodically logs queue size metrics for monitoring.
type ObservabilityDecorator[T Jobable] struct {
	services.StateMachine
	stopCh services.StopChan
	wg     sync.WaitGroup

	lggr             logger.Logger
	interval         time.Duration
	queue            JobQueue[T]
	recordSizeMetric func(ctx context.Context, size int64)
}

// NewObservabilityDecorator creates a new observability decorator for a JobQueue.
// The recordSizeMetric function is required and will be called with the queue size
// on each monitoring cycle to record metrics.
func NewObservabilityDecorator[T Jobable](
	queue JobQueue[T],
	lggr logger.Logger,
	interval time.Duration,
	recordSizeMetric func(ctx context.Context, size int64),
) (*ObservabilityDecorator[T], error) {
	if queue == nil {
		return nil, fmt.Errorf("queue cannot be nil")
	}
	if lggr == nil {
		return nil, fmt.Errorf("logger cannot be nil")
	}
	if recordSizeMetric == nil {
		return nil, fmt.Errorf("recordSizeMetric cannot be nil")
	}
	if interval == 0 {
		interval = DefaultObservabilityInterval
	}

	return &ObservabilityDecorator[T]{
		stopCh:           make(chan struct{}),
		queue:            queue,
		lggr:             lggr,
		interval:         interval,
		recordSizeMetric: recordSizeMetric,
	}, nil
}

// Start begins the observability monitoring loop.
func (d *ObservabilityDecorator[T]) Start(ctx context.Context) error {
	return d.StartOnce(d.Name(), func() error {
		d.lggr.Infow("Starting JobQueue observability monitoring",
			"queue", d.queue.Name(),
			"interval", d.interval,
		)
		d.wg.Go(d.monitorLoop)
		return nil
	})
}

// Close stops the observability monitoring loop.
func (d *ObservabilityDecorator[T]) Close() error {
	return d.StopOnce(d.Name(), func() error {
		d.lggr.Infow("Stopping JobQueue observability monitoring",
			"queue", d.queue.Name(),
		)
		close(d.stopCh)
		d.wg.Wait()
		d.lggr.Infow("JobQueue observability monitoring stopped",
			"queue", d.queue.Name(),
		)
		return nil
	})
}

// Name returns the name of the service.
func (d *ObservabilityDecorator[T]) Name() string {
	return fmt.Sprintf("jobqueue.ObservabilityDecorator[%s]", d.queue.Name())
}

// Ready returns nil if the service is ready.
func (d *ObservabilityDecorator[T]) Ready() error {
	return d.StateMachine.Ready()
}

// HealthReport returns a health report for the decorator.
func (d *ObservabilityDecorator[T]) HealthReport() map[string]error {
	report := make(map[string]error)
	report[d.Name()] = d.Ready()
	return report
}

// monitorLoop is the main loop that periodically logs queue size metrics.
func (d *ObservabilityDecorator[T]) monitorLoop() {
	ctx, cancel := d.stopCh.NewCtx()
	defer cancel()

	ticker := time.NewTicker(d.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			d.lggr.Infow("Observability monitoring loop stopped",
				"queue", d.queue.Name(),
			)
			return
		case <-ticker.C:
			d.logQueueSize(ctx)
		}
	}
}

// logQueueSize retrieves and logs the current queue size.
func (d *ObservabilityDecorator[T]) logQueueSize(ctx context.Context) {
	// Create a context with timeout to prevent hanging if database is under pressure
	queryCtx, cancel := context.WithTimeout(ctx, queueSizeQueryTimeout)
	defer cancel()

	size, err := d.queue.Size(queryCtx)
	if err != nil {
		d.lggr.Errorw("Failed to get queue size",
			"queue", d.queue.Name(),
			"error", err,
		)
		return
	}

	d.lggr.Infow("JobQueue size",
		"queue", d.queue.Name(),
		"size", size,
	)

	d.recordSizeMetric(ctx, int64(size))
}

// Delegate all JobQueue interface methods to the underlying queue

// Publish adds one or more jobs to the queue.
func (d *ObservabilityDecorator[T]) Publish(ctx context.Context, jobs ...T) error {
	return d.queue.Publish(ctx, jobs...)
}

// PublishWithDelay adds jobs that become available after the specified delay.
func (d *ObservabilityDecorator[T]) PublishWithDelay(ctx context.Context, delay time.Duration, jobs ...T) error {
	return d.queue.PublishWithDelay(ctx, delay, jobs...)
}

// Consume retrieves and locks up to batchSize jobs for processing.
func (d *ObservabilityDecorator[T]) Consume(ctx context.Context, batchSize int) ([]Job[T], error) {
	return d.queue.Consume(ctx, batchSize)
}

// Complete marks jobs as successfully processed and removes them from active queue.
func (d *ObservabilityDecorator[T]) Complete(ctx context.Context, jobIDs ...string) error {
	return d.queue.Complete(ctx, jobIDs...)
}

// Retry schedules jobs for retry after the specified delay.
func (d *ObservabilityDecorator[T]) Retry(ctx context.Context, delay time.Duration, errors map[string]error, jobIDs ...string) error {
	return d.queue.Retry(ctx, delay, errors, jobIDs...)
}

// Fail marks jobs as permanently failed.
func (d *ObservabilityDecorator[T]) Fail(ctx context.Context, errors map[string]error, jobIDs ...string) error {
	return d.queue.Fail(ctx, errors, jobIDs...)
}

// Cleanup archives or deletes jobs older than the retention period.
func (d *ObservabilityDecorator[T]) Cleanup(ctx context.Context, retentionPeriod time.Duration) (int, error) {
	return d.queue.Cleanup(ctx, retentionPeriod)
}

// Size returns the count of jobs that are pending or processing.
func (d *ObservabilityDecorator[T]) Size(ctx context.Context) (int, error) {
	return d.queue.Size(ctx)
}
