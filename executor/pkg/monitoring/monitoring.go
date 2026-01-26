package monitoring

import (
	"context"
	"fmt"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/executor"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/metrics"
)

// InitMonitoring initializes the beholder monitoring system for the executor.
func InitMonitoring() (executor.Monitoring, error) {
	// Initialize the executor metrics
	executorMetrics, err := InitMetrics()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize executor metrics: %w", err)
	}

	return &ExecutorBeholderMonitoring{
		metrics: NewExecutorMetricLabeler(metrics.NewLabeler(), executorMetrics),
	}, nil
}

var (
	_ executor.Monitoring = (*ExecutorBeholderMonitoring)(nil)
	_ executor.Monitoring = (*NoopExecutorMonitoring)(nil)
)

// ExecutorBeholderMonitoring provides beholder-based monitoring for the executor.
type ExecutorBeholderMonitoring struct {
	metrics executor.MetricLabeler
}

func (v *ExecutorBeholderMonitoring) Metrics() executor.MetricLabeler {
	return v.metrics
}

// NoopExecutorMonitoring provides a no-op implementation of ExecutorMonitoring.
type NoopExecutorMonitoring struct {
	noop executor.MetricLabeler
}

// NewNoopExecutorMonitoring creates a new noop monitoring instance.
func NewNoopExecutorMonitoring() executor.Monitoring {
	return &NoopExecutorMonitoring{
		noop: NewNoopExecutorMetricLabeler(),
	}
}

func (n *NoopExecutorMonitoring) Metrics() executor.MetricLabeler {
	return n.noop
}

var _ executor.MetricLabeler = (*NoopExecutorMetricLabeler)(nil)

// NoopExecutorMetricLabeler provides a no-op implementation of ExecutorMetricLabeler.
type NoopExecutorMetricLabeler struct{}

// NewNoopExecutorMetricLabeler creates a new noop metric labeler.
func NewNoopExecutorMetricLabeler() executor.MetricLabeler {
	return &NoopExecutorMetricLabeler{}
}

func (n *NoopExecutorMetricLabeler) With(keyValues ...string) executor.MetricLabeler {
	return n
}

func (n *NoopExecutorMetricLabeler) RecordMessageExecutionLatency(ctx context.Context, duration time.Duration, destSelector protocol.ChainSelector) {
}

func (n *NoopExecutorMetricLabeler) IncrementMessagesProcessed(ctx context.Context) {}

func (n *NoopExecutorMetricLabeler) IncrementMessagesProcessingFailed(ctx context.Context) {}

func (n *NoopExecutorMetricLabeler) IncrementCCVInfoCacheHits(ctx context.Context) {}

func (n *NoopExecutorMetricLabeler) IncrementCCVInfoCacheMisses(ctx context.Context) {}

func (n *NoopExecutorMetricLabeler) RecordQueryCCVInfoLatency(ctx context.Context, duration time.Duration, destSelector protocol.ChainSelector) {
}

func (n *NoopExecutorMetricLabeler) IncrementExpiredMessages(ctx context.Context) {}

func (n *NoopExecutorMetricLabeler) IncrementAlreadyExecutedMessages(ctx context.Context) {}

func (n *NoopExecutorMetricLabeler) RecordMessageHeapSize(ctx context.Context, size int64) {}
