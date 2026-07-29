package monitoring

import (
	"context"
	"fmt"
	"time"

	commonmetrics "github.com/smartcontractkit/chainlink-ccv/common/metrics"
	"github.com/smartcontractkit/chainlink-ccv/common/monitoring/tracing"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
	"github.com/smartcontractkit/chainlink-common/pkg/metrics"
)

// InitMonitoring initializes the beholder monitoring system for the executor.
func InitMonitoring() (Monitoring, error) {
	// Initialize the executor metrics
	executorMetrics, err := InitMetrics()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize executor metrics: %w", err)
	}

	serviceMetrics, err := commonmetrics.NewServiceMetrics(metrics.NewLabeler(), "executor")
	if err != nil {
		return nil, fmt.Errorf("failed to create service metrics: %w", err)
	}

	return &ExecutorBeholderMonitoring{
		metrics:        NewExecutorMetricLabeler(metrics.NewLabeler(), executorMetrics),
		tracing:        tracing.NewTracing(beholder.GetTracer()),
		ServiceMetrics: serviceMetrics,
	}, nil
}

var (
	_ Monitoring = (*ExecutorBeholderMonitoring)(nil)
	_ Monitoring = (*NoopExecutorMonitoring)(nil)
)

// ExecutorBeholderMonitoring provides beholder-based monitoring for the executor.
type ExecutorBeholderMonitoring struct {
	metrics MetricLabeler
	tracing tracing.Tracing
	commonmetrics.ServiceMetrics
}

func (v *ExecutorBeholderMonitoring) Metrics() MetricLabeler {
	return v.metrics
}

func (v *ExecutorBeholderMonitoring) Tracing() tracing.Tracing {
	return v.tracing
}

// noopServiceMetrics implements commonmetrics.ServiceMetrics with no-op behavior for noop monitoring.
type noopServiceMetrics struct{}

func (noopServiceMetrics) RecordServiceStarted(context.Context) {}

// NoopExecutorMonitoring provides a no-op implementation of ExecutorMonitoring.
type NoopExecutorMonitoring struct {
	noop    MetricLabeler
	tracing tracing.Tracing
	commonmetrics.ServiceMetrics
}

// NewNoopExecutorMonitoring creates a new noop monitoring instance.
func NewNoopExecutorMonitoring() Monitoring {
	return &NoopExecutorMonitoring{
		noop:           NewNoopExecutorMetricLabeler(),
		tracing:        tracing.NewTracing(beholder.GetTracer()),
		ServiceMetrics: noopServiceMetrics{},
	}
}

func (n *NoopExecutorMonitoring) Metrics() MetricLabeler {
	return n.noop
}

func (n *NoopExecutorMonitoring) Tracing() tracing.Tracing {
	return n.tracing
}

var _ MetricLabeler = (*NoopExecutorMetricLabeler)(nil)

// NoopExecutorMetricLabeler provides a no-op implementation of ExecutorMetricLabeler.
type NoopExecutorMetricLabeler struct{}

// NewNoopExecutorMetricLabeler creates a new noop metric labeler.
func NewNoopExecutorMetricLabeler() MetricLabeler {
	return &NoopExecutorMetricLabeler{}
}

func (n *NoopExecutorMetricLabeler) With(keyValues ...string) MetricLabeler {
	return n
}

func (n *NoopExecutorMetricLabeler) RecordMessageExecutionLatency(ctx context.Context, duration time.Duration, destChainSelector protocol.ChainSelector) {
}

func (n *NoopExecutorMetricLabeler) IncrementMessagesProcessing(ctx context.Context) {}

func (n *NoopExecutorMetricLabeler) IncrementMessagesProcessingError(ctx context.Context, retry bool) {
}

func (n *NoopExecutorMetricLabeler) RecordOfframpGetCCVsForMessageLatency(ctx context.Context, duration time.Duration, destChainSelector protocol.ChainSelector) {
}

func (n *NoopExecutorMetricLabeler) IncrementOfframpGetCCVsForMessageFailure(ctx context.Context, destChainSelector protocol.ChainSelector) {
}

func (n *NoopExecutorMetricLabeler) IncrementExpiredMessages(ctx context.Context) {}

func (n *NoopExecutorMetricLabeler) IncrementAlreadyExecutedMessages(ctx context.Context) {}

func (n *NoopExecutorMetricLabeler) RecordMessageHeapSize(ctx context.Context, size int64) {}

func (n *NoopExecutorMetricLabeler) IncrementHeartbeatSuccess(ctx context.Context) {}

func (n *NoopExecutorMetricLabeler) IncrementHeartbeatFailure(ctx context.Context) {}

func (n *NoopExecutorMetricLabeler) IncrementAllIndexersFailed(ctx context.Context) {}

func (n *NoopExecutorMetricLabeler) IncrementIndexerSwitch(ctx context.Context) {}

func (n *NoopExecutorMetricLabeler) SetLastHeartbeatTimestamp(ctx context.Context, timestamp int64) {}

func (n *NoopExecutorMetricLabeler) IncrementUnrecoverableMessageFailure(ctx context.Context) {}

func (n *NoopExecutorMetricLabeler) IncrementDestinationReaderCriticalFailure(ctx context.Context, destChainSelector protocol.ChainSelector) {
}

func (n *NoopExecutorMetricLabeler) SetRemoteChainCursed(ctx context.Context, localSelector, remoteSelector protocol.ChainSelector, cursed bool) {
}

func (n *NoopExecutorMetricLabeler) SetLocalChainGlobalCursed(ctx context.Context, localSelector protocol.ChainSelector, globalCurse bool) {
}
