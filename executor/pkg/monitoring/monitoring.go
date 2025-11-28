package monitoring

import (
	"context"
	"fmt"
	"time"

	"github.com/grafana/pyroscope-go"

	"github.com/smartcontractkit/chainlink-ccv/executor"
	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
	"github.com/smartcontractkit/chainlink-common/pkg/metrics"
)

// ExecutorBeholderMonitoring provides beholder-based monitoring for the executor.
type ExecutorBeholderMonitoring struct {
	metrics executor.MetricLabeler
}

// InitMonitoring initializes the beholder monitoring system for the executor.
func InitMonitoring(config beholder.Config) (executor.Monitoring, error) {
	// Note: due to OTEL spec, all histogram buckets must be defined when the beholder client is created.
	config.MetricViews = MetricViews()

	// Create the beholder client
	client, err := beholder.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create beholder client: %w", err)
	}

	// Set the beholder client and global otel providers
	beholder.SetClient(client)
	beholder.SetGlobalOtelProviders()

	// Initialize the executor metrics
	executorMetrics, err := InitMetrics()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize executor metrics: %w", err)
	}

	// Initialize pyroscope for continuous profiling
	if _, err := pyroscope.Start(pyroscope.Config{
		ApplicationName: "executor",
		ServerAddress:   "http://pyroscope:4040",
		Logger:          pyroscope.StandardLogger,
		ProfileTypes: []pyroscope.ProfileType{
			pyroscope.ProfileCPU,
			pyroscope.ProfileAllocObjects,
			pyroscope.ProfileAllocSpace,
			pyroscope.ProfileGoroutines,
			pyroscope.ProfileBlockDuration,
			pyroscope.ProfileMutexDuration,
		},
	}); err != nil {
		return nil, fmt.Errorf("failed to initialize pyroscope client: %w", err)
	}

	return &ExecutorBeholderMonitoring{
		metrics: NewExecutorMetricLabeler(metrics.NewLabeler(), executorMetrics),
	}, nil
}

func (v *ExecutorBeholderMonitoring) Metrics() executor.MetricLabeler {
	return v.metrics
}

var _ executor.Monitoring = (*NoopExecutorMonitoring)(nil)

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

func (n *NoopExecutorMetricLabeler) RecordMessageExecutionLatency(ctx context.Context, duration time.Duration) {
}

func (n *NoopExecutorMetricLabeler) RecordMessageE2ELatency(ctx context.Context, duration time.Duration) {
}

func (n *NoopExecutorMetricLabeler) IncrementMessagesProcessed(ctx context.Context) {}

func (n *NoopExecutorMetricLabeler) IncrementMessagesProcessingFailed(ctx context.Context) {}
