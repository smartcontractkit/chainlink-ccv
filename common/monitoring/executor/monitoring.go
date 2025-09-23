package executormonitoring

import (
	"fmt"

	"github.com/smartcontractkit/chainlink-ccv/executor"
	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
	"github.com/smartcontractkit/chainlink-common/pkg/metrics"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

var _ executor.Monitoring = (*ExecutorBeholderMonitoring)(nil)

type ExecutorBeholderMonitoring struct {
	metrics ExecutorMetricLabeler
}

func InitMonitoring(config beholder.Config) (*ExecutorBeholderMonitoring, error) {
	// Note: due to OTEL spec, all histogram buckets must be defined when the beholder client is created.
	config.MetricViews = []sdkmetric.View{}

	// Create the beholder client
	client, err := beholder.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create beholder client: %w", err)
	}

	// Set the beholder client and global otel providers, so they don't have to be referenced elsewhere.
	beholder.SetClient(client)
	beholder.SetGlobalOtelProviders()

	// Initialize the executor metrics
	executorMetrics, err := InitMetrics()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize executor metrics: %w", err)
	}

	return &ExecutorBeholderMonitoring{
		metrics: *NewExecutorMetricLabeler(metrics.NewLabeler(), executorMetrics),
	}, nil
}

func (e *ExecutorBeholderMonitoring) Metrics() executor.MetricLabeler {
	return e.metrics
}
