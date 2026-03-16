package monitoring

import (
	"context"
	"fmt"

	"github.com/grafana/pyroscope-go"

	commonmetrics "github.com/smartcontractkit/chainlink-ccv/common/metrics"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
	"github.com/smartcontractkit/chainlink-common/pkg/metrics"
)

type AggregatorBeholderMonitoring struct {
	metrics        common.AggregatorMetricLabeler
	serviceMetrics commonmetrics.ServiceMetrics
}

func InitMonitoring(config beholder.Config) (common.AggregatorMonitoring, error) {
	config.MetricViews = MetricViews()

	// Create the beholder client
	client, err := beholder.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create beholder client: %w", err)
	}

	// Set the beholder client and global otel providers, so they don't have to be referenced elsewhere.
	beholder.SetClient(client)
	beholder.SetGlobalOtelProviders()

	// Initialize the aggregator metrics
	aggregatorMetrics, err := InitMetrics()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize aggregator metrics: %w", err)
	}

	serviceMetrics, err := commonmetrics.NewServiceMetrics(metrics.NewLabeler(), "aggregator")
	if err != nil {
		return nil, fmt.Errorf("failed to create service metrics: %w", err)
	}

	if _, err := pyroscope.Start(pyroscope.Config{
		ApplicationName: "aggregator",
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

	return &AggregatorBeholderMonitoring{
		metrics:        NewAggregatorMetricLabeler(metrics.NewLabeler(), aggregatorMetrics),
		serviceMetrics: serviceMetrics,
	}, nil
}

func (m *AggregatorBeholderMonitoring) Metrics() common.AggregatorMetricLabeler {
	return m.metrics
}

func (m *AggregatorBeholderMonitoring) RecordServiceStarted(ctx context.Context) {
	m.serviceMetrics.RecordServiceStarted(ctx)
}
