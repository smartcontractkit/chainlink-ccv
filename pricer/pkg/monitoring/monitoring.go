package monitoring

import (
	"fmt"

	"github.com/grafana/pyroscope-go"

	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
	"github.com/smartcontractkit/chainlink-common/pkg/metrics"
)

// Monitoring provides monitoring capabilities for the pricer service.
type Monitoring interface {
	// Metrics returns the metric labeler for recording metrics.
	Metrics() *PricerMetricLabeler
}

// InitMonitoring initializes the beholder monitoring system for the pricer.
func InitMonitoring(config beholder.Config) (Monitoring, error) {
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

	// Initialize the pricer metrics
	pricerMetrics, err := InitMetrics()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize pricer metrics: %w", err)
	}

	// Initialize Pyroscope for profiling
	if _, err := pyroscope.Start(pyroscope.Config{
		ApplicationName: "pricer",
		ServerAddress:   "http://pyroscope:4040",
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

	return &PricerBeholderMonitoring{
		metrics: NewPricerMetricLabeler(metrics.NewLabeler(), pricerMetrics),
	}, nil
}

var (
	_ Monitoring = (*PricerBeholderMonitoring)(nil)
	_ Monitoring = (*NoopPricerMonitoring)(nil)
)

// PricerBeholderMonitoring provides beholder-based monitoring for the pricer.
type PricerBeholderMonitoring struct {
	metrics *PricerMetricLabeler
}

func (p *PricerBeholderMonitoring) Metrics() *PricerMetricLabeler {
	return p.metrics
}

// NoopPricerMonitoring provides a no-op implementation of Monitoring.
type NoopPricerMonitoring struct {
	metrics *PricerMetricLabeler
}

// NewNoopPricerMonitoring creates a new noop monitoring instance.
func NewNoopPricerMonitoring() Monitoring {
	return &NoopPricerMonitoring{
		metrics: NewNoopPricerMetricLabeler(),
	}
}

func (n *NoopPricerMonitoring) Metrics() *PricerMetricLabeler {
	return n.metrics
}
