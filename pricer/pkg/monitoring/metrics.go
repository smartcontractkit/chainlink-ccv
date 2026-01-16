package monitoring

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	PromPricerEVMTickDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "pricer_evm_tick_duration_seconds",
			Help: "Duration of EVM tick operations in seconds",
			Buckets: []float64{
				0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10,
			},
		},
		[]string{"chainID"},
	)
)

// PricerMetricLabeler provides a simple interface for recording metrics.
type PricerMetricLabeler struct {
	chainID string
}

// NewPricerMetricLabeler creates a new metric labeler for the pricer service.
func NewPricerMetricLabeler(chainID string) *PricerMetricLabeler {
	return &PricerMetricLabeler{
		chainID: chainID,
	}
}

// RecordEVMTickDuration records the duration of an EVM tick operation.
func (p *PricerMetricLabeler) RecordEVMTickDuration(duration time.Duration) {
	if p == nil || p.chainID == "" {
		return
	}
	PromPricerEVMTickDuration.WithLabelValues(p.chainID).Observe(duration.Seconds())
}

// NewNoopPricerMetricLabeler creates a noop metric labeler that doesn't record metrics.
func NewNoopPricerMetricLabeler() *PricerMetricLabeler {
	return &PricerMetricLabeler{
		chainID: "", // empty chainID means no-op
	}
}
