package monitoring

import (
	"github.com/smartcontractkit/chainlink-common/pkg/metrics"
)

// NewNoopPricerMetricLabeler creates a new noop metric labeler.
// The PricerMetricLabeler methods already handle nil metrics gracefully.
func NewNoopPricerMetricLabeler() *PricerMetricLabeler {
	return &PricerMetricLabeler{
		Labeler: metrics.NewLabeler(),
		pm:      nil, // nil metrics means no-op
	}
}
