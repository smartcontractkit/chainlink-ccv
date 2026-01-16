package monitoring

// Monitoring provides monitoring capabilities for the pricer service.
type Monitoring interface {
	// Metrics returns the metric labeler for recording metrics.
	Metrics() *PricerMetricLabeler
}

// PricerPromMonitoring provides Prometheus-based monitoring for the pricer.
type PricerPromMonitoring struct {
	metrics *PricerMetricLabeler
}

func (p *PricerPromMonitoring) Metrics() *PricerMetricLabeler {
	return p.metrics
}

// NewPricerMonitoring creates a new Prometheus-based monitoring instance.
func NewPricerMonitoring(chainID string) Monitoring {
	return &PricerPromMonitoring{
		metrics: NewPricerMetricLabeler(chainID),
	}
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
