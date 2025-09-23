package monitoring

import (
	"context"

	"github.com/smartcontractkit/chainlink-ccv/executor"
)

var _ executor.Monitoring = (*NoopExecutorMonitoring)(nil)

type NoopExecutorMonitoring struct {
	noop executor.MetricLabeler
}

func NewNoopExecutorMonitoring() executor.Monitoring {
	return &NoopExecutorMonitoring{noop: NewNoopExecutorMetricLabeler()}
}

func (n *NoopExecutorMonitoring) Metrics() executor.MetricLabeler {
	return n.noop
}

type NoopExecutorMetricLabeler struct{}

func NewNoopExecutorMetricLabeler() executor.MetricLabeler {
	return &NoopExecutorMetricLabeler{}
}

func (n *NoopExecutorMetricLabeler) With(keyValues ...string) executor.MetricLabeler {
	return n
}

func (n *NoopExecutorMetricLabeler) IncrementUniqueMessagesCounter(ctx context.Context) {}
