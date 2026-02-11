package middlewares

import (
	"context"
	"time"

	"google.golang.org/grpc"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/scope"
)

type MetricMiddleware struct {
	m common.AggregatorMonitoring
}

func (m *MetricMiddleware) Intercept(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
	startTime := time.Now()
	metrics := scope.AugmentMetrics(ctx, m.m.Metrics())
	metrics.IncrementActiveRequestsCounter(ctx)
	defer metrics.DecrementActiveRequestsCounter(ctx)
	defer func() {
		duration := time.Since(startTime)
		metrics.RecordAPIRequestDuration(ctx, duration)
	}()

	resp, err = handler(ctx, req)
	if err != nil {
		metrics.IncrementAPIRequestErrors(ctx, info.FullMethod)
	}
	return resp, err
}

func NewMetricMiddleware(
	m common.AggregatorMonitoring,
) *MetricMiddleware {
	return &MetricMiddleware{
		m: m,
	}
}
