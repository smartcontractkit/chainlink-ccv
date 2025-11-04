package middlewares

import (
    "context"
    "errors"
    "testing"

    "google.golang.org/grpc"
    "github.com/stretchr/testify/mock"

    aggregation_mocks "github.com/smartcontractkit/chainlink-ccv/aggregator/internal/aggregation_mocks"
)

func TestMetricMiddleware_RecordsSuccessAndDuration(t *testing.T) {
    metric := aggregation_mocks.NewMockAggregatorMetricLabeler(t)
    monitoring := aggregation_mocks.NewMockAggregatorMonitoring(t)

    monitoring.EXPECT().Metrics().Return(metric)
    metric.EXPECT().With("apiName", "/svc/Method").Return(metric).Maybe()
    metric.EXPECT().IncrementActiveRequestsCounter(context.Background())
    metric.EXPECT().DecrementActiveRequestsCounter(context.Background())
    metric.EXPECT().RecordAPIRequestDuration(context.Background(), mock.Anything)

    mm := NewMetricMiddleware(monitoring)
    info := &grpc.UnaryServerInfo{FullMethod: "/svc/Method"}
    handler := func(ctx context.Context, req any) (any, error) { return "ok", nil }

    _, _ = mm.Intercept(context.Background(), nil, info, handler)
}

func TestMetricMiddleware_RecordsError(t *testing.T) {
    metric := aggregation_mocks.NewMockAggregatorMetricLabeler(t)
    monitoring := aggregation_mocks.NewMockAggregatorMonitoring(t)

    monitoring.EXPECT().Metrics().Return(metric)
    metric.EXPECT().With("apiName", "/svc/Err").Return(metric).Maybe()
    metric.EXPECT().IncrementActiveRequestsCounter(context.Background())
    metric.EXPECT().DecrementActiveRequestsCounter(context.Background())
    metric.EXPECT().RecordAPIRequestDuration(context.Background(), mock.Anything)
    metric.EXPECT().IncrementAPIRequestErrors(context.Background())

    mm := NewMetricMiddleware(monitoring)
    info := &grpc.UnaryServerInfo{FullMethod: "/svc/Err"}
    handler := func(ctx context.Context, req any) (any, error) { return nil, errors.New("boom") }

    _, _ = mm.Intercept(context.Background(), nil, info, handler)
}


