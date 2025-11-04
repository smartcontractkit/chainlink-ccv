package middlewares

import (
	"context"
	"testing"

	"google.golang.org/grpc"

	aggregation_mocks "github.com/smartcontractkit/chainlink-ccv/aggregator/internal/aggregation_mocks"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/scope"
)

func TestScopingMiddleware_SetsAPINameInContext(t *testing.T) {
    m := NewScopingMiddleware()

    // Prepare a mock labeler to assert AugmentMetrics adds apiName label
    labeler := aggregation_mocks.NewMockAggregatorMetricLabeler(t)
    // Expect apiName to be added by middleware
    fullMethod := "/chainlink_ccv.v1.VerifierResultAPI/GetMessagesSince"
    labeler.EXPECT().With("apiName", fullMethod).Return(labeler)

    info := &grpc.UnaryServerInfo{FullMethod: fullMethod}

    handler := func(ctx context.Context, req any) (any, error) {
        // Scoping middleware should have placed apiName in context
        _ = scope.AugmentMetrics(ctx, labeler)
        return nil, nil
    }

    _, _ = m.Intercept(context.Background(), nil, info, handler)
}


