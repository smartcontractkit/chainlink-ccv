package middlewares

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
)

func TestMetricMiddleware_Intercept(t *testing.T) {
	t.Run("increments and decrements active requests counter on success", func(t *testing.T) {
		monitoring := mocks.NewMockAggregatorMonitoring(t)
		metrics := mocks.NewMockAggregatorMetricLabeler(t)

		monitoring.EXPECT().Metrics().Return(metrics)
		metrics.EXPECT().IncrementActiveRequestsCounter(mock.Anything).Once()
		metrics.EXPECT().DecrementActiveRequestsCounter(mock.Anything).Once()
		metrics.EXPECT().RecordAPIRequestDuration(mock.Anything, mock.Anything).Once()

		middleware := NewMetricMiddleware(monitoring)

		handler := func(ctx context.Context, req any) (any, error) {
			return testResponse, nil
		}

		info := &grpc.UnaryServerInfo{FullMethod: "/TestService/TestMethod"}

		resp, err := middleware.Intercept(context.Background(), "request", info, handler)

		require.NoError(t, err)
		assert.Equal(t, testResponse, resp)
	})

	t.Run("increments error counter on handler error", func(t *testing.T) {
		monitoring := mocks.NewMockAggregatorMonitoring(t)
		metrics := mocks.NewMockAggregatorMetricLabeler(t)

		monitoring.EXPECT().Metrics().Return(metrics)
		metrics.EXPECT().IncrementActiveRequestsCounter(mock.Anything).Once()
		metrics.EXPECT().DecrementActiveRequestsCounter(mock.Anything).Once()
		metrics.EXPECT().RecordAPIRequestDuration(mock.Anything, mock.Anything).Once()
		metrics.EXPECT().IncrementAPIRequestErrors(mock.Anything, mock.Anything).Once()

		middleware := NewMetricMiddleware(monitoring)

		handler := func(ctx context.Context, req any) (any, error) {
			return nil, assert.AnError
		}

		info := &grpc.UnaryServerInfo{FullMethod: "/TestService/TestMethod"}

		resp, err := middleware.Intercept(context.Background(), "request", info, handler)

		require.Error(t, err)
		assert.Nil(t, resp)
	})

	t.Run("records request duration", func(t *testing.T) {
		monitoring := mocks.NewMockAggregatorMonitoring(t)
		metrics := mocks.NewMockAggregatorMetricLabeler(t)

		monitoring.EXPECT().Metrics().Return(metrics)
		metrics.EXPECT().IncrementActiveRequestsCounter(mock.Anything).Once()
		metrics.EXPECT().DecrementActiveRequestsCounter(mock.Anything).Once()
		metrics.EXPECT().RecordAPIRequestDuration(mock.Anything, mock.Anything).Once()

		middleware := NewMetricMiddleware(monitoring)

		handler := func(ctx context.Context, req any) (any, error) {
			return testResponse, nil
		}

		info := &grpc.UnaryServerInfo{FullMethod: "/TestService/TestMethod"}

		_, err := middleware.Intercept(context.Background(), "request", info, handler)

		require.NoError(t, err)
	})
}

func TestNewMetricMiddleware(t *testing.T) {
	monitoring := mocks.NewMockAggregatorMonitoring(t)
	middleware := NewMetricMiddleware(monitoring)
	assert.NotNil(t, middleware)
}
