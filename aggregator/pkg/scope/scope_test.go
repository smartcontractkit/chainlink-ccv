package scope

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/auth"
	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func TestWithAPIName(t *testing.T) {
	ctx := context.Background()
	ctx = WithAPIName(ctx, "/TestService/TestMethod")

	value, ok := ctx.Value(apiName).(string)
	require.True(t, ok)
	assert.Equal(t, "/TestService/TestMethod", value)
}

func TestWithRequestID(t *testing.T) {
	ctx := context.Background()
	ctx = WithRequestID(ctx)

	value, ok := ctx.Value(requestIDKey).(string)
	require.True(t, ok)
	assert.NotEmpty(t, value)
	assert.Len(t, value, 36) // UUID format
}

func TestWithRequestID_GeneratesUniqueIDs(t *testing.T) {
	ctx1 := WithRequestID(context.Background())
	ctx2 := WithRequestID(context.Background())

	id1 := ctx1.Value(requestIDKey).(string)
	id2 := ctx2.Value(requestIDKey).(string)

	assert.NotEqual(t, id1, id2)
}

func TestWithMessageID(t *testing.T) {
	ctx := context.Background()
	messageID := []byte{0x01, 0x02, 0x03, 0x04}
	ctx = WithMessageID(ctx, messageID)

	value, ok := ctx.Value(messageIDKey).(string)
	require.True(t, ok)
	assert.Equal(t, "0x01020304", value)
}

func TestWithAddress(t *testing.T) {
	ctx := context.Background()
	address := []byte{0xaa, 0xbb, 0xcc, 0xdd}
	ctx = WithAddress(ctx, address)

	value, ok := ctx.Value(addressKey).(string)
	require.True(t, ok)
	assert.Equal(t, "aabbccdd", value)
}

func TestWithAggregationKey(t *testing.T) {
	ctx := context.Background()
	ctx = WithAggregationKey(ctx, "test-aggregation-key")

	value, ok := ctx.Value(aggregationKey).(string)
	require.True(t, ok)
	assert.Equal(t, "test-aggregation-key", value)
}

func TestRequestIDFromContext(t *testing.T) {
	t.Run("returns value when present", func(t *testing.T) {
		ctx := WithRequestID(context.Background())

		value, ok := RequestIDFromContext(ctx)
		assert.True(t, ok)
		assert.NotEmpty(t, value)
	})

	t.Run("returns false when not present", func(t *testing.T) {
		value, ok := RequestIDFromContext(context.Background())
		assert.False(t, ok)
		assert.Empty(t, value)
	})
}

func TestAPINameFromContext(t *testing.T) {
	t.Run("returns value when present", func(t *testing.T) {
		ctx := WithAPIName(context.Background(), "/Test/Method")

		value, ok := APINameFromContext(ctx)
		assert.True(t, ok)
		assert.Equal(t, "/Test/Method", value)
	})

	t.Run("returns false when not present", func(t *testing.T) {
		value, ok := APINameFromContext(context.Background())
		assert.False(t, ok)
		assert.Empty(t, value)
	})
}

func TestAugmentLogger(t *testing.T) {
	lggr := logger.Sugared(logger.Test(t))

	t.Run("adds values from context to logger", func(t *testing.T) {
		ctx := context.Background()
		ctx = WithAPIName(ctx, "/Test/Method")
		ctx = WithRequestID(ctx)

		augmented := AugmentLogger(ctx, lggr)
		assert.NotNil(t, augmented)
	})

	t.Run("adds caller identity to logger when present", func(t *testing.T) {
		ctx := context.Background()
		identity := auth.CreateCallerIdentity("test-caller", false)
		ctx = auth.ToContext(ctx, identity)

		augmented := AugmentLogger(ctx, lggr)
		assert.NotNil(t, augmented)
	})

	t.Run("handles empty context gracefully", func(t *testing.T) {
		augmented := AugmentLogger(context.Background(), lggr)
		assert.NotNil(t, augmented)
	})
}

func TestAugmentMetrics(t *testing.T) {
	t.Run("adds API name to metrics when present in context", func(t *testing.T) {
		metrics := mocks.NewMockAggregatorMetricLabeler(t)
		metrics.EXPECT().With("apiName", "/Test/Method").Return(metrics).Once()

		ctx := WithAPIName(context.Background(), "/Test/Method")

		result := AugmentMetrics(ctx, metrics)
		assert.NotNil(t, result)
	})

	t.Run("skips when no values in context", func(t *testing.T) {
		metrics := mocks.NewMockAggregatorMetricLabeler(t)

		result := AugmentMetrics(context.Background(), metrics)
		assert.NotNil(t, result)
	})

	t.Run("returns same metrics when context values not string", func(t *testing.T) {
		metrics := mocks.NewMockAggregatorMetricLabeler(t)

		ctx := context.WithValue(context.Background(), apiName, 123) // Wrong type

		result := AugmentMetrics(ctx, metrics)
		assert.Equal(t, metrics, result)
	})
}

func TestAugmentLoggerIfOk(t *testing.T) {
	lggr := logger.Sugared(logger.Test(t))

	t.Run("adds value when present in context", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), requestIDKey, "test-id")

		result := augmentLoggerIfOk(ctx, lggr, requestIDKey)
		assert.NotNil(t, result)
	})

	t.Run("returns original logger when value not present", func(t *testing.T) {
		result := augmentLoggerIfOk(context.Background(), lggr, requestIDKey)
		assert.Equal(t, lggr, result)
	})

	t.Run("returns original logger when value is wrong type", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), requestIDKey, 123)

		result := augmentLoggerIfOk(ctx, lggr, requestIDKey)
		assert.Equal(t, lggr, result)
	})
}

func TestContextKeysExportedAsExpected(t *testing.T) {
	assert.NotEmpty(t, loggerContextKeys)
	assert.NotEmpty(t, metricsContextKeys)

	for _, key := range loggerContextKeys {
		assert.NotEmpty(t, string(key))
	}
}
