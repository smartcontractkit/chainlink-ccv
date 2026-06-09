package scope

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/auth"
	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
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

	value, ok := ctx.Value(messageIDKey).(protocol.ByteSlice)
	require.True(t, ok)
	assert.Equal(t, "0x01020304", value.String())
}

func TestWithAddress(t *testing.T) {
	ctx := context.Background()
	address := []byte{0xaa, 0xbb, 0xcc, 0xdd}
	ctx = WithAddress(ctx, address)

	value, ok := ctx.Value(addressKey).(protocol.ByteSlice)
	require.True(t, ok)
	assert.Equal(t, "0xaabbccdd", value.String())
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
	t.Run("adds values from context to logger", func(t *testing.T) {
		ctx := context.Background()
		ctx = WithAPIName(ctx, "/Test/Method")
		ctx = WithRequestID(ctx)
		ctx = WithMessageID(ctx, []byte{0x01, 0x02})
		ctx = WithAddress(ctx, []byte{0xaa, 0xbb})
		ctx = WithAggregationKey(ctx, "test-aggregation-key")

		requestID, ok := RequestIDFromContext(ctx)
		require.True(t, ok)

		lggr, hook := logger.TestObservedSugared(t, zapcore.InfoLevel)
		augmented := AugmentLogger(ctx, lggr)
		fields := logFields(t, hook, augmented)

		assert.Equal(t, "/Test/Method", fields["apiName"])
		assert.Equal(t, requestID, fields["requestID"])
		assert.Equal(t, "0x0102", fields["messageID"])
		assert.Equal(t, "0xaabb", fields["address"])
		assert.Equal(t, "test-aggregation-key", fields["aggregationKey"])
	})

	t.Run("adds caller identity to logger when present", func(t *testing.T) {
		ctx := context.Background()
		identity := auth.CreateCallerIdentity("test-caller", false)
		ctx = auth.ToContext(ctx, identity)

		lggr, hook := logger.TestObservedSugared(t, zapcore.InfoLevel)
		augmented := AugmentLogger(ctx, lggr)
		fields := logFields(t, hook, augmented)

		assert.Equal(t, "test-caller", fields["caller_id"])
	})

	t.Run("handles empty context gracefully", func(t *testing.T) {
		lggr, hook := logger.TestObservedSugared(t, zapcore.InfoLevel)
		augmented := AugmentLogger(context.Background(), lggr)
		fields := logFields(t, hook, augmented)

		for _, key := range loggerContextKeys {
			_, ok := fields[string(key)]
			assert.False(t, ok, "unexpected field %q", key)
		}
		_, ok := fields["caller_id"]
		assert.False(t, ok)
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
	t.Run("adds string value when present in context", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), requestIDKey, "test-id")

		lggr, hook := logger.TestObservedSugared(t, zapcore.InfoLevel)
		augmented := augmentLoggerIfOk(ctx, lggr, requestIDKey)
		fields := logFields(t, hook, augmented)

		assert.Equal(t, "test-id", fields["requestID"])
	})

	t.Run("adds messageID from ByteSlice context value", func(t *testing.T) {
		ctx := WithMessageID(context.Background(), []byte{0x01, 0x02, 0x03, 0x04})

		lggr, hook := logger.TestObservedSugared(t, zapcore.InfoLevel)
		augmented := augmentLoggerIfOk(ctx, lggr, messageIDKey)
		fields := logFields(t, hook, augmented)

		assert.Equal(t, "0x01020304", fields["messageID"])
	})

	t.Run("adds address from ByteSlice context value", func(t *testing.T) {
		ctx := WithAddress(context.Background(), []byte{0xaa, 0xbb, 0xcc, 0xdd})

		lggr, hook := logger.TestObservedSugared(t, zapcore.InfoLevel)
		augmented := augmentLoggerIfOk(ctx, lggr, addressKey)
		fields := logFields(t, hook, augmented)

		assert.Equal(t, "0xaabbccdd", fields["address"])
	})

	t.Run("returns original logger when ByteSlice value is empty", func(t *testing.T) {
		ctx := WithMessageID(context.Background(), nil)

		lggr, hook := logger.TestObservedSugared(t, zapcore.InfoLevel)
		augmented := augmentLoggerIfOk(ctx, lggr, messageIDKey)
		require.Equal(t, lggr, augmented)

		fields := logFields(t, hook, augmented)
		_, ok := fields["messageID"]
		assert.False(t, ok)
	})

	t.Run("returns original logger when value not present", func(t *testing.T) {
		lggr, hook := logger.TestObservedSugared(t, zapcore.InfoLevel)
		augmented := augmentLoggerIfOk(context.Background(), lggr, requestIDKey)
		require.Equal(t, lggr, augmented)

		fields := logFields(t, hook, augmented)
		_, ok := fields["requestID"]
		assert.False(t, ok)
	})

	t.Run("returns original logger when value is wrong type", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), requestIDKey, 123)

		lggr, hook := logger.TestObservedSugared(t, zapcore.InfoLevel)
		augmented := augmentLoggerIfOk(ctx, lggr, requestIDKey)
		require.Equal(t, lggr, augmented)

		fields := logFields(t, hook, augmented)
		_, ok := fields["requestID"]
		assert.False(t, ok)
	})
}

func logFields(t *testing.T, hook *observer.ObservedLogs, lggr logger.SugaredLogger) map[string]any {
	t.Helper()

	lggr.Infow("test")
	require.Equal(t, 1, hook.Len())

	return hook.All()[0].ContextMap()
}

func TestContextKeysExportedAsExpected(t *testing.T) {
	assert.NotEmpty(t, loggerContextKeys)
	assert.NotEmpty(t, metricsContextKeys)

	for _, key := range loggerContextKeys {
		assert.NotEmpty(t, string(key))
	}
}
