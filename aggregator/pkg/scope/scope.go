package scope

import (
	"context"
	"encoding/hex"

	"github.com/google/uuid"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/auth"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type contextKey string

const (
	messageIDKey     contextKey = "message-id"
	addressKey       contextKey = "address"
	participantIDKey contextKey = "participant-id"
	requestIDKey     contextKey = "request-id"
	committeeIDKey   contextKey = "committee-id"
	apiName          contextKey = "api-name"
)

var loggerContextKeys = []contextKey{
	messageIDKey,
	addressKey,
	participantIDKey,
	requestIDKey,
	committeeIDKey,
	apiName,
}

var metricsContextKeys = []contextKey{
	committeeIDKey,
	apiName,
}

func WithAPIName(ctx context.Context, name string) context.Context {
	return context.WithValue(ctx, apiName, name)
}

func WithRequestID(ctx context.Context) context.Context {
	return context.WithValue(ctx, requestIDKey, uuid.NewString())
}

func WithMessageID(ctx context.Context, id []byte) context.Context {
	return context.WithValue(ctx, messageIDKey, hex.EncodeToString(id))
}

func WithAddress(ctx context.Context, address []byte) context.Context {
	return context.WithValue(ctx, addressKey, hex.EncodeToString(address))
}

func WithParticipantID(ctx context.Context, participantID string) context.Context {
	return context.WithValue(ctx, participantIDKey, participantID)
}

func WithCommitteeID(ctx context.Context, committeeID string) context.Context {
	return context.WithValue(ctx, committeeIDKey, committeeID)
}

func AugmentLogger(ctx context.Context, logger logger.SugaredLogger) logger.SugaredLogger {
	for _, key := range loggerContextKeys {
		logger = augmentLoggerIfOk(ctx, logger, key)
	}

	identity, ok := auth.IdentityFromContext(ctx)
	if ok {
		logger = logger.With("caller_id", identity.CallerID)
	}

	return logger
}

func AugmentMetrics(ctx context.Context, metrics common.AggregatorMetricLabeler) common.AggregatorMetricLabeler {
	for _, key := range metricsContextKeys {
		if value, ok := ctx.Value(key).(string); ok {
			metrics = metrics.With(string(key), value)
		}
	}
	return metrics
}

func augmentLoggerIfOk(ctx context.Context, logger logger.SugaredLogger, key contextKey) logger.SugaredLogger {
	value, ok := ctx.Value(key).(string)
	if !ok {
		return logger
	}
	return logger.With(string(key), value)
}
