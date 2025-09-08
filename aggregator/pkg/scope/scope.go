package scope

import (
	"context"
	"encoding/hex"

	"github.com/google/uuid"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type contextKey string

const (
	messageIDKey     contextKey = "message-id"
	addressKey       contextKey = "address"
	participantIDKey contextKey = "participant-id"
	requestIDKey     contextKey = "request-id"
)

var contextKeys = []contextKey{
	messageIDKey,
	addressKey,
	participantIDKey,
	requestIDKey,
}

func WithRequestID(ctx context.Context) context.Context {
	return context.WithValue(ctx, requestIDKey, uuid.New().String())
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

func AugmentLogger(ctx context.Context, logger logger.SugaredLogger) logger.SugaredLogger {
	for _, key := range contextKeys {
		logger = augmentLoggerIfOk(ctx, logger, key)
	}
	return logger
}

func augmentLoggerIfOk(ctx context.Context, logger logger.SugaredLogger, key contextKey) logger.SugaredLogger {
	value, ok := ctx.Value(key).(string)
	if !ok {
		return logger
	}
	return logger.With(string(key), value)
}
