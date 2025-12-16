package middlewares

import (
	"context"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/status"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/scope"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type LoggingMiddleware struct {
	l logger.SugaredLogger
}

func (m *LoggingMiddleware) Intercept(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
	startTime := time.Now()
	reqLogger := scope.AugmentLogger(ctx, m.l)

	reqLogger.Infof("Request received")
	reqLogger.Debugw("Request payload received", "payload", req)

	resp, err = handler(ctx, req)

	duration := time.Since(startTime)
	statusCode := status.Code(err)

	if err != nil {
		reqLogger.Errorw("Request failed", "duration_ms", duration.Milliseconds(), "status", statusCode.String())
	} else {
		reqLogger.Infow("Request completed", "duration_ms", duration.Milliseconds(), "status", statusCode.String())
	}
	reqLogger.Debugw("Response sent", "payload", resp)

	return resp, err
}

func NewLoggingMiddleware(
	l logger.SugaredLogger,
) *LoggingMiddleware {
	return &LoggingMiddleware{
		l: l,
	}
}
