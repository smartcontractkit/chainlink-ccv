package middlewares

import (
	"context"

	"google.golang.org/grpc"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type LoggingMiddleware struct {
	l logger.SugaredLogger
}

func (m *LoggingMiddleware) Intercept(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
	m.l.Debugf("Received request: %+v", req)
	resp, err = handler(ctx, req)
	if err != nil {
		m.l.Errorf("Error processing request: %v", err)
	} else {
		m.l.Debugf("Successfully processed request")
	}
	return resp, err
}

func NewLoggingMiddleware(
	l logger.SugaredLogger,
) *LoggingMiddleware {
	return &LoggingMiddleware{
		l: l,
	}
}
