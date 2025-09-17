package handlers

import (
	"context"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/scope"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type Handler[Req, Resp any] interface {
	// Handle processes a request and returns a response or error.
	Handle(ctx context.Context, req Req) (Resp, error)
}

type LoggingMiddleware[Req, Resp any] struct {
	next Handler[Req, Resp]
	l    logger.SugaredLogger
}

func (m *LoggingMiddleware[Req, Resp]) Handle(ctx context.Context, req Req) (Resp, error) {
	ctx = scope.WithRequestID(ctx)
	resp, err := m.next.Handle(ctx, req)
	if err != nil {
		m.l.Errorf("Error processing request: %v", err)
	}
	return resp, err
}

func NewLoggingMiddleware[Req, Resp any](
	next Handler[Req, Resp],
	l logger.SugaredLogger,
) *LoggingMiddleware[Req, Resp] {
	return &LoggingMiddleware[Req, Resp]{
		next: next,
		l:    l,
	}
}
