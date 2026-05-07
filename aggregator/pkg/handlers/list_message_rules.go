package handlers

import (
	"context"

	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/scope"
	messagerules "github.com/smartcontractkit/chainlink-ccv/common/messagerules"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	messagepb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/message-rules/v1"
)

type MessageRulesRegistry interface {
	// ActiveRulesSnapshot returns the active message rules, or false if the registry is not ready.
	ActiveRulesSnapshot() ([]messagerules.Rule, bool)
}

type ListMessageRulesHandler struct {
	registry MessageRulesRegistry
	l        logger.SugaredLogger
}

func (h *ListMessageRulesHandler) logger(ctx context.Context) logger.SugaredLogger {
	return scope.AugmentLogger(ctx, h.l)
}

func (h *ListMessageRulesHandler) Handle(ctx context.Context, _ *messagepb.ListMessageRulesRequest) (*messagepb.ListMessageRulesResponse, error) {
	rules, ok := h.registry.ActiveRulesSnapshot()
	if !ok {
		h.logger(ctx).Errorw("Message rules requested before registry completed a successful refresh")
		return nil, grpcstatus.Error(codes.Unavailable, "message rules are not available")
	}

	pbRules, err := messagerules.RulesToProto(rules)
	if err != nil {
		h.logger(ctx).Errorw("Failed to map message rules to proto", "error", err)
		return nil, grpcstatus.Error(codes.Internal, "failed to list message rules")
	}

	return &messagepb.ListMessageRulesResponse{
		Rules: pbRules,
	}, nil
}

func NewListMessageRulesHandler(registry MessageRulesRegistry, l logger.SugaredLogger) *ListMessageRulesHandler {
	return &ListMessageRulesHandler{
		registry: registry,
		l:        l,
	}
}
