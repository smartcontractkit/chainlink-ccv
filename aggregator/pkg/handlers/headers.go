package handlers

import (
	"context"

	"google.golang.org/grpc/metadata"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
)

func LoadCommitteeIDFromContext(ctx context.Context) model.CommitteeID {
	md, _ := metadata.FromIncomingContext(ctx)
	committeeID := model.DefaultCommitteeID
	if vals, ok := md[model.CommitteeIDHeader]; ok && len(vals) > 0 {
		committeeID = vals[0]
	}
	return committeeID
}
