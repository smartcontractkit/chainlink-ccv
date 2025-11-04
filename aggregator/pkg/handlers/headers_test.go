package handlers

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
)

func TestLoadCommitteeIDFromContext_WithHeader_ReturnsValue(t *testing.T) {
	md := metadata.Pairs(model.CommitteeIDHeader, "committee-xyz")
	ctx := metadata.NewIncomingContext(context.Background(), md)
	require.Equal(t, "committee-xyz", LoadCommitteeIDFromContext(ctx))
}

func TestLoadCommitteeIDFromContext_NoHeader_ReturnsDefault(t *testing.T) {
	require.Equal(t, model.DefaultCommitteeID, LoadCommitteeIDFromContext(context.Background()))
}
