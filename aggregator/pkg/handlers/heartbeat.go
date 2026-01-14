package handlers

import (
	"context"
	"fmt"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/auth"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/heartbeat"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/scope"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	heartbeatpb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/heartbeat/v1"
)

type HeartbeatHandler struct {
	storage heartbeat.Storage
	l       logger.SugaredLogger
	m       common.AggregatorMonitoring
}

func (h *HeartbeatHandler) logger(ctx context.Context) logger.SugaredLogger {
	return scope.AugmentLogger(ctx, h.l)
}

// Handle processes the POST request with heartbeat data and returns current benchmark score per chain.
func (h *HeartbeatHandler) Handle(ctx context.Context, req *heartbeatpb.HeartbeatRequest) (*heartbeatpb.HeartbeatResponse, error) {
	identity, ok := auth.IdentityFromContext(ctx)
	if !ok {
		return nil, fmt.Errorf("no caller identity in context")
	}

	callerID := identity.CallerID
	h.logger(ctx).Infof("Received HeartbeatRequest from caller: %s", callerID)

	// Store the block heights from the incoming request
	if req.ChainDetails != nil {
		for chainSelector, blockHeight := range req.ChainDetails.BlockHeightsByChain {
			if err := h.storage.StoreBlockHeight(ctx, callerID, chainSelector, blockHeight); err != nil {
				h.logger(ctx).Warnf("Failed to store block height for chain %d: %v", chainSelector, err)
			}
		}
	}

	// TODO: get the SoT list of blockchains to report on. For now, just report on those sent in the request.
	// Get the list of chain selectors to query
	chainSelectors := make([]uint64, 0, len(req.ChainDetails.BlockHeightsByChain))
	for chainSelector := range req.ChainDetails.BlockHeightsByChain {
		chainSelectors = append(chainSelectors, chainSelector)
	}

	// Retrieve max block heights across all callers
	maxBlockHeights, err := h.storage.GetMaxBlockHeights(ctx, chainSelectors)
	h.logger(ctx).Infof("Max block heights across all callers: %+v", maxBlockHeights)
	if err != nil {
		h.logger(ctx).Errorf("Failed to get max block heights: %v", err)
		// Return empty benchmarks on error
		maxBlockHeights = make(map[uint64]uint64)
	}

	// Create chain benchmarks based on max block heights
	chainBenchmarks := make(map[uint64]*heartbeatpb.ChainBenchmark)
	for chainSelector, maxBlockHeight := range maxBlockHeights {
		chainBenchmarks[chainSelector] = &heartbeatpb.ChainBenchmark{
			BlockHeight: maxBlockHeight,
			Score:       95.5, // TODO: Calculate actual score based on performance metrics
		}
	}

	return &heartbeatpb.HeartbeatResponse{
		AggregatorId:    "mock-aggregator-001",
		Timestamp:       req.SendTimestamp,
		ChainBenchmarks: chainBenchmarks,
	}, nil
}

// NewHeartbeatHandler creates a new instance of HeartbeatHandler.
func NewHeartbeatHandler(storage heartbeat.Storage, l logger.SugaredLogger, m common.AggregatorMonitoring) *HeartbeatHandler {
	return &HeartbeatHandler{
		storage: storage,
		l:       l,
		m:       m,
	}
}
