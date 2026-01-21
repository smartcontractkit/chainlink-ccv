package handlers

import (
	"context"
	"fmt"
	"math"
	"slices"
	"sort"
	"strconv"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/auth"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/heartbeat"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/scope"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	heartbeatpb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/heartbeat/v1"
)

type HeartbeatHandler struct {
	storage      heartbeat.Storage
	aggregatorID string
	committee    *model.Committee
	l            logger.SugaredLogger
	m            common.AggregatorMonitoring
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

	// get Allowed chains from committee config
	allowedChains := make([]uint64, 0, len(h.committee.QuorumConfigs))

	for chainSelector := range h.committee.QuorumConfigs {
		chainSelectorUint, err := strconv.ParseUint(chainSelector, 10, 64)
		if err != nil {
			h.logger(ctx).Warnf("Error parsing chain selector '%s': %v", chainSelector, err)
			continue
		}
		allowedChains = append(allowedChains, chainSelectorUint)
	}

	// filter for allowed chains only
	chainDetails := filterHeartbeatChainDetails(req.ChainDetails, allowedChains)
	if chainDetails == nil || len(chainDetails.BlockHeightsByChain) == 0 {
		h.logger(ctx).Info("No valid chain details provided in heartbeat request")
		return &heartbeatpb.HeartbeatResponse{
			AggregatorId:    h.aggregatorID,
			Timestamp:       req.SendTimestamp,
			ChainBenchmarks: make(map[uint64]*heartbeatpb.ChainBenchmark),
		}, nil
	}

	// Store the block heights from the incoming request
	for chainSelector, blockHeight := range chainDetails.BlockHeightsByChain {
		if err := h.storage.StoreBlockHeight(ctx, callerID, chainSelector, blockHeight); err != nil {
			h.logger(ctx).Warnf("Failed to store block height for chain %d: %v", chainSelector, err)
		}
	}

	// Get the list of chain selectors to query
	chainSelectors := make([]uint64, 0, len(chainDetails.BlockHeightsByChain))
	for chainSelector := range chainDetails.BlockHeightsByChain {
		chainSelectors = append(chainSelectors, chainSelector)
	}

	maxBlockHeights, err := h.storage.GetMaxBlockHeights(ctx, chainSelectors)
	h.logger(ctx).Infof("Max block heights across all callers: %+v", maxBlockHeights)
	if err != nil {
		h.logger(ctx).Errorf("Failed to get max block heights: %v", err)
		maxBlockHeights = make(map[uint64]uint64)
	}

	// Create chain benchmarks based on max block heights
	chainBenchmarks := make(map[uint64]*heartbeatpb.ChainBenchmark)

	for chainSelector, maxBlockHeight := range maxBlockHeights {
		// Collect all block heights for this chain across all callers
		headsAcrossCallers, err := h.storage.GetBlockHeights(ctx, chainSelector)
		if err != nil {
			h.logger(ctx).Warnf("Failed to get block heights for chain %d: %v", chainSelector, err)
			continue
		}

		headsFlat := make([]int64, 0, len(headsAcrossCallers))
		for _, height := range headsAcrossCallers {
			headsFlat = append(headsFlat, int64(height)) // #nosec G115 -- block heights are within int64 range
		}

		// Calculate adaptive score
		currentHeight := req.ChainDetails.BlockHeightsByChain[chainSelector]
		score := CalculateAdaptiveScore(int64(currentHeight), headsFlat) // #nosec G115 -- block heights are within int64 range
		chainBenchmarks[chainSelector] = &heartbeatpb.ChainBenchmark{
			BlockHeight: maxBlockHeight,
			Score:       float32(score),
		}
	}

	metrics := h.m.Metrics().With("caller_id", callerID)
	metrics.SetVerifierLastHeartbeatTimestamp(ctx, req.SendTimestamp)
	metrics.IncrementVerifierHeartbeatsTotal(ctx)

	// Record per-chain metrics
	for chainSelector, benchmark := range chainBenchmarks {
		chainMetrics := metrics.With("chain_selector", fmt.Sprintf("%d", chainSelector))
		chainMetrics.SetVerifierHeartbeatScore(ctx, float64(benchmark.Score))
		chainMetrics.SetVerifierHeartbeatChainHeads(ctx, benchmark.BlockHeight)
	}

	return &heartbeatpb.HeartbeatResponse{
		AggregatorId:    h.aggregatorID,
		Timestamp:       req.SendTimestamp,
		ChainBenchmarks: chainBenchmarks,
	}, nil
}

// NewHeartbeatHandler creates a new instance of HeartbeatHandler.
func NewHeartbeatHandler(storage heartbeat.Storage, aggregatorID string, committee *model.Committee, l logger.SugaredLogger, m common.AggregatorMonitoring) *HeartbeatHandler {
	return &HeartbeatHandler{
		storage:      storage,
		aggregatorID: aggregatorID,
		committee:    committee,
		l:            l,
		m:            m,
	}
}

// CalculateAdaptiveScore computes the adaptive score based on the provided block height and all block heights.
// The score reflects how far behind the provided block height is compared to others using Median Absolute Deviation (MAD).
// Using MAD is much more robust to outliers compared to standard deviation as it uses median instead of mean.
// This helps prevent a few nodes with very low block heights from skewing the score for everyone else.
// Example scores
// 1.0 -> Leading.
// 2.0 -> 1 MAD behind.
// 4.0 -> 3 MADs behind.
func CalculateAdaptiveScore(scoreBlock int64, allBlocks []int64) float64 {
	n := len(allBlocks)
	if n == 0 {
		return 1.0 // Default to baseline if no data
	}

	// 1. Find Median
	sorted := make([]int64, n)
	copy(sorted, allBlocks)
	slices.Sort(sorted)
	median := sorted[n/2]

	// 2. Find MAD (Median Absolute Deviation).
	// This calculates the median of gaps from the median.
	deviations := make([]float64, 0, n)
	for _, b := range sorted {
		dev := math.Abs(float64(b - median))
		deviations = append(deviations, dev)
	}
	sort.Float64s(deviations)
	mad := deviations[n/2]

	// Safety: Assume a minimum deviation of 1 block to avoid divide-by-zero
	if mad < 1.0 {
		mad = 1.0
	}

	// 3. Calculate Lag for the scoreBlock
	lag := float64(median - scoreBlock)
	if lag < 0 {
		lag = 0 // Being ahead is treated as leading (Score 1.0)
	}

	// 4. Calculate Divergence Index
	// Formula: 1 + (Lag / MAD)
	return 1.0 + (lag / mad)
}

func filterHeartbeatChainDetails(details *heartbeatpb.ChainHealthDetails, allowedChains []uint64) *heartbeatpb.ChainHealthDetails {
	if details == nil {
		return nil
	}

	filtered := &heartbeatpb.ChainHealthDetails{
		BlockHeightsByChain: make(map[uint64]uint64),
	}

	for chainSelector, blockHeight := range details.BlockHeightsByChain {
		if slices.Contains(allowedChains, chainSelector) {
			filtered.BlockHeightsByChain[chainSelector] = blockHeight
		}
	}

	return filtered
}
