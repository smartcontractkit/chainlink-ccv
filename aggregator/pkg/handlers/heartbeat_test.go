package handlers

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/auth"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/heartbeat"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	heartbeatpb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/heartbeat/v1"
)

func createTestCommittee(chainSelectors ...uint64) *model.Committee {
	quorumConfigs := make(map[string]*model.QuorumConfig)
	for _, chainSelector := range chainSelectors {
		quorumConfigs[fmt.Sprintf("%d", chainSelector)] = &model.QuorumConfig{
			Threshold: 1,
			Signers:   []model.Signer{},
		}
	}
	return &model.Committee{
		QuorumConfigs: quorumConfigs,
	}
}

func TestHeartbeatHandler_Handle_NoIdentityInContext(t *testing.T) {
	t.Parallel()

	storage := heartbeat.NewInMemoryStorage()
	lggr := logger.TestSugared(t)
	monitoring := &monitoring.NoopAggregatorMonitoring{}
	committee := createTestCommittee(1)
	handler := NewHeartbeatHandler(storage, "mock-aggregator-001", committee, lggr, monitoring)

	req := &heartbeatpb.HeartbeatRequest{
		SendTimestamp: 1768392197,
		ChainDetails: &heartbeatpb.ChainHealthDetails{
			BlockHeightsByChain: map[uint64]uint64{
				1: 1000000,
			},
		},
	}

	resp, err := handler.Handle(context.Background(), req)

	require.Error(t, err)
	require.Nil(t, resp)
	assert.Contains(t, err.Error(), "no caller identity in context")
}

func TestHeartbeatHandler_Handle_SingleCaller(t *testing.T) {
	t.Parallel()

	storage := heartbeat.NewInMemoryStorage()
	lggr := logger.TestSugared(t)
	monitoring := &monitoring.NoopAggregatorMonitoring{}
	committee := createTestCommittee(1, 137)
	handler := NewHeartbeatHandler(storage, "mock-aggregator-001", committee, lggr, monitoring)

	identity := auth.CreateCallerIdentity("caller-1", false)
	ctx := auth.ToContext(context.Background(), identity)

	req := &heartbeatpb.HeartbeatRequest{
		SendTimestamp: 1768392197,
		ChainDetails: &heartbeatpb.ChainHealthDetails{
			BlockHeightsByChain: map[uint64]uint64{
				1:   1000000,
				137: 2000000,
			},
		},
	}

	resp, err := handler.Handle(ctx, req)

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "mock-aggregator-001", resp.AggregatorId)
	assert.Equal(t, int64(1768392197), resp.Timestamp)
	assert.Len(t, resp.ChainBenchmarks, 2)

	// Caller is at max, so score should be 1.0
	assert.Equal(t, uint64(1000000), resp.ChainBenchmarks[1].BlockHeight)
	assert.Equal(t, float32(1.0), resp.ChainBenchmarks[1].Score)

	assert.Equal(t, uint64(2000000), resp.ChainBenchmarks[137].BlockHeight)
	assert.Equal(t, float32(1.0), resp.ChainBenchmarks[137].Score)
}

func TestHeartbeatHandler_Handle_MultipleCallers_ReturnsMaxBlockHeights(t *testing.T) {
	t.Parallel()

	storage := heartbeat.NewInMemoryStorage()
	lggr := logger.TestSugared(t)
	monitoring := &monitoring.NoopAggregatorMonitoring{}
	committee := createTestCommittee(1, 137)
	handler := NewHeartbeatHandler(storage, "mock-aggregator-001", committee, lggr, monitoring)

	// First caller with higher block heights
	caller1Identity := auth.CreateCallerIdentity("caller-1", false)
	ctx1 := auth.ToContext(context.Background(), caller1Identity)

	req1 := &heartbeatpb.HeartbeatRequest{
		SendTimestamp: 1768392197,
		ChainDetails: &heartbeatpb.ChainHealthDetails{
			BlockHeightsByChain: map[uint64]uint64{
				1:   1000000,
				137: 2000000,
			},
		},
	}

	resp1, err := handler.Handle(ctx1, req1)
	require.NoError(t, err)
	require.NotNil(t, resp1)

	// Second caller with mixed block heights (higher on chain 1, lower on chain 137)
	caller2Identity := auth.CreateCallerIdentity("caller-2", false)
	ctx2 := auth.ToContext(context.Background(), caller2Identity)

	req2 := &heartbeatpb.HeartbeatRequest{
		SendTimestamp: 1768392198,
		ChainDetails: &heartbeatpb.ChainHealthDetails{
			BlockHeightsByChain: map[uint64]uint64{
				1:   1000100, // Higher than caller-1
				137: 1999950, // Lower than caller-1
			},
		},
	}

	resp2, err := handler.Handle(ctx2, req2)
	require.NoError(t, err)
	require.NotNil(t, resp2)

	// Verify that max block heights are returned
	assert.Equal(t, uint64(1000100), resp2.ChainBenchmarks[1].BlockHeight)   // caller-2's height
	assert.Equal(t, uint64(2000000), resp2.ChainBenchmarks[137].BlockHeight) // caller-1's height

	assert.Equal(t, float32(1.0), resp2.ChainBenchmarks[1].Score) // At max

	assert.Equal(t, float32(2), resp2.ChainBenchmarks[137].Score)
}

func TestHeartbeatHandler_Handle_NilChainDetails(t *testing.T) {
	t.Parallel()

	storage := heartbeat.NewInMemoryStorage()
	lggr := logger.TestSugared(t)
	monitoring := &monitoring.NoopAggregatorMonitoring{}
	committee := createTestCommittee(1)
	handler := NewHeartbeatHandler(storage, "mock-aggregator-001", committee, lggr, monitoring)

	identity := auth.CreateCallerIdentity("caller-1", false)
	ctx := auth.ToContext(context.Background(), identity)

	req := &heartbeatpb.HeartbeatRequest{
		SendTimestamp: 1768392197,
		ChainDetails:  nil,
	}

	resp, err := handler.Handle(ctx, req)

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "mock-aggregator-001", resp.AggregatorId)
	assert.Len(t, resp.ChainBenchmarks, 0)
}

func TestHeartbeatHandler_Handle_EmptyChainDetails(t *testing.T) {
	t.Parallel()

	storage := heartbeat.NewInMemoryStorage()
	lggr := logger.TestSugared(t)
	monitoring := &monitoring.NoopAggregatorMonitoring{}
	committee := createTestCommittee(1)
	handler := NewHeartbeatHandler(storage, "mock-aggregator-001", committee, lggr, monitoring)

	identity := auth.CreateCallerIdentity("caller-1", false)
	ctx := auth.ToContext(context.Background(), identity)

	req := &heartbeatpb.HeartbeatRequest{
		SendTimestamp: 1768392197,
		ChainDetails: &heartbeatpb.ChainHealthDetails{
			BlockHeightsByChain: map[uint64]uint64{},
		},
	}

	resp, err := handler.Handle(ctx, req)

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Len(t, resp.ChainBenchmarks, 0)
}

func TestHeartbeatHandler_Handle_StorageFailureDoesNotFailRequest(t *testing.T) {
	t.Parallel()

	// Using NoopStorage which returns empty results
	storage := heartbeat.NewNoopStorage()
	lggr := logger.TestSugared(t)
	monitoring := &monitoring.NoopAggregatorMonitoring{}
	committee := createTestCommittee(1)
	handler := NewHeartbeatHandler(storage, "mock-aggregator-001", committee, lggr, monitoring)

	identity := auth.CreateCallerIdentity("caller-1", false)
	ctx := auth.ToContext(context.Background(), identity)

	req := &heartbeatpb.HeartbeatRequest{
		SendTimestamp: 1768392197,
		ChainDetails: &heartbeatpb.ChainHealthDetails{
			BlockHeightsByChain: map[uint64]uint64{
				1: 1000000,
			},
		},
	}

	resp, err := handler.Handle(ctx, req)

	// Should not fail even with noop storage
	require.NoError(t, err)
	require.NotNil(t, resp)
}

func TestCalculateAdaptiveScore(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		scoreBlock int64
		allBlocks  []int64
		expected   float64
	}{
		{
			name:       "no blocks returns baseline",
			scoreBlock: 100,
			allBlocks:  []int64{},
			expected:   1.0,
		},
		{
			name:       "at median gets score of 1.0",
			scoreBlock: 100,
			allBlocks:  []int64{90, 95, 100, 105, 110},
			expected:   1.0,
		},
		{
			name:       "ahead of median gets score of 1.0",
			scoreBlock: 110,
			allBlocks:  []int64{90, 95, 100, 105, 110},
			expected:   1.0,
		},
		{
			name:       "one MAD behind gets score of 2.0",
			scoreBlock: 95,
			allBlocks:  []int64{90, 95, 100, 105, 110},
			expected:   2.0, // median=100, MAD=5, lag=5, score=1+(5/5)=2.0
		},
		{
			name:       "two MADs behind gets score of 3.0",
			scoreBlock: 90,
			allBlocks:  []int64{90, 95, 100, 105, 110},
			expected:   3.0, // median=100, MAD=5, lag=10, score=1+(10/5)=3.0
		},
		{
			name:       "uniform blocks with small MAD",
			scoreBlock: 100,
			allBlocks:  []int64{100, 100, 100, 100, 100},
			expected:   1.0, // All same, at median
		},
		{
			name:       "behind with uniform blocks uses minimum MAD",
			scoreBlock: 90,
			allBlocks:  []int64{100, 100, 100, 100, 100},
			expected:   11.0, // median=100, MAD=1 (min), lag=10, score=1+(10/1)=11.0
		},
		{
			name:       "half similar half lagging - average best node",
			scoreBlock: 1010,
			allBlocks:  []int64{900, 910, 920, 930, 940, 1000, 1005, 1010, 1015, 1020},
			expected:   1.0, // At the median of the similar group, should score well
		},
		{
			name:       "half similar half lagging - lagging node",
			scoreBlock: 920,
			allBlocks:  []int64{900, 910, 920, 930, 940, 1000, 1005, 1010, 1015, 1020},
			expected:   2.25, // median=970 (avg of 940 and 1000), MAD≈40, lag=50, score≈1+(50/40)=2.25
		},
		{
			name:       "half similar half lagging - worst lagging node",
			scoreBlock: 900,
			allBlocks:  []int64{900, 910, 920, 930, 940, 1000, 1005, 1010, 1015, 1020},
			expected:   2.75, // median=970, MAD≈40, lag=70, score≈1+(70/40)=2.75
		},
		{
			name:       "half similar half lagging - best node from leading group",
			scoreBlock: 1020,
			allBlocks:  []int64{900, 910, 920, 930, 940, 1000, 1005, 1010, 1015, 1020},
			expected:   1.0, // Ahead of median, gets baseline score
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			score := CalculateAdaptiveScore(tt.scoreBlock, tt.allBlocks)
			assert.InDelta(t, tt.expected, score, 0.1, "score mismatch for scoreBlock=%d, allBlocks=%v", tt.scoreBlock, tt.allBlocks)
		})
	}
}

func TestHeartbeatHandler_Handle_FiltersByAllowedChains(t *testing.T) {
	t.Parallel()

	storage := heartbeat.NewInMemoryStorage()
	lggr := logger.TestSugared(t)
	monitoring := &monitoring.NoopAggregatorMonitoring{}
	// Only allow chains 1 and 137
	committee := createTestCommittee(1, 137)
	handler := NewHeartbeatHandler(storage, "mock-aggregator-001", committee, lggr, monitoring)

	identity := auth.CreateCallerIdentity("caller-1", false)
	ctx := auth.ToContext(context.Background(), identity)

	req := &heartbeatpb.HeartbeatRequest{
		SendTimestamp: 1768392197,
		ChainDetails: &heartbeatpb.ChainHealthDetails{
			BlockHeightsByChain: map[uint64]uint64{
				1:     1000000, // Allowed
				137:   2000000, // Allowed
				42161: 3000000, // Not allowed (Arbitrum)
				10:    4000000, // Not allowed (Optimism)
			},
		},
	}

	resp, err := handler.Handle(ctx, req)

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "mock-aggregator-001", resp.AggregatorId)
	// Should only return benchmarks for allowed chains (1 and 137)
	assert.Len(t, resp.ChainBenchmarks, 2)
	assert.Contains(t, resp.ChainBenchmarks, uint64(1))
	assert.Contains(t, resp.ChainBenchmarks, uint64(137))
	assert.NotContains(t, resp.ChainBenchmarks, uint64(42161))
	assert.NotContains(t, resp.ChainBenchmarks, uint64(10))
}

func TestHeartbeatHandler_Handle_AllChainsDisallowed(t *testing.T) {
	t.Parallel()

	storage := heartbeat.NewInMemoryStorage()
	lggr := logger.TestSugared(t)
	monitoring := &monitoring.NoopAggregatorMonitoring{}
	// Only allow chain 1
	committee := createTestCommittee(1)
	handler := NewHeartbeatHandler(storage, "mock-aggregator-001", committee, lggr, monitoring)

	identity := auth.CreateCallerIdentity("caller-1", false)
	ctx := auth.ToContext(context.Background(), identity)

	req := &heartbeatpb.HeartbeatRequest{
		SendTimestamp: 1768392197,
		ChainDetails: &heartbeatpb.ChainHealthDetails{
			BlockHeightsByChain: map[uint64]uint64{
				42161: 3000000, // Not allowed (Arbitrum)
				10:    4000000, // Not allowed (Optimism)
			},
		},
	}

	resp, err := handler.Handle(ctx, req)

	require.NoError(t, err)
	require.NotNil(t, resp)
	// No valid chain details after filtering, should return empty benchmarks
	assert.Len(t, resp.ChainBenchmarks, 0)
}

func TestHeartbeatHandler_Handle_NoCommitteeChains(t *testing.T) {
	t.Parallel()

	storage := heartbeat.NewInMemoryStorage()
	lggr := logger.TestSugared(t)
	monitoring := &monitoring.NoopAggregatorMonitoring{}
	// Empty committee with no chains
	committee := createTestCommittee()
	handler := NewHeartbeatHandler(storage, "mock-aggregator-001", committee, lggr, monitoring)

	identity := auth.CreateCallerIdentity("caller-1", false)
	ctx := auth.ToContext(context.Background(), identity)

	req := &heartbeatpb.HeartbeatRequest{
		SendTimestamp: 1768392197,
		ChainDetails: &heartbeatpb.ChainHealthDetails{
			BlockHeightsByChain: map[uint64]uint64{
				1:   1000000,
				137: 2000000,
			},
		},
	}

	resp, err := handler.Handle(ctx, req)

	require.NoError(t, err)
	require.NotNil(t, resp)
	// No allowed chains, should return empty benchmarks
	assert.Len(t, resp.ChainBenchmarks, 0)
}

func TestHeartbeatHandler_Handle_SingleChainAllowed(t *testing.T) {
	t.Parallel()

	storage := heartbeat.NewInMemoryStorage()
	lggr := logger.TestSugared(t)
	monitoring := &monitoring.NoopAggregatorMonitoring{}
	// Only allow chain 137
	committee := createTestCommittee(137)
	handler := NewHeartbeatHandler(storage, "mock-aggregator-001", committee, lggr, monitoring)

	identity := auth.CreateCallerIdentity("caller-1", false)
	ctx := auth.ToContext(context.Background(), identity)

	req := &heartbeatpb.HeartbeatRequest{
		SendTimestamp: 1768392197,
		ChainDetails: &heartbeatpb.ChainHealthDetails{
			BlockHeightsByChain: map[uint64]uint64{
				1:   1000000, // Not allowed
				137: 2000000, // Allowed
			},
		},
	}

	resp, err := handler.Handle(ctx, req)

	require.NoError(t, err)
	require.NotNil(t, resp)
	// Should only return benchmarks for chain 137
	assert.Len(t, resp.ChainBenchmarks, 1)
	assert.Contains(t, resp.ChainBenchmarks, uint64(137))
	assert.NotContains(t, resp.ChainBenchmarks, uint64(1))
	assert.Equal(t, uint64(2000000), resp.ChainBenchmarks[137].BlockHeight)
}

func TestHeartbeatHandler_Handle_ManyChains(t *testing.T) {
	t.Parallel()

	storage := heartbeat.NewInMemoryStorage()
	lggr := logger.TestSugared(t)
	monitoring := &monitoring.NoopAggregatorMonitoring{}
	// Allow multiple chains
	committee := createTestCommittee(1, 137, 42161, 10, 43114, 8453)
	handler := NewHeartbeatHandler(storage, "mock-aggregator-001", committee, lggr, monitoring)

	identity := auth.CreateCallerIdentity("caller-1", false)
	ctx := auth.ToContext(context.Background(), identity)

	req := &heartbeatpb.HeartbeatRequest{
		SendTimestamp: 1768392197,
		ChainDetails: &heartbeatpb.ChainHealthDetails{
			BlockHeightsByChain: map[uint64]uint64{
				1:     1000000, // Ethereum
				137:   2000000, // Polygon
				42161: 3000000, // Arbitrum
				10:    4000000, // Optimism
				43114: 5000000, // Avalanche
				8453:  6000000, // Base
				999:   7000000, // Not allowed
			},
		},
	}

	resp, err := handler.Handle(ctx, req)

	require.NoError(t, err)
	require.NotNil(t, resp)
	// Should return benchmarks for all allowed chains (6 out of 7)
	assert.Len(t, resp.ChainBenchmarks, 6)
	assert.Contains(t, resp.ChainBenchmarks, uint64(1))
	assert.Contains(t, resp.ChainBenchmarks, uint64(137))
	assert.Contains(t, resp.ChainBenchmarks, uint64(42161))
	assert.Contains(t, resp.ChainBenchmarks, uint64(10))
	assert.Contains(t, resp.ChainBenchmarks, uint64(43114))
	assert.Contains(t, resp.ChainBenchmarks, uint64(8453))
	assert.NotContains(t, resp.ChainBenchmarks, uint64(999))
}
