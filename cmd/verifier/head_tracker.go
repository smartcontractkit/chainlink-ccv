package verifier

import (
	"context"
	"fmt"
	"math/big"

	"github.com/smartcontractkit/chainlink-ccv/verifier"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-evm/pkg/client"
	evmtypes "github.com/smartcontractkit/chainlink-evm/pkg/types"
)

// SimpleHeadTrackerWrapper is a simple implementation that wraps chain client calls.
// This provides a HeadTracker interface without requiring the full EVM head tracker setup.
// It calculates finalized blocks using a hardcoded confirmation depth.
type SimpleHeadTrackerWrapper struct {
	chainClient client.Client
	lggr        logger.Logger
}

// NewSimpleHeadTrackerWrapper creates a new simple head tracker that delegates to the chain client.
func NewSimpleHeadTrackerWrapper(chainClient client.Client, lggr logger.Logger) *SimpleHeadTrackerWrapper {
	return &SimpleHeadTrackerWrapper{
		chainClient: chainClient,
		lggr:        lggr,
	}
}

// LatestAndFinalizedBlock returns the latest and finalized block headers.
// Finalized is calculated as latest - verifier.ConfirmationDepth.
func (m *SimpleHeadTrackerWrapper) LatestAndFinalizedBlock(ctx context.Context) (latest, finalized *evmtypes.Head, err error) {
	// Get latest block
	latestHead, err := m.chainClient.HeadByNumber(ctx, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get latest block: %w", err)
	}

	// Calculate finalized block number based on confirmation depth
	var finalizedBlockNum int64
	if latestHead.Number >= verifier.ConfirmationDepth {
		finalizedBlockNum = latestHead.Number - verifier.ConfirmationDepth
	} else {
		finalizedBlockNum = 0
	}

	// Get finalized block header
	finalizedHead, err := m.chainClient.HeadByNumber(ctx, big.NewInt(finalizedBlockNum))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get block at number %d: %w", finalizedBlockNum, err)
	}

	return latestHead, finalizedHead, nil
}

// LatestSafeBlock returns the latest safe block header.
// Returns nil if the chain doesn't support safe blocks (optional feature).
func (m *SimpleHeadTrackerWrapper) LatestSafeBlock(ctx context.Context) (safe *evmtypes.Head, err error) {
	return nil, nil
}

// Backfill is a no-op for the mock implementation.
// In production, this would fetch historical blocks to fill gaps in the chain.
func (m *SimpleHeadTrackerWrapper) Backfill(ctx context.Context, headWithChain, prevHeadWithChain *evmtypes.Head) error {
	// Mock implementation doesn't need backfill functionality
	return nil
}

// LatestChain returns the latest head.
// This is a synchronous call that returns the most recent block.
func (m *SimpleHeadTrackerWrapper) LatestChain() *evmtypes.Head {
	return nil
}

// Start is a no-op for the mock implementation (implements services.Service).
func (m *SimpleHeadTrackerWrapper) Start(ctx context.Context) error {
	return nil
}

// Close is a no-op for the mock implementation (implements services.Service).
func (m *SimpleHeadTrackerWrapper) Close() error {
	return nil
}

// Name returns the service name (implements services.Service).
func (m *SimpleHeadTrackerWrapper) Name() string {
	return "MockHeadTracker"
}

// Ready checks if the service is ready (implements services.Service).
func (m *SimpleHeadTrackerWrapper) Ready() error {
	return nil
}

// HealthReport returns the health status (implements services.Service).
func (m *SimpleHeadTrackerWrapper) HealthReport() map[string]error {
	return map[string]error{m.Name(): nil}
}
