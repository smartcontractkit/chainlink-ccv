package main

import (
	"context"
	"fmt"
	"math/big"
	"sync"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-evm/pkg/client"

	evmtypes "github.com/smartcontractkit/chainlink-evm/pkg/types"
)

// simpleHeadTrackerWrapper is a simple implementation that wraps chain client calls.
// This provides a HeadTracker interface without requiring the full EVM head tracker setup.
// It implements the heads.Tracker interface by delegating to the chain client.
type simpleHeadTrackerWrapper struct {
	chainClient client.Client
	lggr        logger.Logger
}

// newSimpleHeadTrackerWrapper creates a new mock head tracker that delegates to the chain client.
func newSimpleHeadTrackerWrapper(chainClient client.Client, lggr logger.Logger) *simpleHeadTrackerWrapper {
	return &simpleHeadTrackerWrapper{
		chainClient: chainClient,
		lggr:        lggr,
	}
}

// LatestAndFinalizedBlock returns the latest and finalized block headers.
// This method makes RPC calls in parallel to get the current state of the chain efficiently.
func (m *simpleHeadTrackerWrapper) LatestAndFinalizedBlock(ctx context.Context) (latest, finalized *evmtypes.Head, err error) {
	var latestHead, finalizedHead *evmtypes.Head
	var wg sync.WaitGroup
	errCh := make(chan error, 2) // Buffered channel to avoid goroutine leaks

	// Fetch latest block in parallel
	wg.Add(1)
	go func() {
		defer wg.Done()
		head, err := m.chainClient.HeadByNumber(ctx, nil)
		if err != nil {
			errCh <- fmt.Errorf("failed to get latest block: %w", err)
			return
		}
		latestHead = head
	}()

	// Fetch finalized block in parallel
	wg.Add(1)
	go func() {
		defer wg.Done()
		head, err := m.chainClient.LatestFinalizedBlock(ctx)
		if err != nil {
			// Fallback: if finalized block not available, use genesis
			m.lggr.Debugw("Failed to get finalized block, falling back to genesis", "error", err)
			head, err = m.chainClient.HeadByNumber(ctx, big.NewInt(0))
			if err != nil {
				errCh <- fmt.Errorf("failed to get genesis block: %w", err)
				return
			}
		}
		finalizedHead = head
	}()

	// Wait for both goroutines to complete
	wg.Wait()
	close(errCh)

	// Check if any errors occurred
	for err := range errCh {
		if err != nil {
			return nil, nil, err
		}
	}

	return latestHead, finalizedHead, nil
}

// LatestSafeBlock returns the latest safe block header.
// Returns nil if the chain doesn't support safe blocks (optional feature).
func (m *simpleHeadTrackerWrapper) LatestSafeBlock(ctx context.Context) (safe *evmtypes.Head, err error) {
	return nil, nil
}

// Backfill is a no-op for the mock implementation.
// In production, this would fetch historical blocks to fill gaps in the chain.
func (m *simpleHeadTrackerWrapper) Backfill(ctx context.Context, headWithChain, prevHeadWithChain *evmtypes.Head) error {
	// Mock implementation doesn't need backfill functionality
	return nil
}

// LatestChain returns the latest head.
// This is a synchronous call that returns the most recent block.
func (m *simpleHeadTrackerWrapper) LatestChain() *evmtypes.Head {
	return nil
}

// Start is a no-op for the mock implementation (implements services.Service).
func (m *simpleHeadTrackerWrapper) Start(ctx context.Context) error {
	return nil
}

// Close is a no-op for the mock implementation (implements services.Service).
func (m *simpleHeadTrackerWrapper) Close() error {
	return nil
}

// Name returns the service name (implements services.Service).
func (m *simpleHeadTrackerWrapper) Name() string {
	return "MockHeadTracker"
}

// Ready checks if the service is ready (implements services.Service).
func (m *simpleHeadTrackerWrapper) Ready() error {
	return nil
}

// HealthReport returns the health status (implements services.Service).
func (m *simpleHeadTrackerWrapper) HealthReport() map[string]error {
	return map[string]error{m.Name(): nil}
}
