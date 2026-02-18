package verifier

import (
	"context"
	"fmt"
	"math/big"
	"sync"

	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

const MaxFinalityBlocksStored = 1000

// FinalityViolationCheckerService validates that finalized blocks never change their hash.
// This is a synchronous, pull-based service driven by the caller
//
// Architecture:
// - Caller invokes UpdateFinalized() on each poll cycle with the new finalized block number
// - Service fetches and stores block headers from last known finalized to new finalized
// - Caller invokes IsFinalityViolated() to check if any stored block changed
// - No background goroutines - fully synchronous and driven by caller
//
// Finality Violation Detection:
// - When UpdateFinalized is called with block N, we fetch headers from lastFinalized to N
// - For any block we already have stored, we verify the hash matches
// - If hash mismatch detected -> finality violation
// - If violation detected, violationDetected flag is set and IsFinalityViolated returns true
//
// Storage:
// - Stores finalized block headers in a map keyed by block number
// - Only stores blocks that are finalized (no unfinalized blocks)
//
// Thread-safety:
// - All methods are protected by a mutex
// - Safe for concurrent calls from multiple goroutines.
type FinalityViolationCheckerService struct {
	mu sync.RWMutex

	sourceReader  chainaccess.SourceReader
	chainSelector protocol.ChainSelector
	lggr          logger.Logger
	metrics       MetricLabeler

	// Stored finalized blocks (keyed by block number)
	finalizedBlocks map[uint64]protocol.BlockHeader

	// Last finalized block we processed
	lastFinalized uint64

	// Flag indicating if violation was detected
	violationDetected bool
}

// NewFinalityViolationCheckerService creates a new finality violation checker.
func NewFinalityViolationCheckerService(
	sourceReader chainaccess.SourceReader,
	chainSelector protocol.ChainSelector,
	lggr logger.Logger,
	metrics MetricLabeler,
) (*FinalityViolationCheckerService, error) {
	if sourceReader == nil {
		return nil, fmt.Errorf("sourceReader cannot be nil")
	}
	if lggr == nil {
		return nil, fmt.Errorf("logger cannot be nil")
	}

	return &FinalityViolationCheckerService{
		sourceReader:      sourceReader,
		chainSelector:     chainSelector,
		lggr:              logger.With(lggr, "component", "FinalityViolationChecker", "chain", chainSelector),
		metrics:           metrics,
		finalizedBlocks:   make(map[uint64]protocol.BlockHeader),
		lastFinalized:     0,
		violationDetected: false,
	}, nil
}

// UpdateFinalized fetches and stores block headers from lastFinalized to finalizedBlock.
// Validates that any previously stored blocks have not changed.
// Returns error if headers cannot be fetched or if a finality violation is detected.
func (f *FinalityViolationCheckerService) UpdateFinalized(ctx context.Context, finalizedBlock uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	// If violation already detected, don't process further updates
	if f.violationDetected {
		return fmt.Errorf("finality violation already detected, service stopped")
	}

	// If this is the first call, just store the finalized block
	if f.lastFinalized == 0 {
		header, err := f.fetchSingleBlock(ctx, finalizedBlock)
		if err != nil {
			return fmt.Errorf("failed to fetch initial finalized block %d: %w", finalizedBlock, err)
		}
		f.finalizedBlocks[finalizedBlock] = *header
		f.lastFinalized = finalizedBlock
		f.lggr.Infow("Initialized finality checker",
			"finalizedBlock", finalizedBlock,
			"finalizedHash", header.Hash)
		return nil
	}

	// Determine range to verify - handles both forward progress and RPC lagging behind
	fromBlock := min(f.lastFinalized, finalizedBlock)
	toBlock := max(f.lastFinalized, finalizedBlock)

	if finalizedBlock < f.lastFinalized {
		f.lggr.Warnw("Finalized block number decreased - RPC may be lagging, verifying full range",
			"lastFinalized", f.lastFinalized,
			"newFinalized", finalizedBlock,
		)
	}

	// Fetch blocks in range [fromBlock, toBlock]
	// Note: When finalizedBlock == lastFinalized, this still fetches and verifies the hash
	headers, err := f.fetchBlockRange(ctx, fromBlock, toBlock)
	if err != nil {
		return fmt.Errorf("failed to fetch block range [%d, %d]: %w", fromBlock, toBlock, err)
	}

	// Validate and store headers
	for blockNum := fromBlock; blockNum <= toBlock; blockNum++ {
		newHeader, exists := headers[blockNum]
		if !exists {
			return fmt.Errorf("missing header for block %d in fetched range", blockNum)
		}

		if err := f.validateAndStore(ctx, blockNum, newHeader); err != nil {
			return err
		}
	}

	// Only advance lastFinalized when moving forward
	if finalizedBlock > f.lastFinalized {
		f.lastFinalized = finalizedBlock
	}
	f.lggr.Debugw("Updated finalized blocks",
		"lastFinalized", f.lastFinalized,
		"storedBlocksCount", len(f.finalizedBlocks))

	f.trimStoredBlocks()
	return nil
}

func (f *FinalityViolationCheckerService) trimStoredBlocks() {
	if len(f.finalizedBlocks) > MaxFinalityBlocksStored {
		// remove oldest entries to prevent unbounded growth
		var toDelete []uint64
		for blockNum := range f.finalizedBlocks {
			if blockNum < f.lastFinalized-MaxFinalityBlocksStored {
				toDelete = append(toDelete, blockNum)
			}
		}
		for _, blockNum := range toDelete {
			delete(f.finalizedBlocks, blockNum)
		}
	}
}

// validateAndStore checks block hash consistency and parent hash continuity.
// Returns error and sets violationDetected if a finality violation is found.
func (f *FinalityViolationCheckerService) validateAndStore(ctx context.Context, blockNum uint64, newHeader protocol.BlockHeader) error {
	// Check if we already have this block stored
	if storedHeader, ok := f.finalizedBlocks[blockNum]; ok {
		if storedHeader.Hash != newHeader.Hash {
			f.violationDetected = true
			f.lggr.Errorw("FINALITY VIOLATION DETECTED - block hash changed",
				"blockNumber", blockNum,
				"storedHash", storedHeader.Hash,
				"newHash", newHeader.Hash,
			)
			f.metrics.SetVerifierFinalityViolated(ctx, true, f.chainSelector)
			return fmt.Errorf("finality violation: block %d hash changed from %s to %s",
				blockNum, storedHeader.Hash, newHeader.Hash)
		}
		return nil
	}

	// New block: verify parent hash matches the previous stored block
	if blockNum > 0 {
		if prevHeader, hasPrev := f.finalizedBlocks[blockNum-1]; hasPrev {
			if newHeader.ParentHash != prevHeader.Hash {
				f.lggr.Errorw("FINALITY VIOLATION DETECTED - parent hash mismatch",
					"blockNumber", blockNum,
					"expectedParent", prevHeader.Hash,
					"actualParent", newHeader.ParentHash,
				)
				f.violationDetected = true
				f.metrics.SetVerifierFinalityViolated(ctx, true, f.chainSelector)
				return fmt.Errorf("finality violation: block %d parent hash %s doesn't match block %d hash %s",
					blockNum, newHeader.ParentHash, blockNum-1, prevHeader.Hash)
			}
		}
	}

	f.finalizedBlocks[blockNum] = newHeader
	return nil
}

// IsFinalityViolated returns true if a finality violation has been detected.
// This is a lightweight check that doesn't make any RPC calls.
func (f *FinalityViolationCheckerService) IsFinalityViolated() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.violationDetected
}

// reset clears all stored state. Used for testing.
func (f *FinalityViolationCheckerService) reset() {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.finalizedBlocks = make(map[uint64]protocol.BlockHeader)
	f.lastFinalized = 0
	f.violationDetected = false
	f.metrics.SetVerifierFinalityViolated(context.Background(), false, f.chainSelector)

	f.lggr.Infow("Finality checker state reset",
		"chainSelector", f.chainSelector)
}

// fetchSingleBlock fetches a single block header by number.
func (f *FinalityViolationCheckerService) fetchSingleBlock(ctx context.Context, blockNum uint64) (*protocol.BlockHeader, error) {
	blockNumbers := []*big.Int{new(big.Int).SetUint64(blockNum)}
	headers, err := f.sourceReader.GetBlocksHeaders(ctx, blockNumbers)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch block header: %w", err)
	}
	if headers == nil {
		return nil, fmt.Errorf("received nil headers map")
	}

	header, exists := headers[blockNumbers[0]]
	if !exists {
		return nil, fmt.Errorf("block header not found in response")
	}

	return &header, nil
}

// fetchBlockRange fetches block headers for range [start, end] inclusive.
func (f *FinalityViolationCheckerService) fetchBlockRange(ctx context.Context, startBlock, endBlock uint64) (map[uint64]protocol.BlockHeader, error) {
	if startBlock > endBlock {
		return nil, fmt.Errorf("invalid range: startBlock %d > endBlock %d", startBlock, endBlock)
	}

	// Build block numbers array
	var blockNumbers []*big.Int
	for i := startBlock; i <= endBlock; i++ {
		blockNumbers = append(blockNumbers, new(big.Int).SetUint64(i))
	}

	// Fetch headers
	headers, err := f.sourceReader.GetBlocksHeaders(ctx, blockNumbers)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch block headers for range [%d, %d]: %w", startBlock, endBlock, err)
	}
	if headers == nil {
		return nil, fmt.Errorf("received nil headers map")
	}

	// Build map keyed by block number
	blockMap := make(map[uint64]protocol.BlockHeader)
	for _, blockNum := range blockNumbers {
		header, exists := headers[blockNum]
		if !exists {
			return nil, fmt.Errorf("missing block header for block %s", blockNum.String())
		}
		blockMap[header.Number] = header
	}

	return blockMap, nil
}

// NoOpFinalityViolationChecker is a dummy implementation that does nothing.
type NoOpFinalityViolationChecker struct{}

// UpdateFinalized implements protocol.FinalityViolationChecker.
func (n *NoOpFinalityViolationChecker) UpdateFinalized(ctx context.Context, finalizedBlock uint64) error {
	return nil
}

// IsFinalityViolated implements protocol.FinalityViolationChecker.
func (n *NoOpFinalityViolationChecker) IsFinalityViolated() bool {
	return false
}
