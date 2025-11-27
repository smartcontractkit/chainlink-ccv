package services

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/services"
)

const (
	// MinGapBlocks is the minimum gap size before triggering tail rebuild
	MinGapBlocks = 15
	// GapBlocksPercentage defines the dynamic gap threshold as percentage of tail size
	GapBlocksPercentage = 0.30 // 30% of tail size
	// DefaultPollInterval is the default interval for polling new blocks
	DefaultPollInterval = 1000 * time.Millisecond
)

// ReorgDetectorConfig contains configuration for the reorg detector service.
type ReorgDetectorConfig struct {
	// ChainSelector identifies the chain being monitored
	ChainSelector protocol.ChainSelector

	// PollInterval is how often to poll for new blocks
	PollInterval time.Duration
}

// ReorgDetectorService detects blockchain reorganizations by polling block headers.
// It wraps a SourceReader to provide a unified, chain-agnostic reorg detection mechanism.
//
// Architecture:
// - Polls for new blocks at regular intervals using HeadTracker
// - Maintains a map of recent blocks (from finalized to latest) for reorg detection
// - Detects reorgs by comparing parent hashes of consecutive blocks
// - Sends notifications via channel only when reorgs or finality violations are detected
//
// Tail Management:
// - Stored as map[blockNumber]BlockHeader for O(1) lookup
// - Tracks min/max block numbers for range management
// - HeadTracker determines finalized block (by depth or finality tag depending on chain)
// - Automatically backfills gaps when pollInterval > blockTime (normal operation)
// - Rebuilds entire tail if gap exceeds 100 blocks (restart/downtime recovery)
//
// Reorg Detection:
// - On each poll, checks if newBlock.ParentHash == previousBlock.Hash
// - If mismatch: walks back parent chain via RPC to find LCA
// - Compares RPC blocks with stored blocks by number to find reconnection point
//
// Lifecycle:
// - Start() builds initial tail and launches polling goroutine (blocks until ready)
// - Returns a channel that receives ChainStatus updates (only on reorgs/violations)
// - Close() stops polling and closes the status channel
//
// Integration:
// - Created per source chain in Coordinator.Start()
// - Runs alongside SourceReaderService for each chain
// - Uses same SourceReader instance to share RPC connections.
type ReorgDetectorService struct {
	sync   services.StateMachine
	cancel context.CancelFunc
	wg     sync.WaitGroup

	sourceReader chainaccess.SourceReader
	config       ReorgDetectorConfig
	lggr         logger.Logger
	statusCh     chan protocol.ChainStatus

	// In-memory block tracking (keyed by block number for O(1) lookup)
	// Single-writer: only accessed by pollAndCheckForReorgs goroutine
	tailBlocks           map[uint64]protocol.BlockHeader
	latestFinalizedBlock uint64
	latestBlock          uint64

	// Polling configuration
	pollInterval time.Duration
}

// NewReorgDetectorService creates a new reorg detector service.
//
// Parameters:
// - sourceReader: Used to fetch block headers by hash during reorg detection
// - headTracker: Used to get latest/finalized block state (handles depth vs finality tag per chain)
// - config: Configuration including chain selector and poll interval
// - lggr: Logger for operational visibility
//
// Returns:
// - *ReorgDetectorService ready to be started
// - error if configuration is invalid.
func NewReorgDetectorService(
	sourceReader chainaccess.SourceReader,
	config ReorgDetectorConfig,
	lggr logger.Logger,
) (*ReorgDetectorService, error) {
	// Validate configuration
	if sourceReader == nil {
		return nil, fmt.Errorf("source reader is required")
	}
	if config.ChainSelector == 0 {
		return nil, fmt.Errorf("chain selector is required")
	}
	if lggr == nil {
		return nil, fmt.Errorf("logger is required")
	}

	pollInterval := config.PollInterval
	// Default 2 seconds
	if pollInterval == 0 {
		pollInterval = DefaultPollInterval
	}

	return &ReorgDetectorService{
		sourceReader: sourceReader,
		config:       config,
		lggr:         lggr,
		statusCh:     make(chan protocol.ChainStatus, 1),
		tailBlocks:   make(map[uint64]protocol.BlockHeader),
		pollInterval: pollInterval,
	}, nil
}

// Start initializes the reorg detector and begins monitoring.
//
// Behavior:
// 1. Fetches the latest finalized block from the source chain
// 2. Builds initial chain tail (blocks back from finalized)
// 3. Spawns background polling goroutine
// 4. Returns immediately once initial tail is built
//
// The status channel will receive:
// - ChainStatusReorg: When a reorg is detected (includes reorg depth and common ancestor)
// - ChainStatusFinalityViolated: When a finalized block is reorged
//
// Returns:
// - <-chan protocol.ChainStatus: Receive-only channel for status updates
// - error: If initial tail cannot be fetched or context is canceled
//
// Thread-safety:
// - Safe to call once per instance
// - Subsequent calls will return an error.
func (r *ReorgDetectorService) Start(ctx context.Context) (<-chan protocol.ChainStatus, error) {
	var resultCh <-chan protocol.ChainStatus
	err := r.sync.StartOnce("ReorgDetectorService", func() error {
		r.lggr.Infow("Starting reorg detector service",
			"chainSelector", r.config.ChainSelector,
			"pollInterval", r.pollInterval)

		err := r.buildEntireTail(ctx)
		if err != nil {
			return fmt.Errorf("failed to build initial tail: %w", err)
		}

		ctx1, cancel := context.WithCancel(context.Background())
		r.cancel = cancel

		// Start polling goroutine
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			r.pollAndCheckForReorgs(ctx1)
		}()

		r.lggr.Infow("Reorg detector service started successfully",
			"chainSelector", r.config.ChainSelector,
			"latestFinalizedBlock", r.latestFinalizedBlock,
			"latestBlock", r.latestBlock)

		resultCh = r.statusCh
		return nil
	})
	return resultCh, err
}

// pollAndCheckForReorgs is the main polling loop that periodically checks for new blocks
// and detects reorgs.
func (r *ReorgDetectorService) pollAndCheckForReorgs(ctx context.Context) {
	ticker := time.NewTicker(r.pollInterval)
	defer ticker.Stop()

	r.lggr.Infow("Starting reorg detection polling loop",
		"chainSelector", r.config.ChainSelector,
		"pollInterval", r.pollInterval)

	for {
		select {
		case <-ctx.Done():
			r.lggr.Infow("Polling loop stopped due to context cancellation",
				"chainSelector", r.config.ChainSelector)
			return
		case <-ticker.C:
			r.checkBlockMaybeHandleReorg(ctx)
		}
	}
}

// checkBlockMaybeHandleReorg checks the latest block and handles reorgs if detected.
// Based on logpoller's getCurrentBlockMaybeHandleReorg pattern.
func (r *ReorgDetectorService) checkBlockMaybeHandleReorg(ctx context.Context) {
	// Get current chain state in a single RPC call
	latest, finalized, err := r.sourceReader.LatestAndFinalizedBlock(ctx)
	if err != nil {
		r.lggr.Debugw("Failed to fetch latest blocks",
			"chainSelector", r.config.ChainSelector,
			"error", err)
		return
	}
	if latest == nil || finalized == nil {
		r.lggr.Warnw("Received nil block headers",
			"chainSelector", r.config.ChainSelector,
			"latest", latest,
			"finalized", finalized)
		return
	}

	r.lggr.Infow("Checking for reorg",
		"chainSelector", r.config.ChainSelector,
		"latestBlock", latest.Number,
		"latestHash", latest.Hash,
		"finalizedBlock", finalized.Number,
		"finalizedHash", finalized.Hash,
		"ourLatestBlock", r.latestBlock,
		"ourLatestFinalized", r.latestFinalizedBlock,
		"tailSize", len(r.tailBlocks))

	if latest.Number < finalized.Number {
		r.lggr.Warnw("Latest block number is less than finalized block number")
		r.sendFinalityViolation(*latest, finalized.Number)
		return
	}

	// CRITICAL: Check for finality violation FIRST
	// 1. Check if finalized went BACKWARDS (most severe violation)
	if finalized.Number < r.latestFinalizedBlock {
		r.lggr.Errorw("FINALITY VIOLATION: finalized block went backwards",
			"chainSelector", r.config.ChainSelector,
			"ourFinalizedBlock", r.latestFinalizedBlock,
			"newFinalizedBlock", finalized.Number,
			"blocksReorged", r.latestFinalizedBlock-finalized.Number)

		// Use a block from our tail for the violation notification
		violatedBlock := protocol.BlockHeader{Number: r.latestFinalizedBlock}
		if stored, exists := r.tailBlocks[r.latestFinalizedBlock]; exists {
			violatedBlock = stored
		}
		r.sendFinalityViolation(violatedBlock, r.latestFinalizedBlock)
		return
	}

	// 2. Check if finalized advanced - verify hash matches
	if finalized.Number > r.latestFinalizedBlock {
		// Check if we have a stored block at the new finalized height
		storedAtFinalized, exists := r.tailBlocks[finalized.Number]
		if exists {
			// Verify that our stored block hash matches the new finalized block hash
			if storedAtFinalized.Hash != finalized.Hash {
				r.lggr.Errorw("FINALITY VIOLATION: stored block hash != new finalized hash",
					"chainSelector", r.config.ChainSelector,
					"blockNumber", finalized.Number,
					"storedHash", storedAtFinalized.Hash,
					"finalizedHash", finalized.Hash)
				r.sendFinalityViolation(storedAtFinalized, finalized.Number)
				return
			}
		}
	}

	// Handle case where chain went backwards (reorg to earlier block)
	if latest.Number < r.latestBlock {
		r.lggr.Infow("Chain went backwards - reorg detected",
			"chainSelector", r.config.ChainSelector,
			"previousLatest", r.latestBlock,
			"newLatest", latest.Number,
			"blocksReorged", r.latestBlock-latest.Number)

		if err := r.handleReorg(ctx, *latest, finalized.Number); err != nil {
			r.lggr.Errorw("Failed to handle backwards reorg",
				"chainSelector", r.config.ChainSelector,
				"error", err)
			return
		}
		return
	}

	// Check if we should process this block
	if latest.Number == r.latestBlock {
		// Same block number - check if it's actually the same block or a competing fork
		storedBlock, exists := r.tailBlocks[latest.Number]

		if !exists {
			// First time seeing this block number - add it and we're done
			r.addBlockToTail(*latest, finalized.Number)
			return
		}

		if storedBlock.Hash == latest.Hash {
			// Same block we already have - no new blocks
			r.lggr.Debugw("No new blocks",
				"chainSelector", r.config.ChainSelector,
				"latestBlock", latest.Number)
			return
		}

		// Different hash at same height - this is a reorg, fall through to parent hash check
	}

	// At this point: latest.Number >= r.latestBlock and we need to verify chain consistency
	// For same height: we'll check against the stored block (which will show hash mismatch)
	// For new height: we'll check parent hash matches expected parent
	expectedParent, hasParent := r.tailBlocks[latest.Number-1]

	// If we don't have the parent block, backfill the gap
	// Ideally this should not happen unless pollInterval is misconfigured to be more than block time
	if !hasParent {
		tailMaxBeforeBackfill := r.latestBlock
		var ok bool
		expectedParent, ok = r.handleGapBackfill(ctx, r.latestBlock, latest.Number, finalized.Number)
		if !ok {
			return
		}

		// CRITICAL: After backfill, check if backfilled blocks connect to existing tail
		// Without this, we could have mixed blocks from different forks
		firstBackfilledBlock, exists := r.tailBlocks[tailMaxBeforeBackfill+1]
		oldTailTop, tailTopExists := r.tailBlocks[tailMaxBeforeBackfill]

		r.lggr.Infow("Checking backfill connection to tail",
			"chainSelector", r.config.ChainSelector,
			"tailMaxBeforeBackfill", tailMaxBeforeBackfill,
			"firstBackfilledBlockNum", tailMaxBeforeBackfill+1,
			"firstBackfilledExists", exists,
			"oldTailTopExists", tailTopExists,
			"firstBackfilledParentHash", func() string {
				if exists {
					return firstBackfilledBlock.ParentHash.String()
				}
				return "N/A"
			}(),
			"oldTailTopHash", func() string {
				if tailTopExists {
					return oldTailTop.Hash.String()
				}
				return "N/A"
			}())

		if exists && tailTopExists {
			if firstBackfilledBlock.ParentHash != oldTailTop.Hash {
				r.lggr.Infow("Reorg detected - backfilled blocks don't connect to existing tail",
					"chainSelector", r.config.ChainSelector,
					"tailMax", tailMaxBeforeBackfill,
					"firstBackfilledBlock", tailMaxBeforeBackfill+1,
					"expectedParentHash", oldTailTop.Hash,
					"actualParentHash", firstBackfilledBlock.ParentHash)

				// Backfilled blocks are from a different fork - handle reorg
				if err := r.handleReorg(ctx, *latest, finalized.Number); err != nil {
					r.lggr.Errorw("Failed to handle reorg after backfill",
						"chainSelector", r.config.ChainSelector,
						"error", err)
					return
				}
				return
			}
			r.lggr.Infow("Backfilled blocks connect correctly to existing tail",
				"chainSelector", r.config.ChainSelector,
				"tailMax", tailMaxBeforeBackfill)
		}
	}

	// Check for reorg: does parent hash match?
	if latest.ParentHash != expectedParent.Hash {
		r.lggr.Infow("Reorg detected - parent hash mismatch",
			"chainSelector", r.config.ChainSelector,
			"block", latest.Number,
			"expectedParentHash", expectedParent.Hash,
			"actualParentHash", latest.ParentHash)

		// Find LCA and handle reorg
		if err := r.handleReorg(ctx, *latest, finalized.Number); err != nil {
			r.lggr.Errorw("Failed to handle reorg",
				"chainSelector", r.config.ChainSelector,
				"error", err)
			return
		}
	} else {
		// No reorg, add block to tail and trim old blocks
		r.addBlockToTail(*latest, finalized.Number)
	}
}

// backfillBlocks fetches and adds missing blocks to the tail.
// This is normal when pollInterval spans multiple block times.
// Includes validation to detect mid-fetch reorgs. If validation fails, the next poll will retry.
func (r *ReorgDetectorService) backfillBlocks(ctx context.Context, startBlock, endBlock, finalizedBlockNum uint64) error {
	if startBlock > endBlock {
		return fmt.Errorf("invalid range: startBlock %d > endBlock %d", startBlock, endBlock)
	}

	r.lggr.Debugw("Backfilling missing blocks",
		"chainSelector", r.config.ChainSelector,
		"startBlock", startBlock,
		"endBlock", endBlock,
		"count", endBlock-startBlock+1)

	// Fetch block headers in range
	blockMap, err := r.fetchBlockRange(ctx, startBlock, endBlock)
	if err != nil {
		return err
	}

	// Note: We don't validate chain continuity or connection to existing tail.
	// If blocks are inconsistent (mid-fetch reorg) or don't connect to existing tail,
	// the normal parent hash check in checkBlockMaybeHandleReorg will detect and handle it.

	// Add blocks to tail
	for _, header := range blockMap {
		r.tailBlocks[header.Number] = header

		// Update latestBlock as we go
		if header.Number > r.latestBlock {
			r.latestBlock = header.Number
		}
	}

	// Trim blocks older than finalized
	r.trimOlderBlocks(finalizedBlockNum)

	r.lggr.Infow("Backfill completed",
		"chainSelector", r.config.ChainSelector,
		"latestFinalizedBlock", r.latestFinalizedBlock,
		"latestBlock", r.latestBlock,
		"tailSize", len(r.tailBlocks))

	return nil
}

// buildEntireTail rebuilds the entire tail from finalized to latest.
// Used when gap is too large or tail state is inconsistent.
// Stores whatever blocks are returned; normal parent hash check will handle any inconsistencies.
func (r *ReorgDetectorService) buildEntireTail(ctx context.Context) error {
	r.lggr.Infow("Rebuilding entire tail",
		"chainSelector", r.config.ChainSelector)

	// 1. Get current chain state from HeadTracker
	latest, finalized, err := r.sourceReader.LatestAndFinalizedBlock(ctx)
	if err != nil {
		return fmt.Errorf("failed to get latest and finalized blocks: %w", err)
	}
	if latest == nil || finalized == nil {
		return fmt.Errorf("received nil block headers")
	}

	finalizedBlockNum := finalized.Number
	latestBlockNum := latest.Number

	// 2. Fetch block headers in range
	blockMap, err := r.fetchBlockRange(ctx, finalizedBlockNum, latestBlockNum)
	if err != nil {
		return err
	}

	// 3. Replace tail completely
	// Note: If blocks are inconsistent (mid-fetch reorg, out-of-sync RPC, etc.),
	// the normal parent hash check in checkBlockMaybeHandleReorg will detect and handle it
	r.tailBlocks = blockMap
	r.latestFinalizedBlock = finalizedBlockNum
	r.latestBlock = latestBlockNum

	// Log detailed tail state for debugging
	tailBlockNums := make([]uint64, 0, len(r.tailBlocks))
	for blockNum := range r.tailBlocks {
		tailBlockNums = append(tailBlockNums, blockNum)
	}

	r.lggr.Infow("Tail rebuilt successfully in buildEntireTail",
		"chainSelector", r.config.ChainSelector,
		"minBlock", r.latestFinalizedBlock,
		"maxBlock", r.latestBlock,
		"tailSize", len(r.tailBlocks),
		"tailBlocks", tailBlockNums)

	return nil
}

// trimOlderBlocks removes blocks older than the finalized block from the tail.
// Keeps the tail from finalized to latest. Finality violations are detected by:
// 1. checkBlockMaybeHandleReorg verifying stored finalized hash matches new finalized hash
// 2. findBlockAfterLCA not finding an LCA when walking back to finalized
// Called only by the polling goroutine (single-writer).
func (r *ReorgDetectorService) trimOlderBlocks(finalizedBlockNum uint64) {
	// Trim everything before finalized (keep finalized onwards)
	if r.latestFinalizedBlock < finalizedBlockNum {
		for blockNum := r.latestFinalizedBlock; blockNum < finalizedBlockNum; blockNum++ {
			delete(r.tailBlocks, blockNum)
		}
		r.latestFinalizedBlock = finalizedBlockNum
	}
}

// fetchBlockRange fetches block headers for a range [start, end] and returns them as a map.
// This is a utility to avoid duplicating the blockNumbers array creation and map building logic.
func (r *ReorgDetectorService) fetchBlockRange(ctx context.Context, startBlock, endBlock uint64) (map[uint64]protocol.BlockHeader, error) {
	// Build block numbers array
	var blockNumbers []*big.Int
	for i := startBlock; i <= endBlock; i++ {
		blockNumbers = append(blockNumbers, new(big.Int).SetUint64(i))
	}

	// Fetch headers
	headers, err := r.sourceReader.GetBlocksHeaders(ctx, blockNumbers)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch block headers for range [%d, %d]: %w", startBlock, endBlock, err)
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

// addBlockToTail adds a new block to the tail and trims old blocks older than finalized.
// The finalized block is determined by HeadTracker (by depth or finality tag per chain).
func (r *ReorgDetectorService) addBlockToTail(block protocol.BlockHeader, finalizedBlockNum uint64) {
	r.tailBlocks[block.Number] = block
	r.latestBlock = block.Number

	// Trim blocks older than finalized
	r.trimOlderBlocks(finalizedBlockNum)

	r.lggr.Debugw("Added block to tail",
		"chainSelector", r.config.ChainSelector,
		"block", block.Number,
		"hash", block.Hash,
		"finalizedBlock", finalizedBlockNum,
		"tailSize", len(r.tailBlocks))
}

// handleGapBackfill handles backfilling when there's a gap in the tail.
// Returns the expected parent block and a boolean indicating success.
func (r *ReorgDetectorService) handleGapBackfill(ctx context.Context, tailMax, latestBlockNum, finalizedBlockNum uint64) (protocol.BlockHeader, bool) {
	gapStart := tailMax + 1
	gapEnd := latestBlockNum - 1
	gapSize := gapEnd - gapStart + 1

	r.lggr.Infow("Gap detected in tail, backfilling",
		"chainSelector", r.config.ChainSelector,
		"gapStart", gapStart,
		"gapEnd", gapEnd,
		"gapSize", gapSize,
		"latestBlock", latestBlockNum,
		"tailMax", tailMax)

	// Sanity check: gap should be reasonable
	// Use dynamic threshold based on tail size to handle chains with large tails (e.g., Arbitrum)
	maxGap := r.maxGapBlocks()
	if gapSize > maxGap {
		r.lggr.Errorw("Unexpectedly large gap detected, rebuilding entire tail",
			"chainSelector", r.config.ChainSelector,
			"gapSize", gapSize,
			"maxGapBlocks", maxGap,
			"tailMax", tailMax,
			"latestBlock", latestBlockNum)
		if err := r.buildEntireTail(ctx); err != nil {
			r.lggr.Errorw("Failed to rebuild tail after large gap",
				"chainSelector", r.config.ChainSelector,
				"error", err)
		}
		return protocol.BlockHeader{}, false
	}

	// Backfill missing blocks
	if err := r.backfillBlocks(ctx, gapStart, gapEnd, finalizedBlockNum); err != nil {
		r.lggr.Errorw("Failed to backfill blocks",
			"chainSelector", r.config.ChainSelector,
			"gapStart", gapStart,
			"gapEnd", gapEnd,
			"error", err)
		return protocol.BlockHeader{}, false
	}

	// Re-fetch parent after backfill
	expectedParent, hasParent := r.tailBlocks[latestBlockNum-1]

	if !hasParent {
		r.lggr.Errorw("Parent block still missing after backfill",
			"chainSelector", r.config.ChainSelector,
			"parentBlock", latestBlockNum-1)
		return protocol.BlockHeader{}, false
	}

	r.lggr.Infow("Successfully backfilled gap",
		"chainSelector", r.config.ChainSelector,
		"gapSize", gapSize)

	return expectedParent, true
}

// handleReorg handles a detected reorg by finding the LCA and sending appropriate notifications.
func (r *ReorgDetectorService) handleReorg(ctx context.Context, newBlock protocol.BlockHeader, finalizedBlockNum uint64) error {
	r.lggr.Infow("Handling reorg",
		"chainSelector", r.config.ChainSelector,
		"newBlock", newBlock.Number,
		"newBlockHash", newBlock.Hash,
		"newBlockParentHash", newBlock.ParentHash,
		"latestFinalizedBlock", finalizedBlockNum,
		"ourLatestBlock", r.latestBlock,
		"ourLatestFinalized", r.latestFinalizedBlock,
		"tailSize", len(r.tailBlocks))

	// Find block after LCA by walking back the new chain
	// Use our stored finalized block, not the new finalized, because LCA could be below new finalized
	blockAfterLCA, err := r.findBlockAfterLCA(ctx, newBlock, r.latestFinalizedBlock)
	if err != nil {
		// Check if it's a finality violation
		var finalityViolationError *finalityViolationError
		if errors.As(err, &finalityViolationError) {
			r.lggr.Errorw("FINALITY VIOLATION DETECTED",
				"chainSelector", r.config.ChainSelector,
				"error", err)

			// Send finality violation notification
			r.sendFinalityViolation(blockAfterLCA, finalizedBlockNum)
			return nil
		}
		return fmt.Errorf("failed to find LCA: %w", err)
	}

	// LCA is the parent of blockAfterLCA
	lcaBlockNumber := blockAfterLCA.Number - 1

	r.lggr.Infow("Found LCA - preparing to rebuild tail",
		"chainSelector", r.config.ChainSelector,
		"lcaBlock", lcaBlockNumber,
		"blockAfterLCA", blockAfterLCA.Number,
		"blockAfterLCAHash", blockAfterLCA.Hash,
		"blockAfterLCAParentHash", blockAfterLCA.ParentHash)

	// Rebuild tail from blockAfterLCA
	if err := r.rebuildTailFromBlock(ctx, blockAfterLCA); err != nil {
		return fmt.Errorf("failed to rebuild tail: %w", err)
	}

	// Send reorg notification
	r.lggr.Infow("Sending reorg notification",
		"chainSelector", r.config.ChainSelector,
		"lcaBlock", lcaBlockNumber,
		"resetToBlock", lcaBlockNumber)
	r.sendReorgNotification(lcaBlockNumber)

	return nil
}

// findBlockAfterLCA finds the block after the Last Common Ancestor by fetching
// a range of blocks from the new chain and comparing with our stored blocks.
// This approach avoids the race condition of walking by hash across multiple RPC calls
// which could hit different nodes with inconsistent chain views.
// Uses our stored finalized block as the start to ensure we can find LCA even if it's below new finalized.
func (r *ReorgDetectorService) findBlockAfterLCA(ctx context.Context, currentBlock protocol.BlockHeader, ourFinalizedBlock uint64) (protocol.BlockHeader, error) {
	r.lggr.Infow("Finding block after LCA",
		"chainSelector", r.config.ChainSelector,
		"currentBlock", currentBlock.Number,
		"ourFinalizedBlock", ourFinalizedBlock)

	// 1. Determine range to fetch: [our finalized, currentBlock]
	// Use OUR finalized block, not new chain's finalized, because LCA could be below new finalized
	startBlock := ourFinalizedBlock
	endBlock := currentBlock.Number

	// 2. Fetch ALL blocks in range by number (single batch for consistency)
	newChainBlocks, err := r.fetchBlockRange(ctx, startBlock, endBlock)
	if err != nil {
		return protocol.BlockHeader{}, err
	}

	// 3. Walk back from current block comparing with stored tail to find LCA
	// Note: If fetched blocks are inconsistent, we'll still find LCA or finality violation correctly
	// Start from currentBlock and walk back until we find a match
	r.lggr.Infow("Walking back to find LCA",
		"chainSelector", r.config.ChainSelector,
		"walkingFrom", currentBlock.Number,
		"walkingTo", ourFinalizedBlock,
		"tailSize", len(r.tailBlocks))

	for blockNum := currentBlock.Number; blockNum >= ourFinalizedBlock; blockNum-- {
		newChainBlock := newChainBlocks[blockNum]
		ourBlock, exists := r.tailBlocks[blockNum]

		r.lggr.Infow("Comparing block",
			"chainSelector", r.config.ChainSelector,
			"blockNum", blockNum,
			"existsInTail", exists,
			"newChainHash", newChainBlock.Hash,
			"ourHash", func() string {
				if exists {
					return ourBlock.Hash.String()
				}
				return "N/A"
			}())

		if exists && ourBlock.Hash == newChainBlock.Hash {
			// Found LCA! The block after LCA is blockNum + 1
			if blockNum < currentBlock.Number {
				result := newChainBlocks[blockNum+1]
				r.lggr.Infow("Found LCA",
					"chainSelector", r.config.ChainSelector,
					"lcaBlock", blockNum,
					"lcaHash", ourBlock.Hash,
					"blockAfterLCA", result.Number)
				return result, nil
			}
			// If LCA is currentBlock itself, this is not actually a reorg
			// This shouldn't happen in normal flow, but handle it gracefully
			r.lggr.Warnw("LCA is current block, no reorg needed",
				"chainSelector", r.config.ChainSelector,
				"block", blockNum)
			return currentBlock, nil
		}
	}

	// 5. If we reach here, we didn't find any matching block down to our finalized
	// This means our finalized block was reorged (finality violation)
	r.lggr.Errorw("No LCA found - finality violation detected",
		"chainSelector", r.config.ChainSelector,
		"ourFinalizedBlock", ourFinalizedBlock,
		"currentBlock", currentBlock.Number,
		"tailSize", len(r.tailBlocks))

	ourStoredFinalizedBlock, exists := r.tailBlocks[ourFinalizedBlock]
	newChainFinalizedBlock := newChainBlocks[ourFinalizedBlock]

	r.lggr.Errorw("Finality violation details",
		"chainSelector", r.config.ChainSelector,
		"ourFinalizedBlockExists", exists,
		"ourFinalizedHash", func() string {
			if exists {
				return ourStoredFinalizedBlock.Hash.String()
			}
			return "N/A"
		}(),
		"newChainFinalizedHash", newChainFinalizedBlock.Hash)

	// For finality violations, we still need to return a block
	// Return the block right after our finalized as the "blockAfterLCA"
	var result protocol.BlockHeader
	if ourFinalizedBlock+1 <= currentBlock.Number {
		result = newChainBlocks[ourFinalizedBlock+1]
	} else {
		result = currentBlock
	}

	return result, &finalityViolationError{
		violatedBlock:              ourStoredFinalizedBlock,
		newChainBlock:              newChainFinalizedBlock,
		finalizedNum:               ourFinalizedBlock,
		latestFinalizedBlockExists: exists,
	}
}

// rebuildTailFromBlock rebuilds the tail starting from the given block (block after LCA)
// up to the current latest block. Stores whatever blocks are returned; normal parent hash check will handle any inconsistencies.
func (r *ReorgDetectorService) rebuildTailFromBlock(ctx context.Context, startBlock protocol.BlockHeader) error {
	r.lggr.Infow("Rebuilding tail from block",
		"chainSelector", r.config.ChainSelector,
		"startBlock", startBlock.Number)

	// 1. Get current latest block from HeadTracker to know how far to fetch
	latest, _, err := r.sourceReader.LatestAndFinalizedBlock(ctx)
	if err != nil {
		return fmt.Errorf("failed to get latest block: %w", err)
	}
	if latest == nil {
		return fmt.Errorf("latest block is nil")
	}

	// 2. Fetch block headers by number in batch
	var blockNumbers []*big.Int
	for i := startBlock.Number; i <= latest.Number; i++ {
		blockNumbers = append(blockNumbers, new(big.Int).SetUint64(i))
	}

	headers, err := r.sourceReader.GetBlocksHeaders(ctx, blockNumbers)
	if err != nil {
		return fmt.Errorf("failed to fetch block headers: %w", err)
	}

	// Build map
	blockMap := make(map[uint64]protocol.BlockHeader)
	for _, blockNum := range blockNumbers {
		header, exists := headers[blockNum]
		if !exists {
			// Block might not exist yet if we're at chain tip
			// In this case, just stop here - not an error
			break
		}
		blockMap[header.Number] = header
	}

	if len(blockMap) == 0 {
		return fmt.Errorf("no blocks fetched in range [%d, %d]", startBlock.Number, latest.Number)
	}

	// 3. Clear old tail and rebuild
	// Note: If blocks are inconsistent, normal parent hash check will detect and handle it
	maxBlock := startBlock.Number + uint64(len(blockMap)) - 1
	r.tailBlocks = blockMap
	r.latestFinalizedBlock = startBlock.Number
	r.latestBlock = maxBlock

	// Log detailed tail state for debugging
	tailBlockNums := make([]uint64, 0, len(r.tailBlocks))
	for blockNum := range r.tailBlocks {
		tailBlockNums = append(tailBlockNums, blockNum)
	}

	r.lggr.Infow("Tail rebuilt successfully",
		"chainSelector", r.config.ChainSelector,
		"startBlock", startBlock.Number,
		"minBlock", r.latestFinalizedBlock,
		"maxBlock", r.latestBlock,
		"tailSize", len(r.tailBlocks),
		"tailBlocks", tailBlockNums)

	return nil
}

// sendReorgNotification sends a reorg notification with the common ancestor block.
func (r *ReorgDetectorService) sendReorgNotification(lcaBlockNumber uint64) {
	status := protocol.ChainStatus{
		Type:         protocol.ReorgTypeNormal,
		ResetToBlock: lcaBlockNumber,
	}

	select {
	case r.statusCh <- status:
		r.lggr.Infow("Sent reorg notification",
			"chainSelector", r.config.ChainSelector,
			"type", status.Type.String(),
			"resetToBlock", lcaBlockNumber)
	default:
		r.lggr.Warnw("Status channel full, dropping reorg notification",
			"chainSelector", r.config.ChainSelector)
	}
}

// sendFinalityViolation sends a finality violation notification.
// No reset block is provided - finality violations require immediate stop and manual intervention.
func (r *ReorgDetectorService) sendFinalityViolation(violatedBlock protocol.BlockHeader, finalizedBlockNum uint64) {
	r.lggr.Errorw("FINALITY VIOLATION - sending notification",
		"chainSelector", r.config.ChainSelector,
		"violatedBlock", violatedBlock.Number,
		"violatedHash", violatedBlock.Hash,
		"finalizedBlock", finalizedBlockNum)

	status := protocol.ChainStatus{
		Type:         protocol.ReorgTypeFinalityViolation,
		ResetToBlock: 0, // No safe reset point exists
	}

	select {
	case r.statusCh <- status:
		r.lggr.Errorw("Sent finality violation notification - chain reader will stop",
			"chainSelector", r.config.ChainSelector,
			"type", status.Type.String())
	default:
		r.lggr.Warnw("Status channel full, dropping finality violation notification",
			"chainSelector", r.config.ChainSelector)
	}

	// Stop the reorg detector service after finality violation
	// The chain is compromised and no longer trustworthy - stop polling
	// Signal the polling loop to stop immediately before Close() completes
	if r.cancel != nil {
		r.cancel() // ← Stop polling loop immediately
	}
	go func() {
		if err := r.Close(); err != nil {
			r.lggr.Errorw("Failed to close reorg detector after finality violation",
				"chainSelector", r.config.ChainSelector,
				"error", err)
		}
	}()
}

// finalityViolationError is returned when a reorg violates finality.
type finalityViolationError struct {
	violatedBlock              protocol.BlockHeader
	newChainBlock              protocol.BlockHeader
	finalizedNum               uint64
	latestFinalizedBlockExists bool
}

func (e *finalityViolationError) Error() string {
	if !e.latestFinalizedBlockExists {
		return fmt.Sprintf("finality violation: finalized block %d not found in tail", e.finalizedNum)
	}
	return fmt.Sprintf("finality violation: finalized block hash %s does not match new chain hash %s at height %d",
		e.violatedBlock.Hash, e.newChainBlock.Hash, e.finalizedNum)
}

// Close stops the reorg detector and closes the status channel.
//
// Behavior:
// 1. Signals monitoring goroutine to stop via context cancellation
// 2. Waits for goroutine to finish (blocks until clean shutdown)
// 3. Closes status channel (readers will receive channel close signal)
//
// Thread-safety:
// - Safe to call multiple times (subsequent calls are no-ops)
// - Blocks until monitoring goroutine exits.
func (r *ReorgDetectorService) Close() error {
	return r.sync.StopOnce("ReorgDetectorService", func() error {
		r.lggr.Infow("Stopping ReorgDetectorService", "chainSelector", r.config.ChainSelector)

		// Signal cancellation
		r.cancel()

		// Wait for goroutines without holding lock
		r.wg.Wait()

		// Close status channel (safe - goroutine is stopped)
		close(r.statusCh)

		r.lggr.Infow("Reorg detector service closed", "chainSelector", r.config.ChainSelector)
		return nil
	})
}

// maxGapBlocks returns the dynamic maximum gap size based on tail size.
// Uses a percentage of the tail size with a minimum threshold.
func (r *ReorgDetectorService) maxGapBlocks() uint64 {
	tailSize := r.latestBlock - r.latestFinalizedBlock
	dynamicMax := uint64(float64(tailSize) * GapBlocksPercentage)
	if dynamicMax < MinGapBlocks {
		return MinGapBlocks
	}
	return dynamicMax
}
