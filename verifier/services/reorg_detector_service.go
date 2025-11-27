package services

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"sync/atomic"
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
	// FinalizedBufferPercentage defines the buffer of finalized blocks to keep as percentage of tail
	// Keeps historical finalized blocks to verify backwards finality changes without extra RPC calls
	FinalizedBufferPercentage = 0.20 // 20% of tail size
	// MinFinalizedBuffer is the minimum number of finalized blocks to keep
	MinFinalizedBuffer = 10
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

	// Finality violation flag - once set, no more notifications are sent
	finalityViolated atomic.Bool
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

// isFinalityViolation checks for finality violations and RPC consistency.
// Returns true if a finality violation is detected.
func (r *ReorgDetectorService) isFinalityViolation(
	latest *protocol.BlockHeader,
	finalized *protocol.BlockHeader,
) bool {
	// Check RPC consistency: latest should always be >= finalized
	if latest.Number < finalized.Number {
		if r.checkBlockConsistency(*latest) {
			return false
		}
		r.lggr.Infow("Finality violation reason: RPC inconsistency with hash mismatch",
			"latestNum", latest.Number,
			"finalizedNum", finalized.Number)
		return true
	}

	// Check if finalized went backwards
	if finalized.Number < r.latestFinalizedBlock {
		if r.checkBlockConsistency(*finalized) {
			return false
		}
		r.lggr.Infow("Finality violation reason: finalized went backwards with hash mismatch",
			"ourFinalizedNum", r.latestFinalizedBlock,
			"newFinalizedNum", finalized.Number)
		return true
	}

	// Check if finalized advanced - verify hash if we have the block
	if finalized.Number > r.latestFinalizedBlock {
		if _, exists := r.tailBlocks[finalized.Number]; exists {
			if !r.checkBlockConsistency(*finalized) {
				r.lggr.Infow("Finality violation reason: finalized hash mismatch",
					"finalizedNum", finalized.Number,
					"finalizedHash", finalized.Hash)
				return true
			}
		}
		// If we don't have it yet, we'll verify chain continuity when processing new blocks
	}

	return false
}

// isReorg checks if a reorg occurred.
// Returns true if reorg detected, false otherwise (including gaps).
func (r *ReorgDetectorService) isReorg(latest protocol.BlockHeader) bool {
	// Chain is at same height or went backwards
	if latest.Number <= r.latestBlock {
		if r.checkBlockConsistency(latest) {
			// Same block we already have - RPC is behind or duplicate poll
			return false
		}
		// Different hash or missing block - reorg detected
		r.lggr.Infow("Reorg detected: hash mismatch at same/earlier height",
			"blockNum", latest.Number,
			"blockHash", latest.Hash)
		return true
	}

	// New block - check parent hash if parent exists
	expectedParent, hasParent := r.tailBlocks[latest.Number-1]
	if !hasParent {
		return false // Gap exists, not a reorg (caller handles gap)
	}

	if latest.ParentHash != expectedParent.Hash {
		r.lggr.Infow("Reorg detected: parent hash mismatch", "blockNum", latest.Number)
		return true
	}

	return false
}

// hasParentBlock checks if we have the parent block in our tail
func (r *ReorgDetectorService) hasParentBlock(blockNum uint64) bool {
	if blockNum == 0 {
		return true // Genesis
	}
	_, exists := r.tailBlocks[blockNum-1]
	return exists
}

// checkBlockConsistency checks if a block at given height matches what we have stored.
// Returns true if the block exists in tail and hash matches (consistent).
// Returns false if hash mismatch or block not in tail (inconsistent).
func (r *ReorgDetectorService) checkBlockConsistency(block protocol.BlockHeader) bool {
	stored, exists := r.tailBlocks[block.Number]
	if !exists {
		r.lggr.Debugw("Block not found in tail for consistency check",
			"blockNum", block.Number)
		return false
	}
	return stored.Hash == block.Hash
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
	latest, finalized, err := r.sourceReader.LatestAndFinalizedBlock(ctx)
	if err != nil {
		r.lggr.Errorw("Failed to fetch latest blocks",
			"chainSelector", r.config.ChainSelector,
			"error", err)
		return
	}
	if latest == nil || finalized == nil {
		r.lggr.Errorw("Received nil block headers",
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

	// Check for finality violations and RPC consistency
	if r.isFinalityViolation(latest, finalized) {
		r.lggr.Errorw("FINALITY VIOLATION detected - stopping processing")
		r.sendFinalityViolation(finalized.Number)
		return
	}

	// Detect reorg
	if r.isReorg(*latest) {
		// Reorg detected and logged inside isReorg
		if err := r.handleReorg(ctx, *latest, finalized.Number); err != nil {
			r.lggr.Errorw("Failed to handle reorg", "error", err)
		}
		return
	}

	// No reorg - fill any missing blocks and validate chain continuity
	r.fillMissingAndValidate(ctx, *latest, finalized)
}

// fillMissingAndValidate fills any missing blocks between our latest and the new block,
// validates chain continuity, and adds the new block.
// Handles both normal progression (0 missing) and gaps (1+ missing blocks).
func (r *ReorgDetectorService) fillMissingAndValidate(
	ctx context.Context,
	latest protocol.BlockHeader,
	finalized *protocol.BlockHeader,
) {
	missingBlockCount := latest.Number - r.latestBlock - 1

	// Fill missing blocks if any (could be 0 for normal progression, 1+ for gaps)
	if missingBlockCount > 0 {
		tailMaxBeforeFill := r.latestBlock

		// Backfill missing blocks
		_, ok := r.handleGapBackfill(ctx, r.latestBlock, latest.Number, finalized.Number)
		if !ok {
			return
		}

		// Validate filled blocks connect to existing tail
		firstFilledBlock, exists := r.tailBlocks[tailMaxBeforeFill+1]
		oldTailTop, tailTopExists := r.tailBlocks[tailMaxBeforeFill]

		if exists && tailTopExists {
			if firstFilledBlock.ParentHash != oldTailTop.Hash {
				r.lggr.Infow("Reorg detected - filled blocks don't connect to tail",
					"tailMax", tailMaxBeforeFill,
					"expectedParentHash", oldTailTop.Hash,
					"actualParentHash", firstFilledBlock.ParentHash)

				if err := r.handleReorg(ctx, latest, finalized.Number); err != nil {
					r.lggr.Errorw("Failed to handle reorg after fill", "error", err)
				}
				return
			}
		}
	}

	// Validate latest block's parent hash (always check, whether we filled blocks or not)
	expectedParent, hasParent := r.tailBlocks[latest.Number-1]
	if hasParent && latest.ParentHash != expectedParent.Hash {
		r.lggr.Infow("Reorg detected - parent hash mismatch",
			"block", latest.Number,
			"expectedParentHash", expectedParent.Hash,
			"actualParentHash", latest.ParentHash)

		if err := r.handleReorg(ctx, latest, finalized.Number); err != nil {
			r.lggr.Errorw("Failed to handle reorg", "error", err)
		}
		return
	}

	// All good - add block
	r.addBlockToTail(latest, finalized.Number)
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

// trimOlderBlocks removes blocks older than finalized minus buffer from the tail.
// Keeps a dynamic buffer of finalized blocks (based on tail size) for backwards finality verification.
// Tail range: [finalized - buffer, latest]
// Called only by the polling goroutine (single-writer).
func (r *ReorgDetectorService) trimOlderBlocks(finalizedBlockNum uint64) {
	if r.latestFinalizedBlock < finalizedBlockNum {
		// Calculate buffer size: percentage of tail with minimum threshold
		tailSize := r.latestBlock - finalizedBlockNum
		bufferSize := uint64(float64(tailSize) * FinalizedBufferPercentage)
		if bufferSize < MinFinalizedBuffer {
			bufferSize = MinFinalizedBuffer
		}

		// Calculate trim point: keep buffer of blocks before finalized
		var trimBelow uint64
		if finalizedBlockNum > bufferSize {
			trimBelow = finalizedBlockNum - bufferSize
		} else {
			trimBelow = 0 // Don't trim if we're still near genesis
		}

		// Trim blocks below the buffer threshold
		for blockNum := r.latestFinalizedBlock; blockNum < trimBelow; blockNum++ {
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
			"latestBlock", latestBlockNum,
			"state", r.dumpTailState())
		if err := r.buildEntireTail(ctx); err != nil {
			r.lggr.Errorw("Failed to rebuild tail after large gap",
				"chainSelector", r.config.ChainSelector,
				"error", err,
				"state", r.dumpTailState())
		}
		return protocol.BlockHeader{}, false
	}

	// Backfill missing blocks
	if err := r.backfillBlocks(ctx, gapStart, gapEnd, finalizedBlockNum); err != nil {
		r.lggr.Errorw("Failed to backfill blocks",
			"chainSelector", r.config.ChainSelector,
			"gapStart", gapStart,
			"gapEnd", gapEnd,
			"error", err,
			"state", r.dumpTailState())
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
	r.lggr.Infow("Handling reorg")

	// Find block after LCA by walking back the new chain
	// Use our stored finalized block, not the new finalized, because LCA could be below new finalized
	blockAfterLCA, err := r.findBlockAfterLCA(ctx, newBlock, r.latestFinalizedBlock)
	if err != nil {
		// Check if it's a finality violation
		var finalityViolationError *finalityViolationError
		if errors.As(err, &finalityViolationError) {
			r.lggr.Errorw("FINALITY VIOLATION detected",
				"chainSelector", r.config.ChainSelector,
				"error", err,
				"state", r.dumpTailState())

			// Send finality violation notification
			r.sendFinalityViolation(finalizedBlockNum)
			return nil
		}
		return fmt.Errorf("failed to find LCA: %w", err)
	}

	// LCA is the parent of blockAfterLCA
	lcaBlockNumber := blockAfterLCA.Number - 1

	r.lggr.Infow("Found LCA - preparing to rebuild tail",
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
		"currentBlockHash", currentBlock.Hash,
		"ourFinalizedBlock", ourFinalizedBlock,
		"ourLatestBlock", r.latestBlock,
		"tailSize", len(r.tailBlocks))

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
		"tailSize", len(r.tailBlocks),
		"state", r.dumpTailState())

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
	// Don't send any more notifications if finality was violated
	if r.finalityViolated.Load() {
		r.lggr.Warnw("Skipping reorg notification - finality already violated",
			"chainSelector", r.config.ChainSelector,
			"lcaBlockNumber", lcaBlockNumber)
		return
	}

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

// sendFinalityViolation sends a finality violation notification and stops the polling loop.
// No reset block is provided - finality violations require immediate stop and manual intervention.
// The coordinator is responsible for closing the detector after receiving this notification.
func (r *ReorgDetectorService) sendFinalityViolation(finalizedBlockNum uint64) {
	// Set flag to prevent any more notifications
	r.finalityViolated.Store(true)

	status := protocol.ChainStatus{
		Type:         protocol.ReorgTypeFinalityViolation,
		ResetToBlock: 0, // No safe reset point exists
	}

	select {
	case r.statusCh <- status:
		r.lggr.Infow("Sent finality violation notification - stopping polling")
	default:
		r.lggr.Warnw("Status channel full, dropping finality violation notification")
	}

	// Signal the polling loop to stop immediately
	// The coordinator will close the detector after receiving the notification
	if r.cancel != nil {
		r.cancel()
	}
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

// dumpTailState returns current tail state for debugging
func (r *ReorgDetectorService) dumpTailState() map[string]interface{} {
	tailBlockNums := make([]uint64, 0, len(r.tailBlocks))
	for blockNum := range r.tailBlocks {
		tailBlockNums = append(tailBlockNums, blockNum)
	}
	// Sort for readability
	for i := 0; i < len(tailBlockNums); i++ {
		for j := i + 1; j < len(tailBlockNums); j++ {
			if tailBlockNums[i] > tailBlockNums[j] {
				tailBlockNums[i], tailBlockNums[j] = tailBlockNums[j], tailBlockNums[i]
			}
		}
	}

	return map[string]interface{}{
		"chainSelector":        r.config.ChainSelector,
		"latestBlock":          r.latestBlock,
		"latestFinalizedBlock": r.latestFinalizedBlock,
		"tailSize":             len(r.tailBlocks),
		"tailBlockNumbers":     tailBlockNums,
		"finalityViolated":     r.finalityViolated.Load(),
	}
}

// validateChainContinuity checks if blocks form valid chain via parent hashes.
// Returns error if any block's parent hash doesn't match previous block's hash.
func (r *ReorgDetectorService) validateChainContinuity(
	blocks map[uint64]protocol.BlockHeader,
	startNum, endNum uint64,
) error {
	for i := startNum + 1; i <= endNum; i++ {
		current, currentExists := blocks[i]
		parent, parentExists := blocks[i-1]

		if !currentExists {
			return fmt.Errorf("missing block %d in range", i)
		}
		if !parentExists {
			return fmt.Errorf("missing parent block %d", i-1)
		}

		if current.ParentHash != parent.Hash {
			return fmt.Errorf("parent hash mismatch at block %d: "+
				"parent.Hash=%s but current.ParentHash=%s",
				i, parent.Hash, current.ParentHash)
		}
	}
	return nil
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
