package verifier

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/chainaccess"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

const (
	MAX_GAP_BLOCKS = 10 // Maximum allowed gap in blocks before rebuilding entire tail
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
	sourceReader SourceReader
	headTracker  chainaccess.HeadTracker
	config       ReorgDetectorConfig
	lggr         logger.Logger
	statusCh     chan protocol.ChainStatus
	cancel       context.CancelFunc
	wg           sync.WaitGroup

	// In-memory block tracking (keyed by block number for O(1) lookup)
	tailBlocks   map[uint64]protocol.BlockHeader
	tailMinBlock uint64 // Oldest block number in tail (finalized boundary)
	tailMaxBlock uint64 // Newest block number in tail (current tip)
	tailMu       sync.RWMutex

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
	sourceReader SourceReader,
	headTracker chainaccess.HeadTracker,
	config ReorgDetectorConfig,
	lggr logger.Logger,
) (*ReorgDetectorService, error) {
	// Validate configuration
	if sourceReader == nil {
		return nil, fmt.Errorf("source reader is required")
	}
	if headTracker == nil {
		return nil, fmt.Errorf("head tracker is required")
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
		pollInterval = 2000 * time.Millisecond
	}

	return &ReorgDetectorService{
		sourceReader: sourceReader,
		headTracker:  headTracker,
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
	if r.cancel != nil {
		return nil, fmt.Errorf("reorg detector already started")
	}

	r.lggr.Infow("Starting reorg detector service",
		"chainSelector", r.config.ChainSelector,
		"pollInterval", r.pollInterval)

	// Build initial tail
	if err := r.buildEntireTail(ctx); err != nil {
		return nil, fmt.Errorf("failed to build initial tail: %w", err)
	}

	ctx, cancel := context.WithCancel(ctx)
	r.cancel = cancel

	// Start polling goroutine
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		r.pollAndCheckForReorgs(ctx)
	}()

	r.lggr.Infow("Reorg detector service started successfully",
		"chainSelector", r.config.ChainSelector,
		"tailMinBlock", r.tailMinBlock,
		"tailMaxBlock", r.tailMaxBlock)

	return r.statusCh, nil
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
// Based on logpoller's getCurrentBlockMaybeHandleReorg pattern
func (r *ReorgDetectorService) checkBlockMaybeHandleReorg(ctx context.Context) {
	// Get current chain state in a single RPC call
	latest, finalized, err := r.headTracker.LatestAndFinalizedBlock(ctx)
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

	// Get expected parent and current tail state
	r.tailMu.RLock()
	tailMax := r.tailMaxBlock
	expectedParent, hasParent := r.tailBlocks[latest.Number-1]
	r.tailMu.RUnlock()

	// Check if chain has progressed
	if latest.Number <= tailMax {
		r.lggr.Debugw("No new blocks",
			"chainSelector", r.config.ChainSelector,
			"latestBlock", latest.Number,
			"tailMax", tailMax)
		return
	}

	// If we don't have the parent block, backfill the gap
	// Ideally this should not happen unless pollInterval is misconfigured to be more than block time
	if !hasParent {
		gapStart := tailMax + 1
		gapEnd := latest.Number - 1
		gapSize := gapEnd - gapStart + 1

		r.lggr.Debugw("Gap detected in tail, backfilling",
			"chainSelector", r.config.ChainSelector,
			"gapStart", gapStart,
			"gapEnd", gapEnd,
			"gapSize", gapSize,
			"latestBlock", latest.Number,
			"tailMax", tailMax)

		// Sanity check: gap should be reasonable
		// If gap > MAX_GAP_BLOCKS, something is very wrong (missed many polls, restart after long downtime, etc.)
		if gapSize > MAX_GAP_BLOCKS {
			r.lggr.Errorw("Unexpectedly large gap detected, rebuilding entire tail",
				"chainSelector", r.config.ChainSelector,
				"gapSize", gapSize,
				"tailMax", tailMax,
				"latestBlock", latest.Number)
			if err := r.buildEntireTail(ctx); err != nil {
				r.lggr.Errorw("Failed to rebuild tail after large gap",
					"chainSelector", r.config.ChainSelector,
					"error", err)
			}
			return
		}

		// Backfill missing blocks
		if err := r.backfillBlocks(ctx, gapStart, gapEnd, finalized.Number); err != nil {
			r.lggr.Errorw("Failed to backfill blocks",
				"chainSelector", r.config.ChainSelector,
				"gapStart", gapStart,
				"gapEnd", gapEnd,
				"error", err)
			return
		}

		// Re-fetch parent after backfill
		r.tailMu.RLock()
		expectedParent, hasParent = r.tailBlocks[latest.Number-1]
		r.tailMu.RUnlock()

		if !hasParent {
			r.lggr.Errorw("Parent block still missing after backfill",
				"chainSelector", r.config.ChainSelector,
				"parentBlock", latest.Number-1)
			return
		}

		r.lggr.Debugw("Successfully backfilled gap",
			"chainSelector", r.config.ChainSelector,
			"gapSize", gapSize)
	}

	// Check for reorg: does parent hash match?
	if latest.ParentHash != expectedParent.Hash {
		r.lggr.Debugw("Reorg detected - parent hash mismatch",
			"chainSelector", r.config.ChainSelector,
			"block", latest.Number,
			"expectedParentHash", expectedParent.Hash,
			"actualParentHash", latest.ParentHash)

		// Find LCA and handle reorg using finalized block number
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
	var blockNumbers []*big.Int
	for i := startBlock; i <= endBlock; i++ {
		blockNumbers = append(blockNumbers, new(big.Int).SetUint64(i))
	}

	headers, err := r.sourceReader.GetBlocksHeaders(ctx, blockNumbers)
	if err != nil {
		return fmt.Errorf("failed to fetch block headers for range [%d, %d]: %w", startBlock, endBlock, err)
	}

	// Add blocks to tail and trim old ones
	r.tailMu.Lock()
	defer r.tailMu.Unlock()

	for _, blockNum := range blockNumbers {
		header, exists := headers[blockNum]
		if !exists {
			return fmt.Errorf("missing block header for block %s", blockNum.String())
		}
		r.tailBlocks[header.Number] = header

		// Update tailMaxBlock as we go
		if header.Number > r.tailMaxBlock {
			r.tailMaxBlock = header.Number
		}
	}

	// Trim blocks older than finalized
	r.trimOlderBlocks(finalizedBlockNum)

	r.lggr.Debugw("Backfill completed",
		"chainSelector", r.config.ChainSelector,
		"tailMinBlock", r.tailMinBlock,
		"tailMaxBlock", r.tailMaxBlock,
		"tailSize", len(r.tailBlocks))

	return nil
}

// buildEntireTail rebuilds the entire tail from finalized to latest.
// Used when gap is too large or tail state is inconsistent.
func (r *ReorgDetectorService) buildEntireTail(ctx context.Context) error {
	r.lggr.Infow("Rebuilding entire tail",
		"chainSelector", r.config.ChainSelector)

	// Get current chain state
	latest, finalized, err := r.headTracker.LatestAndFinalizedBlock(ctx)
	if err != nil {
		return fmt.Errorf("failed to get latest and finalized blocks: %w", err)
	}
	if latest == nil || finalized == nil {
		return fmt.Errorf("received nil block headers")
	}

	finalizedBlockNum := finalized.Number
	latestBlockNum := latest.Number

	// Fetch block headers in the range [finalizedBlockNum, latestBlockNum]
	var blockNumbers []*big.Int
	for i := finalizedBlockNum; i <= latestBlockNum; i++ {
		blockNumbers = append(blockNumbers, new(big.Int).SetUint64(i))
	}

	headers, err := r.sourceReader.GetBlocksHeaders(ctx, blockNumbers)
	if err != nil {
		return fmt.Errorf("failed to fetch block headers: %w", err)
	}

	// Replace tail completely
	r.tailMu.Lock()
	defer r.tailMu.Unlock()

	r.tailBlocks = make(map[uint64]protocol.BlockHeader)
	for _, blockNum := range blockNumbers {
		header, exists := headers[blockNum]
		if !exists {
			return fmt.Errorf("missing block header for block %s", blockNum.String())
		}
		r.tailBlocks[header.Number] = header
	}

	r.tailMinBlock = finalizedBlockNum
	r.tailMaxBlock = latestBlockNum

	r.lggr.Infow("Tail rebuilt successfully",
		"chainSelector", r.config.ChainSelector,
		"minBlock", r.tailMinBlock,
		"maxBlock", r.tailMaxBlock,
		"tailSize", len(r.tailBlocks))

	return nil
}

// trimOlderBlocks removes blocks older than the finalized block from the tail.
// Must be called with tailMu lock held.
func (r *ReorgDetectorService) trimOlderBlocks(finalizedBlockNum uint64) {
	if r.tailMinBlock < finalizedBlockNum {
		for blockNum := r.tailMinBlock; blockNum < finalizedBlockNum; blockNum++ {
			delete(r.tailBlocks, blockNum)
		}
		r.tailMinBlock = finalizedBlockNum
	}
}

// addBlockToTail adds a new block to the tail and trims old blocks older than finalized.
// The finalized block is determined by HeadTracker (by depth or finality tag per chain).
func (r *ReorgDetectorService) addBlockToTail(block protocol.BlockHeader, finalizedBlockNum uint64) {
	r.tailMu.Lock()
	defer r.tailMu.Unlock()

	r.tailBlocks[block.Number] = block
	r.tailMaxBlock = block.Number

	// Trim blocks older than finalized
	r.trimOlderBlocks(finalizedBlockNum)

	r.lggr.Debugw("Added block to tail",
		"chainSelector", r.config.ChainSelector,
		"block", block.Number,
		"hash", block.Hash,
		"finalizedBlock", finalizedBlockNum,
		"tailSize", len(r.tailBlocks))
}

// handleReorg handles a detected reorg by finding the LCA and sending appropriate notifications.
func (r *ReorgDetectorService) handleReorg(ctx context.Context, newBlock protocol.BlockHeader, latestFinalizedBlock uint64) error {
	r.lggr.Infow("Handling reorg",
		"chainSelector", r.config.ChainSelector,
		"newBlock", newBlock.Number,
		"latestFinalized", latestFinalizedBlock)

	// Find block after LCA by walking back the new chain
	blockAfterLCA, err := r.findBlockAfterLCA(ctx, newBlock, latestFinalizedBlock)
	if err != nil {
		// Check if it's a finality violation
		var finalityViolationError *finalityViolationError
		if errors.As(err, &finalityViolationError) {
			r.lggr.Errorw("FINALITY VIOLATION DETECTED",
				"chainSelector", r.config.ChainSelector,
				"error", err)

			// Send finality violation notification
			r.sendFinalityViolation(blockAfterLCA, latestFinalizedBlock)
			return nil
		}
		return fmt.Errorf("failed to find LCA: %w", err)
	}

	// LCA is the parent of blockAfterLCA
	lcaBlockNumber := blockAfterLCA.Number - 1

	r.lggr.Infow("Found LCA",
		"chainSelector", r.config.ChainSelector,
		"lcaBlock", lcaBlockNumber,
		"blockAfterLCA", blockAfterLCA.Number)

	// Rebuild tail from blockAfterLCA
	if err := r.rebuildTailFromBlock(ctx, blockAfterLCA); err != nil {
		return fmt.Errorf("failed to rebuild tail: %w", err)
	}

	// Send reorg notification
	r.sendReorgNotification(lcaBlockNumber)

	return nil
}

// findBlockAfterLCA finds the block after the Last Common Ancestor by walking back
// the new chain and comparing with our stored blocks.
// Based on logpoller's findBlockAfterLCA algorithm.
func (r *ReorgDetectorService) findBlockAfterLCA(ctx context.Context, currentBlock protocol.BlockHeader, latestFinalizedBlock uint64) (protocol.BlockHeader, error) {
	// Walk back from current block's parent
	parent, err := r.sourceReader.GetBlockHeaderByHash(ctx, currentBlock.ParentHash)
	if err != nil {
		return protocol.BlockHeader{}, fmt.Errorf("failed to fetch parent block by hash %s: %w", currentBlock.ParentHash, err)
	}
	if parent == nil {
		return protocol.BlockHeader{}, fmt.Errorf("parent block not found for hash %s", currentBlock.ParentHash)
	}

	blockAfterLCA := currentBlock

	// Walk back until we find a matching block or hit finalized boundary
	for parent.Number >= latestFinalizedBlock {
		// Check if we have this block in our tail
		r.tailMu.RLock()
		ourBlock, exists := r.tailBlocks[parent.Number]
		r.tailMu.RUnlock()

		if exists && ourBlock.Hash == parent.Hash {
			// Found LCA! Return blockAfterLCA
			r.lggr.Debugw("Found matching block (LCA)",
				"chainSelector", r.config.ChainSelector,
				"lcaBlock", parent.Number,
				"lcaHash", parent.Hash)
			return blockAfterLCA, nil
		}

		// Continue walking back
		blockAfterLCA = *parent
		parent, err = r.sourceReader.GetBlockHeaderByHash(ctx, parent.ParentHash)
		if err != nil {
			return protocol.BlockHeader{}, fmt.Errorf("failed to fetch parent block by hash %s: %w", blockAfterLCA.ParentHash, err)
		}
		if parent == nil {
			return protocol.BlockHeader{}, fmt.Errorf("parent block not found for hash %s", blockAfterLCA.ParentHash)
		}
	}

	// Reorg is deeper than finalized block - finality violation
	r.tailMu.RLock()
	ourFinalizedBlock, exists := r.tailBlocks[latestFinalizedBlock]
	r.tailMu.RUnlock()

	return blockAfterLCA, &finalityViolationError{
		violatedBlock:              ourFinalizedBlock,
		newChainBlock:              blockAfterLCA,
		finalizedNum:               latestFinalizedBlock,
		latestFinalizedBlockExists: exists,
	}
}

// rebuildTailFromBlock rebuilds the tail starting from the given block (block after LCA)
// up to the current latest block.
func (r *ReorgDetectorService) rebuildTailFromBlock(ctx context.Context, startBlock protocol.BlockHeader) error {
	r.lggr.Infow("Rebuilding tail from block",
		"chainSelector", r.config.ChainSelector,
		"startBlock", startBlock.Number)

	// Get current latest block to know how far to fetch
	latest, _, err := r.headTracker.LatestAndFinalizedBlock(ctx)
	if err != nil {
		return fmt.Errorf("failed to get latest block: %w", err)
	}
	if latest == nil {
		return fmt.Errorf("latest block is nil")
	}

	// Fetch blocks from startBlock to current latest
	endBlock := latest.Number

	var blockNumbers []*big.Int
	for i := startBlock.Number; i <= endBlock; i++ {
		blockNumbers = append(blockNumbers, new(big.Int).SetUint64(i))
	}

	headers, err := r.sourceReader.GetBlocksHeaders(ctx, blockNumbers)
	if err != nil {
		return fmt.Errorf("failed to fetch block headers: %w", err)
	}

	// Clear old tail and rebuild
	r.tailMu.Lock()
	defer r.tailMu.Unlock()

	r.tailBlocks = make(map[uint64]protocol.BlockHeader)
	for _, blockNum := range blockNumbers {
		header, exists := headers[blockNum]
		if !exists {
			// Block might not exist yet if we're at chain tip
			// In this case, just stop here
			break
		}
		r.tailBlocks[header.Number] = header
	}

	r.tailMinBlock = startBlock.Number
	r.tailMaxBlock = startBlock.Number + uint64(len(r.tailBlocks)) - 1

	r.lggr.Infow("Tail rebuilt successfully",
		"chainSelector", r.config.ChainSelector,
		"minBlock", r.tailMinBlock,
		"maxBlock", r.tailMaxBlock,
		"tailSize", len(r.tailBlocks))

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
	r.tailMu.Lock()
	defer r.tailMu.Unlock()

	// Check if already closed
	if r.cancel == nil {
		return nil // Already closed
	}

	r.lggr.Infow("Closing reorg detector service", "chainSelector", r.config.ChainSelector)

	// Signal cancellation
	r.cancel()
	r.cancel = nil // Mark as closed

	// Release lock while waiting for goroutines
	r.tailMu.Unlock()
	r.wg.Wait()
	r.tailMu.Lock()

	// Close status channel (only once)
	close(r.statusCh)

	r.lggr.Infow("Reorg detector service closed", "chainSelector", r.config.ChainSelector)
	return nil
}
