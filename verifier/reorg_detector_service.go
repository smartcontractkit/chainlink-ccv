package verifier

import (
	"context"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// ReorgDetectorConfig contains configuration for the reorg detector service.
type ReorgDetectorConfig struct {
	// ChainSelector identifies the chain being monitored
	ChainSelector protocol.ChainSelector

	// FinalityDepth is the number of blocks before considering a block "final".
	// Blocks deeper than this are assumed safe from reorgs.
	// The chain tail is automatically sized to 2 * FinalityDepth to provide
	// sufficient buffer for reorg detection before finality violations.
	// This is chain-specific (e.g., 64 for Ethereum, 128 for Polygon).
	// Default: 64 blocks
	FinalityDepth uint64
}

// ReorgDetectorService detects blockchain reorganizations by subscribing to block headers.
// It wraps a SourceReader to provide a unified, chain-agnostic reorg detection mechanism.
//
// Architecture:
// - Uses SourceReader.SubscribeNewHeads() to receive block headers
// - Maintains a "tail" of recent block hashes (automatically 2 * FinalityDepth blocks)
// - Detects reorgs by comparing new block hashes with stored tail
// - Sends notifications via channel only when reorgs or finality violations are detected
//
// Tail Sizing:
// - Tail length = 2 * FinalityDepth (automatic, not configurable)
// - This provides sufficient buffer to catch reorgs before they become finality violations
// - Example: FinalityDepth=64 → tail tracks 128 blocks
//
// Lifecycle:
// - Start() initializes the tail and subscribes (blocks until ready)
// - Returns a channel that receives ChainStatus updates (only on problems)
// - Close() stops monitoring and closes the status channel
//
// Integration:
// - Created per source chain in Coordinator.Start()
// - Runs alongside SourceReaderService for each chain
// - Uses same SourceReader instance to share RPC connections
type ReorgDetectorService struct {
	sourceReader SourceReader
	config       ReorgDetectorConfig
	lggr         logger.Logger
	statusCh     chan protocol.ChainStatus
	cancel       context.CancelFunc
	doneCh       chan struct{}

	// Tail tracking
	chainTail       *protocol.ChainTail
	tailMu          sync.RWMutex
	lastSeenBlock   uint64
	lastSeenBlockMu sync.RWMutex
}

// NewReorgDetectorService creates a new reorg detector service.
//
// Parameters:
// - sourceReader: Used to subscribe to block headers and fetch block hashes
// - config: Configuration including chain selector and finality depth
// - lggr: Logger for operational visibility
//
// Returns:
// - *ReorgDetectorService ready to be started
// - error if configuration is invalid
func NewReorgDetectorService(
	sourceReader SourceReader,
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

	// Set defaults
	if config.FinalityDepth == 0 {
		config.FinalityDepth = 64 // Ethereum finality depth
	}

	return &ReorgDetectorService{
		sourceReader: sourceReader,
		config:       config,
		lggr:         lggr,
		statusCh:     make(chan protocol.ChainStatus, 1),
		doneCh:       make(chan struct{}),
	}, nil
}

// getTailLength returns the number of blocks to track in the chain tail.
// This is automatically calculated as 2 * FinalityDepth to provide sufficient
// buffer for reorg detection before finality violations occur.
func (r *ReorgDetectorService) getTailLength() int {
	return int(r.config.FinalityDepth * 2)
}

// Start initializes the reorg detector and begins monitoring.
//
// Behavior:
// 1. Fetches the latest finalized block from the source chain
// 2. Builds initial chain tail (2 * FinalityDepth blocks back from finalized)
// 3. Subscribes to new block headers
// 4. Spawns background goroutine to process subscribed blocks
// 5. Returns immediately once subscription is established (synchronous init)
//
// The status channel will receive:
// - ChainStatusReorg: When a reorg is detected (includes reorg depth and common ancestor)
// - ChainStatusFinalityViolated: When a block deeper than FinalityDepth is reorged
//
// Returns:
// - <-chan protocol.ChainStatus: Receive-only channel for status updates
// - error: If initial tail cannot be fetched, subscription fails, or context is cancelled
//
// Thread-safety:
// - Safe to call once per instance
// - Subsequent calls will return an error
func (r *ReorgDetectorService) Start(ctx context.Context) (<-chan protocol.ChainStatus, error) {
	r.lggr.Infow("Starting reorg detector service",
		"chainSelector", r.config.ChainSelector,
		"finalityDepth", r.config.FinalityDepth)

	// Create cancellable context for monitoring goroutine
	//ctx, r.cancel = context.WithCancel(ctx)
	//
	//// Build initial tail
	//tail, err := r.buildInitialTail(ctx)
	//if err != nil {
	//	return nil, fmt.Errorf("failed to build initial tail: %w", err)
	//}
	//
	//r.tailMu.Lock()
	//r.chainTail = tail
	//r.lastSeenBlock = tail.Tip().Number
	//r.tailMu.Unlock()
	//
	//r.lggr.Infow("Initial tail built successfully",
	//	"chainSelector", r.config.ChainSelector,
	//	"stableTip", tail.StableTip().Number,
	//	"tip", tail.Tip().Number,
	//	"tailLength", tail.Len())
	//
	//// Subscribe to new heads
	//headsCh, err := r.sourceReader.SubscribeNewHeads(ctx)
	//if err != nil {
	//	return nil, fmt.Errorf("failed to subscribe to new heads: %w", err)
	//}
	//
	//r.lggr.Infow("Subscribed to new heads successfully",
	//	"chainSelector", r.config.ChainSelector)
	//
	//// Start monitoring goroutine
	//go r.monitorSubscription(ctx, headsCh)

	return r.statusCh, nil
}

// buildInitialTail fetches the initial chain tail by walking back from the finalized head.
func (r *ReorgDetectorService) buildInitialTail(ctx context.Context) (*protocol.ChainTail, error) {
	// Get latest finalized block
	finalizedBlock, err := r.sourceReader.LatestFinalizedBlockHeight(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get latest finalized block: %w", err)
	}

	r.lggr.Infow("Building initial tail from finalized block",
		"chainSelector", r.config.ChainSelector,
		"finalizedBlock", finalizedBlock.String(),
		"blocksToFetch", r.getTailLength())

	// Calculate starting block (finalized - tailLength)
	tailLength := int64(r.getTailLength())
	startBlock := new(big.Int).Sub(finalizedBlock, big.NewInt(tailLength-1))
	if startBlock.Sign() < 0 {
		startBlock = big.NewInt(0)
	}

	// Fetch block headers
	var blocks []protocol.BlockHeader
	for blockNum := new(big.Int).Set(startBlock); blockNum.Cmp(finalizedBlock) <= 0; blockNum.Add(blockNum, big.NewInt(1)) {
		header, err := r.sourceReader.GetBlockHeader(ctx, blockNum)
		if err != nil {
			return nil, fmt.Errorf("failed to get block header at %s: %w", blockNum.String(), err)
		}
		blocks = append(blocks, *header)
	}

	if len(blocks) == 0 {
		return nil, fmt.Errorf("no blocks fetched for initial tail")
	}

	// Create and validate chain tail
	tail, err := protocol.NewChainTail(blocks)
	if err != nil {
		return nil, fmt.Errorf("failed to create chain tail: %w", err)
	}

	return tail, nil
}

// monitorSubscription is the main monitoring loop that processes subscribed blocks.
//
// Algorithm:
//  1. Receive new block header from subscription
//  2. Check for gaps (missing block numbers) - backfill if needed - in case there were any network issues with subscription
//  3. Compare block hash with stored tail at same height
//  4. If mismatch detected:
//     a. Identify common ancestor (walk back until hashes match)
//     b. Calculate reorg depth
//     c. Check if reorg violates finality (depth > FinalityDepth)
//     d. Send appropriate ChainStatus notification
//     e. Rebuild tail from common ancestor
//  5. Update tail with new block (maintain 2 * FinalityDepth length)
//  6. Handle subscription failures (channel close) - attempt resubscription
//
// Error handling:
// - Transient RPC errors during backfill: Log warning, continue
// - Subscription channel close: Attempt resubscription with backfill
// - Context cancellation: Clean shutdown
func (r *ReorgDetectorService) monitorSubscription(ctx context.Context, headsCh <-chan protocol.BlockHeader) {
	defer close(r.doneCh)

	r.lggr.Infow("Reorg monitoring loop started", "chainSelector", r.config.ChainSelector)

	for {
		select {
		case <-ctx.Done():
			r.lggr.Infow("Reorg monitoring loop stopped", "chainSelector", r.config.ChainSelector)
			return

		case newHead, ok := <-headsCh:
			if !ok {
				// Subscription channel closed - attempt recovery
				r.lggr.Warnw("Subscription channel closed, attempting recovery",
					"chainSelector", r.config.ChainSelector)

				// Try to resubscribe with backfill
				newHeadsCh, err := r.handleSubscriptionFailure(ctx)
				if err != nil {
					r.lggr.Errorw("Failed to recover from subscription failure",
						"chainSelector", r.config.ChainSelector,
						"error", err)
					return
				}

				headsCh = newHeadsCh
				continue
			}

			// Process the new head
			if err := r.processNewHead(ctx, newHead); err != nil {
				r.lggr.Errorw("Failed to process new head",
					"chainSelector", r.config.ChainSelector,
					"blockNumber", newHead.Number,
					"error", err)
				// Continue processing - don't stop on transient errors
			}
		}
	}
}

// processNewHead processes a newly received block header.
func (r *ReorgDetectorService) processNewHead(ctx context.Context, newHead protocol.BlockHeader) error {
	r.lastSeenBlockMu.RLock()
	lastSeen := r.lastSeenBlock
	r.lastSeenBlockMu.RUnlock()

	// Check for gaps
	if newHead.Number > lastSeen+1 {
		r.lggr.Warnw("Gap detected in block subscription",
			"chainSelector", r.config.ChainSelector,
			"lastSeen", lastSeen,
			"newHead", newHead.Number,
			"gap", newHead.Number-lastSeen-1)

		// Backfill the gap
		if err := r.backfillGap(ctx, lastSeen+1, newHead.Number-1); err != nil {
			r.lggr.Errorw("Failed to backfill gap",
				"chainSelector", r.config.ChainSelector,
				"error", err)
			// Continue anyway - we'll check the new head
		}
	}

	// Check for reorg
	r.tailMu.Lock()
	defer r.tailMu.Unlock()

	// Check if we have this block number in our tail
	existingBlock := r.chainTail.BlockByNumber(newHead.Number)
	if existingBlock != nil {
		// We have this block number - check if hash matches
		if existingBlock.Hash != newHead.Hash {
			// Reorg detected!
			r.lggr.Warnw("Reorg detected",
				"chainSelector", r.config.ChainSelector,
				"blockNumber", newHead.Number,
				"oldHash", existingBlock.Hash,
				"newHash", newHead.Hash)

			return r.handleReorg(ctx, newHead)
		}
		// Hash matches - no reorg, just update last seen
		r.lastSeenBlockMu.Lock()
		r.lastSeenBlock = newHead.Number
		r.lastSeenBlockMu.Unlock()
		return nil
	}

	// This is a new block - add to tail
	if err := r.appendToTail(newHead); err != nil {
		return fmt.Errorf("failed to append to tail: %w", err)
	}

	r.lastSeenBlockMu.Lock()
	r.lastSeenBlock = newHead.Number
	r.lastSeenBlockMu.Unlock()

	r.lggr.Debugw("New block added to tail",
		"chainSelector", r.config.ChainSelector,
		"blockNumber", newHead.Number,
		"hash", newHead.Hash)

	return nil
}

// handleReorg handles a detected reorg by finding the common ancestor and notifying the coordinator.
func (r *ReorgDetectorService) handleReorg(ctx context.Context, newHead protocol.BlockHeader) error {
	// Find common ancestor by walking back
	commonAncestor, err := r.findCommonAncestor(ctx, newHead)
	if err != nil {
		return fmt.Errorf("failed to find common ancestor: %w", err)
	}

	reorgDepth := newHead.Number - commonAncestor

	r.lggr.Infow("Reorg details",
		"chainSelector", r.config.ChainSelector,
		"newHead", newHead.Number,
		"commonAncestor", commonAncestor,
		"depth", reorgDepth,
		"finalityDepth", r.config.FinalityDepth)

	// Check if this violates finality
	if reorgDepth > r.config.FinalityDepth {
		// Finality violation!
		r.lggr.Errorw("FINALITY VIOLATION DETECTED",
			"chainSelector", r.config.ChainSelector,
			"reorgDepth", reorgDepth,
			"finalityDepth", r.config.FinalityDepth,
			"commonAncestor", commonAncestor)

		// Build new tail from common ancestor
		newTail, err := r.rebuildTailFromBlock(ctx, commonAncestor)
		if err != nil {
			return fmt.Errorf("failed to rebuild tail after finality violation: %w", err)
		}

		violatedBlock := r.chainTail.StableTip()
		status := protocol.ChainStatusFinalityViolated{
			ViolatedBlock:    violatedBlock,
			NewTail:          *newTail,
			SafeRestartBlock: commonAncestor,
		}

		r.chainTail = newTail

		select {
		case r.statusCh <- status:
			r.lggr.Infow("Sent finality violation notification",
				"chainSelector", r.config.ChainSelector)
		case <-ctx.Done():
			return ctx.Err()
		}
	} else {
		// Regular reorg
		r.lggr.Warnw("Regular reorg detected",
			"chainSelector", r.config.ChainSelector,
			"depth", reorgDepth,
			"commonAncestor", commonAncestor)

		// Build new tail from common ancestor
		newTail, err := r.rebuildTailFromBlock(ctx, commonAncestor)
		if err != nil {
			return fmt.Errorf("failed to rebuild tail after reorg: %w", err)
		}

		status := protocol.ChainStatusReorg{
			NewTail:             *newTail,
			CommonAncestorBlock: commonAncestor,
		}

		r.chainTail = newTail

		select {
		case r.statusCh <- status:
			r.lggr.Infow("Sent reorg notification",
				"chainSelector", r.config.ChainSelector)
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return nil
}

// findCommonAncestor finds the common ancestor between the current tail and the new chain.
func (r *ReorgDetectorService) findCommonAncestor(ctx context.Context, newHead protocol.BlockHeader) (uint64, error) {
	// Walk back from the new head until we find a matching hash in our tail
	currentBlockNum := newHead.Number

	for currentBlockNum > 0 {
		// Get current chain's block hash
		header, err := r.sourceReader.GetBlockHeader(ctx, big.NewInt(int64(currentBlockNum)))
		if err != nil {
			return 0, fmt.Errorf("failed to get block header at %d: %w", currentBlockNum, err)
		}

		// Check if we have this block in our tail
		existingBlock := r.chainTail.BlockByNumber(currentBlockNum)
		if existingBlock != nil && existingBlock.Hash == header.Hash {
			// Found common ancestor
			return currentBlockNum, nil
		}

		currentBlockNum--
	}

	// If we get here, the common ancestor is genesis (block 0)
	return 0, nil
}

// rebuildTailFromBlock rebuilds the chain tail starting from a given block number.
func (r *ReorgDetectorService) rebuildTailFromBlock(ctx context.Context, fromBlock uint64) (*protocol.ChainTail, error) {
	// Get current chain head
	latestBlock, err := r.sourceReader.LatestBlockHeight(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get latest block: %w", err)
	}

	// Calculate how many blocks to fetch (up to tailLength)
	tailLength := uint64(r.getTailLength())
	startBlock := fromBlock
	if latestBlock.Uint64() > fromBlock+tailLength {
		startBlock = latestBlock.Uint64() - tailLength
	}

	r.lggr.Infow("Rebuilding tail",
		"chainSelector", r.config.ChainSelector,
		"fromBlock", fromBlock,
		"startBlock", startBlock,
		"latestBlock", latestBlock.String())

	// Fetch block headers
	var blocks []protocol.BlockHeader
	for blockNum := startBlock; blockNum <= latestBlock.Uint64(); blockNum++ {
		header, err := r.sourceReader.GetBlockHeader(ctx, big.NewInt(int64(blockNum)))
		if err != nil {
			return nil, fmt.Errorf("failed to get block header at %d: %w", blockNum, err)
		}
		blocks = append(blocks, *header)
	}

	if len(blocks) == 0 {
		return nil, fmt.Errorf("no blocks fetched while rebuilding tail")
	}

	// Create and validate chain tail
	tail, err := protocol.NewChainTail(blocks)
	if err != nil {
		return nil, fmt.Errorf("failed to create chain tail: %w", err)
	}

	return tail, nil
}

// appendToTail adds a new block to the tail and maintains the tail length.
func (r *ReorgDetectorService) appendToTail(newBlock protocol.BlockHeader) error {
	// Verify parent hash matches
	currentTip := r.chainTail.Tip()
	if newBlock.ParentHash != currentTip.Hash {
		return fmt.Errorf("parent hash mismatch: new block parent %s != current tip hash %s",
			newBlock.ParentHash, currentTip.Hash)
	}

	// Add new block to tail
	allBlocks := append(r.chainTail.Blocks(), newBlock)

	// Trim if exceeds tail length
	maxLen := r.getTailLength()
	if len(allBlocks) > maxLen {
		allBlocks = allBlocks[len(allBlocks)-maxLen:]
	}

	// Create new tail
	newTail, err := protocol.NewChainTail(allBlocks)
	if err != nil {
		return fmt.Errorf("failed to create new tail: %w", err)
	}

	r.chainTail = newTail
	return nil
}

// backfillGap fills in missing blocks between lastSeen and beforeBlock.
func (r *ReorgDetectorService) backfillGap(ctx context.Context, fromBlock, toBlock uint64) error {
	r.lggr.Infow("Backfilling gap",
		"chainSelector", r.config.ChainSelector,
		"fromBlock", fromBlock,
		"toBlock", toBlock)

	for blockNum := fromBlock; blockNum <= toBlock; blockNum++ {
		header, err := r.sourceReader.GetBlockHeader(ctx, big.NewInt(int64(blockNum)))
		if err != nil {
			return fmt.Errorf("failed to get block header at %d during backfill: %w", blockNum, err)
		}

		// Process this block like a normal subscription update
		r.tailMu.Lock()
		if err := r.appendToTail(*header); err != nil {
			r.tailMu.Unlock()
			r.lggr.Warnw("Failed to append backfilled block to tail",
				"chainSelector", r.config.ChainSelector,
				"blockNumber", blockNum,
				"error", err)
			// Continue with next block
			continue
		}
		r.tailMu.Unlock()

		r.lastSeenBlockMu.Lock()
		r.lastSeenBlock = blockNum
		r.lastSeenBlockMu.Unlock()
	}

	r.lggr.Infow("Gap backfilled successfully",
		"chainSelector", r.config.ChainSelector,
		"fromBlock", fromBlock,
		"toBlock", toBlock)

	return nil
}

// handleSubscriptionFailure attempts to recover from a subscription failure.
func (r *ReorgDetectorService) handleSubscriptionFailure(ctx context.Context) (<-chan protocol.BlockHeader, error) {
	r.lggr.Warnw("Attempting to recover from subscription failure",
		"chainSelector", r.config.ChainSelector)

	// Get current chain head to calculate gap
	latestBlock, err := r.sourceReader.LatestBlockHeight(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get latest block during recovery: %w", err)
	}

	r.lastSeenBlockMu.RLock()
	lastSeen := r.lastSeenBlock
	r.lastSeenBlockMu.RUnlock()

	// Backfill gap if any
	if latestBlock.Uint64() > lastSeen {
		gap := latestBlock.Uint64() - lastSeen
		r.lggr.Warnw("Backfilling gap before resubscribing",
			"chainSelector", r.config.ChainSelector,
			"lastSeen", lastSeen,
			"latestBlock", latestBlock.String(),
			"gap", gap)

		if err := r.backfillGap(ctx, lastSeen+1, latestBlock.Uint64()); err != nil {
			r.lggr.Errorw("Failed to backfill gap during recovery",
				"chainSelector", r.config.ChainSelector,
				"error", err)
			// Continue with resubscription anyway
		}
	}

	// Resubscribe
	maxRetries := 3
	var newHeadsCh <-chan protocol.BlockHeader
	for attempt := 1; attempt <= maxRetries; attempt++ {
		newHeadsCh, err = r.sourceReader.SubscribeNewHeads(ctx)
		if err == nil {
			r.lggr.Infow("Successfully resubscribed after failure",
				"chainSelector", r.config.ChainSelector,
				"attempt", attempt)
			return newHeadsCh, nil
		}

		r.lggr.Warnw("Resubscription attempt failed",
			"chainSelector", r.config.ChainSelector,
			"attempt", attempt,
			"maxRetries", maxRetries,
			"error", err)

		if attempt < maxRetries {
			// Exponential backoff
			backoff := time.Duration(1<<(attempt-1)) * time.Second
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
				// Continue to next attempt
			}
		}
	}

	return nil, fmt.Errorf("failed to resubscribe after %d attempts: %w", maxRetries, err)
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
// - Blocks until monitoring goroutine exits
func (r *ReorgDetectorService) Close() error {
	r.lggr.Infow("Closing reorg detector service", "chainSelector", r.config.ChainSelector)

	if r.cancel != nil {
		r.cancel()
	}

	// Wait for monitoring goroutine to finish
	<-r.doneCh

	// Close status channel
	close(r.statusCh)

	r.lggr.Infow("Reorg detector service closed", "chainSelector", r.config.ChainSelector)
	return nil
}
