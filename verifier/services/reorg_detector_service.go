package services

import (
	"context"
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

		// Build initial tail from finalized to latest
		latest, finalized, err := r.sourceReader.LatestAndFinalizedBlock(ctx)
		if err != nil {
			return fmt.Errorf("failed to get latest and finalized blocks: %w", err)
		}
		if latest == nil || finalized == nil {
			return fmt.Errorf("received nil block headers")
		}

		blockMap, err := r.fetchBlockRange(ctx, finalized.Number, latest.Number)
		if err != nil {
			return fmt.Errorf("failed to fetch initial blocks: %w", err)
		}

		r.tailBlocks = blockMap
		r.latestFinalizedBlock = finalized.Number
		r.latestBlock = latest.Number

		r.lggr.Infow("Initial tail built",
			"latestFinalizedBlock", r.latestFinalizedBlock,
			"latestBlock", r.latestBlock,
			"tailSize", len(r.tailBlocks))

		ctx1, cancel := context.WithCancel(context.Background())
		r.cancel = cancel

		// Start polling goroutine
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			r.pollAndCheckForReorgs(ctx1)
		}()

		r.lggr.Infow("Reorg detector service started successfully")

		resultCh = r.statusCh
		return nil
	})
	return resultCh, err
}

// isFinalityViolated checks for finality violations and RPC consistency.
// Returns true if a finality violation is detected.
func (r *ReorgDetectorService) isFinalityViolated(
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
	if r.isFinalityViolated(latest, finalized) {
		r.lggr.Errorw("FINALITY VIOLATION detected - stopping processing")
		r.sendFinalityViolation()
		return
	}

	// Quick check: if latest hasn't advanced and hash matches, nothing to do
	if latest.Number <= r.latestBlock && r.checkBlockConsistency(*latest) {
		r.lggr.Debugw("No new blocks")
		return
	}

	// Fetch blocks from finalized to latest and handle any reorgs
	r.fillMissingAndValidate(ctx, *latest, finalized)
}

// fillMissingAndValidate fetches blocks from our finalized to new latest,
// detects reorgs by comparing with our tail, and handles accordingly.
// Always fetches from finalized to guarantee LCA can be found.
func (r *ReorgDetectorService) fillMissingAndValidate(
	ctx context.Context,
	latest protocol.BlockHeader,
	finalized *protocol.BlockHeader,
) {
	// Fetch from our finalized block to new latest
	// This gives us overlap with our tail to find LCA if reorg occurred
	rawFetchedBlocks, err := r.fetchBlockRange(ctx, r.latestFinalizedBlock, latest.Number)
	if err != nil {
		r.lggr.Errorw("Failed to fetch blocks", "error", err)
		return
	}

	// Sanitize fetched blocks - extract longest valid chain
	// Handles mid-fetch reorgs gracefully
	longestValidBlocks := r.getLongestConsecutiveChain(rawFetchedBlocks, r.latestFinalizedBlock, latest.Number)
	if len(longestValidBlocks) == 0 {
		r.lggr.Errorw("No valid blocks in fetch")
		return
	}

	// Find LCA by comparing fetched blocks with our tail - in normal cases LCA == our latest block
	lcaBlockNum := r.findLCAInBlocks(longestValidBlocks)

	if lcaBlockNum == 0 {
		// No LCA found - finality violation
		r.lggr.Errorw("FINALITY VIOLATION detected - No LCA found")
		r.sendFinalityViolation()
		return
	}

	// Check if reorg occurred
	if lcaBlockNum < r.latestBlock {
		// Reorg detected - LCA is before our latest
		r.lggr.Infow("Reorg detected via LCA",
			"lcaBlock", lcaBlockNum,
			"ourLatest", r.latestBlock,
			"newLatest", latest.Number)

		// Remove blocks after LCA from our tail
		for blockNum := range r.tailBlocks {
			if blockNum > lcaBlockNum {
				delete(r.tailBlocks, blockNum)
			}
		}
		r.latestBlock = lcaBlockNum

		r.sendReorgNotification(lcaBlockNum)
		return
	}

	// Check if mid-fetch reorg occurred (fetched blocks were inconsistent)
	midFetchReorg := len(longestValidBlocks) < len(rawFetchedBlocks)
	// if lca is not earlier and midFetchReorg happened, notify as well
	if midFetchReorg {
		var lastValidBlock uint64
		// Find the last valid block in the longest valid chain
		for blockNum := range longestValidBlocks {
			if blockNum > lastValidBlock {
				lastValidBlock = blockNum
			}
		}
		r.lggr.Infow("Mid-fetch reorg detected - fetched blocks were inconsistent",
			"requestedBlocks length", len(rawFetchedBlocks),
			"validBlocks length", len(longestValidBlocks),
			"lastValidBlock", lastValidBlock)

		r.sendReorgNotification(lastValidBlock)
	}

	// Add fetched blocks after r.latestBlock to tail
	for blockNum, header := range longestValidBlocks {
		if blockNum > r.latestBlock {
			r.tailBlocks[blockNum] = header
			if blockNum > r.latestBlock {
				r.latestBlock = blockNum
			}
		}
	}

	r.latestFinalizedBlock = finalized.Number
	// Trim blocks older than finalized buffer
	r.trimOlderBlocks(finalized.Number)
}

// findLCAInBlocks finds the Last Common Ancestor by comparing fetched blocks with our tail.
// Returns the block number of the LCA, or 0 if no LCA found (finality violation).
// In normal cases the LCA will equal our latest block.
func (r *ReorgDetectorService) findLCAInBlocks(fetchedBlocks map[uint64]protocol.BlockHeader) uint64 {
	// Walk backwards from our latest to finalized to find where chains match
	for blockNum := r.latestBlock; blockNum >= r.latestFinalizedBlock; blockNum-- {
		ourBlock, ourExists := r.tailBlocks[blockNum]
		fetchedBlock, fetchedExists := fetchedBlocks[blockNum]

		if ourExists && fetchedExists && ourBlock.Hash == fetchedBlock.Hash {
			// Found matching block - this is our LCA
			r.lggr.Debugw("Found LCA",
				"lcaBlock", blockNum,
				"lcaHash", ourBlock.Hash)
			return blockNum
		}
	}

	// No LCA found in the finalized range - finality violation
	return 0
}

// trimOlderBlocks removes blocks older than finalized minus buffer from the tail.
// Keeps a dynamic buffer of finalized blocks (based on tail size) for backwards finality verification.
// Tail range: [finalized - buffer, latest]
// Called only by the polling goroutine (single-writer).
func (r *ReorgDetectorService) trimOlderBlocks(finalizedBlockNum uint64) {
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
}

// fetchBlockRange fetches block headers for a range [start, end] and returns them as a map.
func (r *ReorgDetectorService) fetchBlockRange(ctx context.Context, startBlock, endBlock uint64) (map[uint64]protocol.BlockHeader, error) {
	if startBlock > endBlock {
		return nil, fmt.Errorf("invalid range: startBlock %d > endBlock %d", startBlock, endBlock)
	}

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

// handleReorg handles a detected reorg by finding the LCA and sending appropriate notifications.
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
func (r *ReorgDetectorService) sendFinalityViolation() {
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

// getLongestConsecutiveChain extracts the longest valid chain from fetched blocks.
// Walks from startNum and stops at first inconsistency.
// Returns map of valid blocks up to the break point.
func (r *ReorgDetectorService) getLongestConsecutiveChain(
	blocks map[uint64]protocol.BlockHeader,
	startNum, endNum uint64,
) map[uint64]protocol.BlockHeader {
	validBlocks := make(map[uint64]protocol.BlockHeader)

	// Add first block if it exists
	if first, exists := blocks[startNum]; exists {
		validBlocks[startNum] = first
	} else {
		r.lggr.Warnw("First block missing in fetch", "blockNum", startNum)
		return validBlocks
	}

	// Walk forward, adding blocks while chain is valid
	for i := startNum + 1; i <= endNum; i++ {
		current, currentExists := blocks[i]

		if !currentExists {
			r.lggr.Debugw("Found longest valid chain - block missing",
				"blockNum", i,
				"lastValid", i-1)
			break
		}

		// Parent must exist (we added it in previous iteration)
		parent := validBlocks[i-1]

		if current.ParentHash != parent.Hash {
			r.lggr.Infow("Found longest valid chain - parent hash mismatch (mid-fetch reorg)",
				"blockNum", i,
				"lastValidBlock", i-1)
			break
		}

		validBlocks[i] = current
	}

	if len(validBlocks) < int(endNum-startNum+1) {
		r.lggr.Infow("mid fetch reorg - extracted longest chain",
			"requested", endNum-startNum+1,
			"valid", len(validBlocks),
			"lastValid", startNum+uint64(len(validBlocks))-1)
	}

	return validBlocks
}
