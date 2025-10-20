package verifier

import (
	"context"
	"fmt"
	"sync"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// ReorgDetectorConfig contains configuration for the reorg detector service.
type ReorgDetectorConfig struct {
	// ChainSelector identifies the chain being monitored
	ChainSelector protocol.ChainSelector

	// FinalityDepth is the number of blocks before considering a block "final".
	// Blocks deeper than this are assumed safe from reorgs.
	// The chain tail is automatically sized to 2 * FinalityDepth to provide
	// sufficient buffer for reorg detection before finality violations.
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
// - Uses same SourceReader instance to share RPC connections.
type ReorgDetectorService struct {
	sourceReader SourceReader
	config       ReorgDetectorConfig
	lggr         logger.Logger
	statusCh     chan protocol.ChainStatus
	cancel       context.CancelFunc
	wg           sync.WaitGroup

	// Uncomment when implementing tail tracking
	// chainTail       *protocol.ChainTail
	// tailMu          sync.RWMutex
	// lastSeenBlock   uint64
	// lastSeenBlockMu sync.RWMutex
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
// - error if configuration is invalid.
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
		config.FinalityDepth = 64
	}

	return &ReorgDetectorService{
		sourceReader: sourceReader,
		config:       config,
		lggr:         lggr,
		statusCh:     make(chan protocol.ChainStatus, 1),
	}, nil
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
// - error: If initial tail cannot be fetched, subscription fails, or context is canceled
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
		"finalityDepth", r.config.FinalityDepth)

	ctx, cancel := context.WithCancel(ctx)
	r.cancel = cancel

	// TODO: Implement initialization logic
	// - Fetch latest finalized block
	// - Build initial chain tail
	// - Subscribe to new block headers

	// Start monitoring goroutine
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		r.monitorSubscription(ctx, nil)
	}()

	return r.statusCh, nil
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
// - Context cancellation: Clean shutdown.
func (r *ReorgDetectorService) monitorSubscription(ctx context.Context, headsCh <-chan protocol.BlockHeader) {
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
	r.lggr.Infow("Closing reorg detector service", "chainSelector", r.config.ChainSelector)

	if r.cancel != nil {
		r.cancel()
	}

	// Wait for monitoring goroutine to finish
	r.wg.Wait()

	// Close status channel
	close(r.statusCh)

	r.lggr.Infow("Reorg detector service closed", "chainSelector", r.config.ChainSelector)
	return nil
}
