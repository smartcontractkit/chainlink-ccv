package verifier

import (
	"context"
	"fmt"
	"math/big"
	"sync"
	"sync/atomic"
	"time"

	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/onramp"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/batcher"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

const (
	// CheckpointBufferBlocks is the number of blocks to lag behind finalized
	// to ensure downstream processing is complete.
	CheckpointBufferBlocks = 20

	// CheckpointInterval is how often to write checkpoints.
	CheckpointInterval = 300 * time.Second

	// StartupLookbackHours when no checkpoint exists.
	StartupLookbackHours = 8

	// CheckpointRetryAttempts on startup.
	CheckpointRetryAttempts = 5
)

// SourceReaderService implements SourceReader for reading CCIPMessageSent events from blockchain.
type SourceReaderService struct {
	sourceReader         SourceReader
	logger               logger.Logger
	lastProcessedBlock   *big.Int
	verificationTaskCh   chan batcher.BatchResult[VerificationTask]
	stopCh               chan struct{}
	ccipMessageSentTopic string
	wg                   sync.WaitGroup
	pollInterval         time.Duration
	chainSelector        protocol.ChainSelector
	mu                   sync.RWMutex
	isRunning            bool

	// Reset coordination using optimistic locking pattern.
	// This version counter is incremented each time ResetToBlock() is called.
	// The processEventCycle() captures the version at the start of its cycle,
	// and checks it again before updating lastProcessedBlock. If the version
	// changed (indicating a reset occurred during the cycle's RPC calls),
	// the cycle skips its update to avoid overwriting the reset value.
	// This allows us to protect lastProcessedBlock without holding locks across I/O.
	resetVersion atomic.Uint64

	// Checkpoint management
	checkpointManager     protocol.CheckpointManager
	lastCheckpointTime    time.Time
	lastCheckpointedBlock *big.Int
}

// SourceReaderServiceOption is a functional option for SourceReaderService.
type SourceReaderServiceOption func(*SourceReaderService)

// WithPollInterval sets the poll interval for the source reader service.
func WithPollInterval(interval time.Duration) SourceReaderServiceOption {
	return func(s *SourceReaderService) {
		s.pollInterval = interval
	}
}

// NewSourceReaderService creates a new blockchain-based source reader.
func NewSourceReaderService(
	sourceReader SourceReader,
	chainSelector protocol.ChainSelector,
	checkpointManager protocol.CheckpointManager,
	logger logger.Logger,
	pollInterval time.Duration,
	opts ...SourceReaderServiceOption,
) *SourceReaderService {
	s := &SourceReaderService{
		sourceReader:         sourceReader,
		logger:               logger,
		verificationTaskCh:   make(chan batcher.BatchResult[VerificationTask], 1),
		stopCh:               make(chan struct{}),
		pollInterval:         pollInterval,
		chainSelector:        chainSelector,
		ccipMessageSentTopic: onramp.OnRampCCIPMessageSent{}.Topic().Hex(),
		checkpointManager:    checkpointManager,
	}

	// Apply options
	for _, opt := range opts {
		opt(s)
	}

	return s
}

// Start begins reading messages and pushing them to the messages channel.
func (r *SourceReaderService) Start(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.isRunning {
		return nil // Already running
	}

	r.logger.Infow("🔄 Starting SourceReaderService",
		"chainSelector", r.chainSelector,
		"topic", r.ccipMessageSentTopic)

	// Test connectivity before starting
	if err := r.testConnectivity(ctx); err != nil {
		r.logger.Errorw("❌ Connectivity test failed", "error", err)
		return err
	}

	r.isRunning = true
	r.wg.Add(1)

	go r.eventMonitoringLoop(ctx)

	r.logger.Infow("✅ SourceReaderService started successfully")
	return nil
}

// Stop stops the reader and closes the messages channel.
func (r *SourceReaderService) Stop() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.isRunning {
		return nil // Already stopped
	}

	r.logger.Infow("🛑 Stopping SourceReaderService")

	close(r.stopCh)
	r.wg.Wait()
	close(r.verificationTaskCh)

	r.isRunning = false

	r.logger.Infow("✅ SourceReaderService stopped successfully")
	return nil
}

// VerificationTaskChannel returns the channel where new message events are delivered as batches.
func (r *SourceReaderService) VerificationTaskChannel() <-chan batcher.BatchResult[VerificationTask] {
	return r.verificationTaskCh
}

// HealthCheck returns the current health status of the reader.
func (r *SourceReaderService) HealthCheck(ctx context.Context) error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if !r.isRunning {
		return nil // Not running is OK for health check
	}

	// Test basic connectivity
	return r.testConnectivity(ctx)
}

// ResetToBlock synchronously resets the reader to the specified block.
//
// Thread-safety:
// This method uses an optimistic locking pattern via resetVersion to coordinate
// with in-flight processEventCycle() calls. The sequence is:
//  1. Acquire write lock
//  2. Write checkpoint if resetBlock < lastCheckpointedBlock (finality violation scenario)
//  3. Increment resetVersion (signals to cycles: "your read is now stale")
//  4. Update lastProcessedBlock to the reset value
//  5. Release lock
//
// Any processEventCycle() that captured the old version before step 3 will see
// the version mismatch and skip its lastProcessedBlock update, preserving the reset.
//
// The coordinator's reorgInProgress flag prevents new tasks from being queued
// into the coordinator's pending queue during the reset window.
//
// Checkpoint handling:
// For regular reorgs (non-finalized range), the common ancestor is always >= checkpoint,
// so no checkpoint write is needed - periodic checkpointing will naturally advance.
// For finality violations, the reset block falls below the last checkpoint, so we must
// immediately persist the new checkpoint to ensure safe restart.
func (r *SourceReaderService) ResetToBlock(ctx context.Context, block uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	resetBlock := new(big.Int).SetUint64(block)

	// Check if we need to write checkpoint (resetBlock < lastCheckpointedBlock)
	// This only happens during finality violations where we reset below finalized range
	needsCheckpointWrite := r.lastCheckpointedBlock != nil && resetBlock.Cmp(r.lastCheckpointedBlock) < 0

	r.logger.Infow("Resetting source reader to block",
		"chainSelector", r.chainSelector,
		"fromBlock", r.lastProcessedBlock,
		"toBlock", resetBlock,
		"lastCheckpoint", r.lastCheckpointedBlock,
		"needsCheckpointWrite", needsCheckpointWrite,
		"resetVersion", r.resetVersion.Load()+1)

	// Write checkpoint FIRST if needed (before updating in-memory state)
	// This ensures restart safety for finality violations
	if needsCheckpointWrite && r.checkpointManager != nil {
		if err := r.checkpointManager.WriteCheckpoint(ctx, r.chainSelector, resetBlock); err != nil {
			return fmt.Errorf("failed to persist reset checkpoint: %w", err)
		}
		r.logger.Infow("Reset checkpoint persisted successfully",
			"chainSelector", r.chainSelector,
			"checkpointBlock", resetBlock.String())
		r.lastCheckpointedBlock = new(big.Int).Set(resetBlock)
		r.lastCheckpointTime = time.Now()
	}

	// Increment version to signal in-flight cycles that their read is stale
	r.resetVersion.Add(1)

	// Update to reset value
	r.lastProcessedBlock = resetBlock

	return nil
}

// testConnectivity tests if we can connect to the blockchain client.
func (r *SourceReaderService) testConnectivity(ctx context.Context) error {
	if r.sourceReader == nil {
		return nil // No client configured
	}

	// Test if we can make an RPC call
	testCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	_, _, err := r.sourceReader.LatestAndFinalizedBlock(testCtx)
	if err != nil {
		r.logger.Warnw("⚠️ Connectivity test failed", "error", err)
		return fmt.Errorf("connectivity test failed: %w", err)
	}

	return nil
}

// readCheckpointWithRetries tries to read checkpoint from aggregator with exponential backoff.
func (r *SourceReaderService) readCheckpointWithRetries(ctx context.Context, maxAttempts int) (*big.Int, error) {
	if r.checkpointManager == nil {
		r.logger.Debugw("No checkpoint manager available for checkpoint reading")
		return nil, nil
	}

	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		checkpoint, err := r.checkpointManager.ReadCheckpoint(ctx, r.chainSelector)
		if err == nil {
			return checkpoint, nil
		}

		lastErr = err
		r.logger.Warnw("Failed to read checkpoint",
			"attempt", attempt,
			"maxAttempts", maxAttempts,
			"error", err)

		if attempt < maxAttempts {
			// Exponential backoff: 1s, 2s, 4s
			backoffDuration := time.Duration(1<<(attempt-1)) * time.Second
			r.logger.Debugw("Retrying checkpoint read after backoff", "duration", backoffDuration)

			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoffDuration):
				// Continue to next attempt
			}
		}
	}

	return nil, fmt.Errorf("failed to read checkpoint after %d attempts: %w", maxAttempts, lastErr)
}

// calculateBlockFromHoursAgo calculates the block number from the specified hours ago.
func (r *SourceReaderService) calculateBlockFromHoursAgo(ctx context.Context, lookbackHours uint64) (*big.Int, error) {
	latest, _, err := r.sourceReader.LatestAndFinalizedBlock(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get latest block: %w", err)
	}
	if latest == nil {
		return nil, fmt.Errorf("latest block is nil")
	}
	currentBlock := new(big.Int).SetUint64(latest.Number)

	// Try to sample recent blocks to estimate block time
	sampleSize := int64(2)
	startBlock := new(big.Int).Sub(currentBlock, big.NewInt(sampleSize))
	if startBlock.Sign() < 0 {
		startBlock = big.NewInt(0)
	}

	// Get timestamps for block time calculation

	startTime, err := r.sourceReader.BlockTime(ctx, startBlock)
	if err != nil {
		r.logger.Warnw("Failed to get start header for block time calculation, using fallback", "error", err)
		return r.fallbackBlockEstimate(currentBlock), nil
	}

	currentTime, err := r.sourceReader.BlockTime(ctx, currentBlock)
	if err != nil {
		r.logger.Warnw("Failed to get current header for block time calculation, using fallback", "error", err)
		return r.fallbackBlockEstimate(currentBlock), nil
	}

	// Calculate average block time
	blockDiff := new(big.Int).Sub(currentBlock, startBlock)
	timeDiff := currentTime - startTime

	r.logger.Infow("Block time calculation",
		"currentBlock", currentBlock.String(),
		"startBlock", startBlock.String(),
		"blockDiff", blockDiff.String(),
		"currentTime", currentTime,
		"startTime", startTime,
		"timeDiff", timeDiff)
	if blockDiff.Sign() > 0 && timeDiff > 0 {
		avgBlockTime := timeDiff / blockDiff.Uint64()
		blocksInLookback := (lookbackHours * 3600) / avgBlockTime

		lookbackBlock := new(big.Int).Sub(currentBlock, new(big.Int).SetUint64(blocksInLookback))

		if lookbackBlock.Sign() < 0 {
			r.logger.Infow("Lookback block below zero, adjusting to zero", "calculatedLookbackBlock", lookbackBlock.String())
			lookbackBlock = big.NewInt(0)
		}

		r.logger.Infow("Calculated lookback",
			"currentBlock", currentBlock.String(),
			"lookbackHours", lookbackHours,
			"avgBlockTime", avgBlockTime,
			"blocksInLookback", blocksInLookback,
			"lookbackBlock", lookbackBlock.String())

		return lookbackBlock, nil
	}

	return r.fallbackBlockEstimate(currentBlock), nil
}

// fallbackBlockEstimate provides a conservative fallback when block time calculation fails.
func (r *SourceReaderService) fallbackBlockEstimate(currentBlock *big.Int) *big.Int {
	// Conservative fallback: 100 blocks
	lookback := new(big.Int).Sub(currentBlock, big.NewInt(100))
	if lookback.Sign() < 0 {
		return big.NewInt(0)
	}

	r.logger.Infow("Using fallback block estimate",
		"currentBlock", currentBlock.String(),
		"fallbackLookback", lookback.String())

	return lookback
}

// initializeStartBlock determines the starting block for event monitoring.
func (r *SourceReaderService) initializeStartBlock(ctx context.Context) (*big.Int, error) {
	r.logger.Infow("Initializing start block for event monitoring")

	// Try to read checkpoint with retries
	checkpoint, err := r.readCheckpointWithRetries(ctx, CheckpointRetryAttempts)
	if err != nil {
		r.logger.Warnw("Failed to read checkpoint after retries, falling back to lookback hours window",
			"lookbackHours", StartupLookbackHours,
			"error", err)
	}

	if checkpoint == nil {
		r.logger.Infow("No checkpoint found, calculating from lookback hours ago", "lookbackHours", StartupLookbackHours)
		return r.calculateBlockFromHoursAgo(ctx, StartupLookbackHours)
	}

	// Resume from checkpoint + 1
	startBlock := new(big.Int).Add(checkpoint, big.NewInt(1))
	r.logger.Infow("Resuming from checkpoint",
		"checkpointBlock", checkpoint.String(),
		"startBlock", startBlock.String())

	return startBlock, nil
}

// calculateCheckpointBlock determines the safe checkpoint block (finalized - buffer).
// Takes lastProcessedBlock as parameter to avoid races with concurrent updates.
func (r *SourceReaderService) calculateCheckpointBlock(ctx context.Context, lastProcessed *big.Int) (*big.Int, error) {
	_, finalizedHeader, err := r.sourceReader.LatestAndFinalizedBlock(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get finalized block: %w", err)
	}
	if finalizedHeader == nil {
		return nil, fmt.Errorf("finalized block is nil")
	}
	finalized := new(big.Int).SetUint64(finalizedHeader.Number)

	checkpointBlock := new(big.Int).Sub(finalized, big.NewInt(CheckpointBufferBlocks))

	// Handle early chain scenario
	if checkpointBlock.Sign() <= 0 {
		r.logger.Debugw("Too early to checkpoint",
			"finalized", finalized.String(),
			"buffer", CheckpointBufferBlocks)
		return nil, nil
	}

	// Safety: don't checkpoint beyond what we've read
	if lastProcessed != nil && checkpointBlock.Cmp(lastProcessed) > 0 {
		checkpointBlock = new(big.Int).Set(lastProcessed)
		r.logger.Debugw("Capping checkpoint at last processed block",
			"finalized", finalized.String(),
			"lastProcessed", lastProcessed.String(),
			"checkpoint", checkpointBlock.String())
	}

	return checkpointBlock, nil
}

// updateCheckpoint writes a checkpoint if conditions are met.
// Takes lastProcessedBlock as parameter to avoid races with concurrent updates.
//
// Thread-safety:
// Uses optimistic locking via resetVersion to prevent overwriting a reset checkpoint.
// If a reset occurs between checkpoint calculation and write, the stale write is skipped.
func (r *SourceReaderService) updateCheckpoint(ctx context.Context, lastProcessed *big.Int) {
	// Skip if no checkpoint manager
	if r.checkpointManager == nil {
		return
	}

	// Only checkpoint periodically
	if time.Since(r.lastCheckpointTime) < CheckpointInterval {
		return
	}

	// Capture version before starting checkpoint calculation
	versionBeforeCalc := r.resetVersion.Load()

	// Calculate safe checkpoint block (finalized - buffer)
	// This may take time due to RPC calls
	checkpointBlock, err := r.calculateCheckpointBlock(ctx, lastProcessed)
	if err != nil {
		r.logger.Warnw("Failed to calculate checkpoint block", "error", err)
		return
	}

	if checkpointBlock == nil {
		// Too early to checkpoint (still in buffer zone from genesis)
		r.logger.Debugw("Skipping checkpoint - too early")
		return
	}

	// Acquire lock to check for staleness and perform write atomically
	r.mu.Lock()
	defer r.mu.Unlock()

	// Check if a reset occurred during our calculation
	currentVersion := r.resetVersion.Load()
	if currentVersion != versionBeforeCalc {
		r.logger.Debugw("Skipping stale checkpoint write due to concurrent reset",
			"calculatedCheckpoint", checkpointBlock.String(),
			"versionBeforeCalc", versionBeforeCalc,
			"currentVersion", currentVersion)
		return
	}

	// Don't re-checkpoint the same block
	if r.lastCheckpointedBlock != nil &&
		checkpointBlock.Cmp(r.lastCheckpointedBlock) <= 0 {
		r.logger.Debugw("Skipping checkpoint - no progress",
			"checkpointBlock", checkpointBlock.String(),
			"lastCheckpointed", r.lastCheckpointedBlock.String())
		return
	}

	// Write checkpoint (fire-and-forget, just log errors)
	err = r.checkpointManager.WriteCheckpoint(ctx, r.chainSelector, checkpointBlock)
	if err != nil {
		r.logger.Errorw("Failed to write checkpoint",
			"error", err,
			"block", checkpointBlock.String())
		// Continue processing, don't fail
	} else {
		r.logger.Infow("Checkpoint updated",
			"checkpointBlock", checkpointBlock.String(),
			"currentProcessed", lastProcessed.String())
		r.lastCheckpointTime = time.Now()
		r.lastCheckpointedBlock = new(big.Int).Set(checkpointBlock)
	}
}

// eventMonitoringLoop runs the continuous event monitoring.
func (r *SourceReaderService) eventMonitoringLoop(ctx context.Context) {
	defer r.wg.Done()

	// Add panic recovery
	defer func() {
		if rec := recover(); rec != nil {
			r.logger.Errorw("❌ Recovered from panic in event monitoring loop", "panic", rec)
		}
	}()

	// Initialize start block on first run
	if r.lastProcessedBlock == nil {
		startBlock, err := r.initializeStartBlock(ctx)
		if err != nil {
			r.logger.Errorw("Failed to initialize start block", "error", err)
			// Use fallback
			startBlock = big.NewInt(1)
		}
		r.lastProcessedBlock = startBlock
		r.logger.Infow("Initialized start block", "block", startBlock.String())
	}

	ticker := time.NewTicker(r.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			r.logger.Infow("🛑 Context cancelled, stopping event monitoring")
			return

		case <-r.stopCh:
			r.logger.Infow("🛑 Close signal received, stopping event monitoring")
			return

		case <-ticker.C:
			r.processEventCycle(ctx)
		}
	}
}

// processEventCycle processes a single cycle of event monitoring.
//
// Thread-safety:
// This method uses an optimistic locking pattern to coordinate with ResetToBlock().
// At the start, it captures both the resetVersion and lastProcessedBlock under a read lock.
// After performing potentially long-running RPC calls, it checks the version again before
// updating lastProcessedBlock. If a reset occurred during the RPC calls (version changed),
// this cycle skips its update to preserve the reset value.
func (r *SourceReaderService) processEventCycle(ctx context.Context) {
	// Capture resetVersion and lastProcessedBlock atomically under read lock.
	// This establishes a "snapshot" that we'll validate before updating state later.
	r.mu.RLock()
	startVersion := r.resetVersion.Load()
	fromBlock := new(big.Int).Add(r.lastProcessedBlock, big.NewInt(1))
	r.mu.RUnlock()

	// Get current block (potentially slow RPC call - no locks held)
	blockCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	latest, _, err := r.sourceReader.LatestAndFinalizedBlock(blockCtx)
	cancel()

	if err != nil {
		r.logger.Errorw("⚠️ Failed to get latest block", "error", err)
		// Send batch-level error to coordinator
		r.sendBatchError(ctx, fmt.Errorf("failed to get latest block: %w", err))
		return
	}
	if latest == nil {
		r.logger.Errorw("⚠️ Latest block is nil")
		r.sendBatchError(ctx, fmt.Errorf("latest block is nil"))
		return
	}

	currentBlock := new(big.Int).SetUint64(latest.Number)

	// Only query if there are new blocks
	if fromBlock.Cmp(currentBlock) > 0 {
		r.logger.Debugw("🔍 No new blocks to process", "fromBlock", fromBlock.String(),
			"currentBlock", currentBlock.String())
		return
	}

	// Query for logs
	logsCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	tasks, err := r.sourceReader.VerificationTasks(logsCtx, fromBlock, currentBlock)
	if err != nil {
		r.logger.Errorw("⚠️ Failed to query logs", "error", err,
			"fromBlock", fromBlock.String(),
			"toBlock", currentBlock.String())
		// Send batch-level error to coordinator
		r.sendBatchError(ctx, fmt.Errorf("failed to query logs from block %s to %s: %w",
			fromBlock.String(), currentBlock.String(), err))
		return
	}

	// Skip sending if no tasks were found
	if len(tasks) == 0 {
		r.logger.Debugw("🔍 No events found in range",
			"fromBlock", fromBlock.String(),
			"toBlock", currentBlock.String())
		return
	}

	// Send entire batch of tasks as BatchResult
	batch := batcher.BatchResult[VerificationTask]{
		Items: tasks,
		Error: nil,
	}

	// Send to verification channel (blocking - backpressure)
	select {
	case r.verificationTaskCh <- batch:
		r.logger.Infow("✅ Verification task batch sent to channel",
			"batchSize", len(tasks),
			"fromBlock", fromBlock.String(),
			"toBlock", currentBlock.String())
	case <-ctx.Done():
		r.logger.Debugw("Context cancelled while sending batch")
		return
	}

	// Update processed block - but only if no reset occurred during our RPC calls.
	// We use optimistic locking: check if resetVersion changed since we captured it.
	// If it changed, a reset happened during this cycle's work, so we skip the update
	// to preserve the reset value.
	r.mu.Lock()
	currentVersion := r.resetVersion.Load()
	if currentVersion == startVersion {
		// No reset occurred - safe to update
		r.lastProcessedBlock = new(big.Int).Set(currentBlock)
	} else {
		// Reset occurred during this cycle - skip update to preserve reset value
		r.logger.Infow("Skipping lastProcessedBlock update due to concurrent reset",
			"cycleStartVersion", startVersion,
			"currentVersion", currentVersion,
			"wouldHaveSet", currentBlock.String(),
			"preserving", r.lastProcessedBlock.String())
	}
	r.mu.Unlock()

	// Try to checkpoint if appropriate (only if we updated)
	if currentVersion == startVersion {
		r.updateCheckpoint(ctx, currentBlock)
	}

	r.logger.Infow("📈 Processed block range",
		"fromBlock", fromBlock.String(),
		"toBlock", currentBlock.String(),
		"eventsFound", len(tasks))
	r.logger.Debugw("Event details", "logs", tasks)
}

// sendBatchError sends a batch-level error to the coordinator.
func (r *SourceReaderService) sendBatchError(ctx context.Context, err error) {
	batch := batcher.BatchResult[VerificationTask]{
		Items: nil,
		Error: err,
	}

	select {
	case r.verificationTaskCh <- batch:
		r.logger.Debugw("Batch error sent to coordinator", "error", err)
	case <-ctx.Done():
		r.logger.Debugw("Context cancelled while sending batch error")
	}
}

func (r *SourceReaderService) GetSourceReader() SourceReader {
	return r.sourceReader
}
