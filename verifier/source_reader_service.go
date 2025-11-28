package verifier

import (
	"context"
	"fmt"
	"math/big"
	"runtime/debug"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/gobindings/generated/latest/onramp"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/batcher"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/services"
)

const (
	// ChainStatusBufferBlocks is the number of blocks to lag behind finalized
	// to ensure downstream processing is complete.
	ChainStatusBufferBlocks = 20

	// ChainStatusInterval is how often to write statuses.
	ChainStatusInterval = 300 * time.Second

	// StartupLookbackHours when no chain status exists.
	StartupLookbackHours = 8

	// ChainStatusRetryAttempts on startup.
	ChainStatusRetryAttempts = 5
)

// SourceReaderService wraps a SourceReader and converts MessageSentEvents to VerificationTasks.
type SourceReaderService struct {
	sync   services.StateMachine
	stopCh services.StopChan
	wg     sync.WaitGroup

	logger               logger.Logger
	sourceReader         chainaccess.SourceReader
	verificationTaskCh   chan batcher.BatchResult[VerificationTask]
	ccipMessageSentTopic string
	pollInterval         time.Duration
	chainSelector        protocol.ChainSelector
	filter               chainaccess.MessageFilter

	// State that requires synchronization
	mu                 sync.RWMutex
	lastProcessedBlock *big.Int
	// Reset coordination using optimistic locking pattern.
	// This version counter is incremented each time ResetToBlock() is called.
	// The processEventCycle() captures the version at the start of its cycle,
	// and checks it again before updating lastProcessedBlock. If the version
	// changed (indicating a reset occurred during the cycle's RPC calls),
	// the cycle skips its update to avoid overwriting the reset value.
	// This allows us to protect lastProcessedBlock without holding locks across I/O.
	resetVersion uint64

	// ChainStatus management
	chainStatusManager   protocol.ChainStatusManager
	lastChainStatusTime  time.Time
	lastChainStatusBlock *big.Int
}

// SourceReaderServiceOption is a functional option for SourceReaderService.
type SourceReaderServiceOption func(*SourceReaderService)

// NewSourceReaderService creates a new blockchain-based source reader.
func NewSourceReaderService(
	sourceReader chainaccess.SourceReader,
	chainSelector protocol.ChainSelector,
	chainStatusManager protocol.ChainStatusManager,
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
		chainStatusManager:   chainStatusManager,
		// TODO: Pass real filters via constructor. Empty chainaccess.CompositeMessageFilter means allow all
		filter: chainaccess.NewCompositeMessageFilter(),
	}

	// Apply options
	for _, opt := range opts {
		opt(s)
	}

	return s
}

// Start begins reading messages and pushing them to the messages channel.
func (r *SourceReaderService) Start(ctx context.Context) error {
	return r.sync.StartOnce("SourceReaderService", func() error {
		r.logger.Infow("Starting SourceReaderService",
			"chainSelector", r.chainSelector,
			"topic", r.ccipMessageSentTopic)

		// Test connectivity before starting
		if err := r.testConnectivity(ctx); err != nil {
			r.logger.Errorw("Connectivity test failed", "error", err)
			return err
		}

		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			r.eventMonitoringLoop()
		}()

		r.logger.Infow("SourceReaderService started successfully")
		return nil
	})
}

// Stop stops the reader and closes the messages channel.
func (r *SourceReaderService) Stop() error {
	return r.sync.StopOnce("SourceReaderService", func() error {
		r.logger.Infow("Stopping SourceReaderService")
		close(r.stopCh)

		// Wait for goroutine WITHOUT holding lock to avoid deadlock
		// (event loop needs to acquire lock to finish its cycle)
		r.wg.Wait()

		// Re-acquire lock to update state
		close(r.verificationTaskCh)

		r.logger.Infow("SourceReaderService stopped successfully")
		return nil
	})
}

// VerificationTaskChannel returns the channel where new message events are delivered as batches.
func (r *SourceReaderService) VerificationTaskChannel() <-chan batcher.BatchResult[VerificationTask] {
	return r.verificationTaskCh
}

// HealthCheck returns the current health status of the reader.
func (r *SourceReaderService) HealthCheck(ctx context.Context) error {
	if err := r.sync.Ready(); err != nil {
		return err
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
//  2. Write chain status if resetBlock < lastChainStatusBlock (finality violation scenario)
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
// ChainStatus handling:
// For regular reorgs (non-finalized range), the common ancestor is always >= chain status,
// so no chainStatus write is needed - periodic chain status chain statuses will naturally advance.
// For finality violations, the reset block falls below the last chain status, so we must
// immediately persist the new chain status to ensure safe restart.
func (r *SourceReaderService) ResetToBlock(block uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	resetBlock := new(big.Int).SetUint64(block)

	r.logger.Infow("Resetting source reader to block",
		"chainSelector", r.chainSelector,
		"fromBlock", r.lastProcessedBlock,
		"toBlock", resetBlock,
		"lastChainStatus", r.lastChainStatusBlock,
		"resetVersion", r.resetVersion+1)

	// Increment version to signal in-flight cycles that their read is stale
	r.resetVersion++
	// Update to reset value (already holding lock from function entry)
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

	_, finalized, err := r.sourceReader.LatestAndFinalizedBlock(testCtx)
	if err != nil {
		r.logger.Warnw("Connectivity test failed", "error", err)
		return fmt.Errorf("connectivity test failed: %w", err)
	}
	if finalized == nil {
		r.logger.Warnw("Connectivity test failed: finalized block is nil")
		return fmt.Errorf("connectivity test failed: finalized block is nil")
	}

	_, err = r.sourceReader.BlockTime(testCtx, new(big.Int).SetUint64(finalized.Number))
	if err != nil {
		r.logger.Warnw("Connectivity test failed during BlockTime call", "error", err)
		return fmt.Errorf("connectivity test failed during BlockTime call: %w", err)
	}

	return nil
}

// readChainStatusWithRetries tries to read chain status from aggregator with exponential backoff.
func (r *SourceReaderService) readChainStatusWithRetries(ctx context.Context, maxAttempts int) (*protocol.ChainStatusInfo, error) {
	if r.chainStatusManager == nil {
		r.logger.Debugw("No chainStatus manager available for chainStatus reading")
		return nil, nil
	}

	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		statusMap, err := r.chainStatusManager.ReadChainStatuses(ctx, []protocol.ChainSelector{r.chainSelector})
		if err == nil {
			// Extract status for this chain from the map
			chainStatus := statusMap[r.chainSelector]
			return chainStatus, nil
		}

		lastErr = err
		r.logger.Warnw("Failed to read chainStatus",
			"attempt", attempt,
			"maxAttempts", maxAttempts,
			"error", err)

		if attempt < maxAttempts {
			// Exponential backoff: 1s, 2s, 4s
			backoffDuration := time.Duration(1<<(attempt-1)) * time.Second
			r.logger.Debugw("Retrying chainStatus read after backoff", "duration", backoffDuration)

			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoffDuration):
				// Continue to next attempt
			}
		}
	}

	return nil, fmt.Errorf("failed to read chainStatus after %d attempts: %w", maxAttempts, lastErr)
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
		if avgBlockTime <= 0 {
			r.logger.Warnw("Average block time calculated as zero, using fallback")
			return r.fallbackBlockEstimate(currentBlock), nil
		}
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

	// Try to read chain status with retries
	chainStatus, err := r.readChainStatusWithRetries(ctx, ChainStatusRetryAttempts)
	if err != nil {
		r.logger.Warnw("Failed to read chainStatus after retries, falling back to lookback hours window",
			"lookbackHours", StartupLookbackHours,
			"error", err)
	}

	if chainStatus == nil {
		r.logger.Infow("No chainStatus found, calculating from lookback hours ago", "lookbackHours", StartupLookbackHours)
		return r.calculateBlockFromHoursAgo(ctx, StartupLookbackHours)
	}

	// Resume from chain status + 1
	startBlock := new(big.Int).Add(chainStatus.FinalizedBlockHeight, big.NewInt(1))
	r.logger.Infow("Resuming from chainStatus",
		"chainStatusBlock", chainStatus.FinalizedBlockHeight.String(),
		"disabled", chainStatus.Disabled,
		"startBlock", startBlock.String())

	return startBlock, nil
}

// calculateChainStatusBlock determines the safe chain status block (finalized - buffer).
// Takes lastProcessedBlock as parameter to avoid races with concurrent updates.
func (r *SourceReaderService) calculateChainStatusBlock(ctx context.Context, lastProcessed *big.Int) (*big.Int, error) {
	_, finalizedHeader, err := r.sourceReader.LatestAndFinalizedBlock(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get finalized block: %w", err)
	}
	if finalizedHeader == nil {
		return nil, fmt.Errorf("finalized block is nil")
	}
	finalized := new(big.Int).SetUint64(finalizedHeader.Number)

	chainStatusBlock := new(big.Int).Sub(finalized, big.NewInt(ChainStatusBufferBlocks))

	// Handle early chain scenario
	if chainStatusBlock.Sign() <= 0 {
		r.logger.Debugw("Too early to chainStatus",
			"finalized", finalized.String(),
			"buffer", ChainStatusBufferBlocks)
		return nil, nil
	}

	// Safety: don't chain status beyond what we've read
	if lastProcessed != nil && chainStatusBlock.Cmp(lastProcessed) > 0 {
		chainStatusBlock = new(big.Int).Set(lastProcessed)
		r.logger.Debugw("Capping chainStatus at last processed block",
			"finalized", finalized.String(),
			"lastProcessed", lastProcessed.String(),
			"chainStatus", chainStatusBlock.String())
	}

	return chainStatusBlock, nil
}

// updateChainStatus writes a chain status if conditions are met.
// Takes lastProcessedBlock as parameter to avoid races with concurrent updates.
//
// Thread-safety:
// Uses optimistic locking via resetVersion to prevent overwriting a reset chain status.
// If a reset occurs between chain status calculation and write, the stale write is skipped.
func (r *SourceReaderService) updateChainStatus(ctx context.Context, lastProcessed *big.Int) {
	// Skip if no chain status manager
	if r.chainStatusManager == nil {
		return
	}

	// Only chain status periodically
	if time.Since(r.lastChainStatusTime) < ChainStatusInterval {
		return
	}

	// Capture version before starting chain status calculation
	r.mu.RLock()
	versionBeforeCalc := r.resetVersion
	r.mu.RUnlock()

	// Calculate safe chain status block (finalized - buffer)
	// This may take time due to RPC calls
	chainStatusBlock, err := r.calculateChainStatusBlock(ctx, lastProcessed)
	if err != nil {
		r.logger.Warnw("Failed to calculate chainStatus block", "error", err)
		return
	}

	if chainStatusBlock == nil {
		// Too early to chain status (still in buffer zone from genesis)
		r.logger.Debugw("Skipping chainStatus - too early")
		return
	}

	// Acquire lock to check for staleness and perform write atomically
	r.mu.Lock()
	defer r.mu.Unlock()

	// Check if a reset occurred during our calculation
	currentVersion := r.resetVersion
	if currentVersion != versionBeforeCalc {
		r.logger.Debugw("Skipping stale chainStatus write due to concurrent reset",
			"calculatedChainStatus", chainStatusBlock.String(),
			"versionBeforeCalc", versionBeforeCalc,
			"currentVersion", currentVersion)
		return
	}

	// Don't re-chain status the same block
	if r.lastChainStatusBlock != nil &&
		chainStatusBlock.Cmp(r.lastChainStatusBlock) <= 0 {
		r.logger.Debugw("Skipping chainStatus - no progress",
			"chainStatusBlock", chainStatusBlock.String(),
			"lastChainStatused", r.lastChainStatusBlock.String())
		return
	}

	// Write chain status (fire-and-forget, just log errors)
	err = r.chainStatusManager.WriteChainStatuses(ctx, []protocol.ChainStatusInfo{
		{
			ChainSelector:        r.chainSelector,
			FinalizedBlockHeight: chainStatusBlock,
			Disabled:             false,
		},
	})
	if err != nil {
		r.logger.Errorw("Failed to write chainStatus",
			"error", err,
			"block", chainStatusBlock.String())
		// Continue processing, don't fail
	} else {
		r.logger.Infow("ChainStatus updated",
			"chainStatusBlock", chainStatusBlock.String(),
			"currentProcessed", lastProcessed.String())
		r.lastChainStatusTime = time.Now()
		r.lastChainStatusBlock = new(big.Int).Set(chainStatusBlock)
	}
}

// eventMonitoringLoop runs the continuous event monitoring.
func (r *SourceReaderService) eventMonitoringLoop() {
	ctx, cancel := r.stopCh.NewCtx()
	defer cancel()

	// Add panic recovery
	defer func() {
		if rec := recover(); rec != nil {
			r.logger.Errorw(
				"Recovered from panic in event monitoring loop",
				"panic", rec,
				"stack", string(debug.Stack()),
			)
		}
	}()

	startBlock, err := r.initializeStartBlock(ctx)
	if err != nil {
		r.logger.Errorw("Failed to initialize start block", "error", err)
		// Use fallback
		startBlock = big.NewInt(1)
	}
	r.mu.Lock()
	r.lastProcessedBlock = startBlock
	r.mu.Unlock()
	r.logger.Infow("Initialized start block", "block", startBlock.String())

	ticker := time.NewTicker(r.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			r.logger.Infow("Close signal received, stopping event monitoring")
			return
		case <-ticker.C:
			r.processEventCycle(ctx)
		}
	}
}

// findHighestBlockInTasks returns the highest block number from verification tasks.
// Returns nil if tasks is empty.
func findHighestBlockInTasks(tasks []VerificationTask) *big.Int {
	if len(tasks) == 0 {
		return nil
	}
	highest := uint64(0)
	for _, task := range tasks {
		if task.BlockNumber > highest {
			highest = task.BlockNumber
		}
	}
	return new(big.Int).SetUint64(highest)
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
	startVersion := r.resetVersion
	fromBlock := r.lastProcessedBlock
	r.mu.RUnlock()

	// Get current block (potentially slow RPC call - no locks held)
	blockCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	latest, finalized, err := r.sourceReader.LatestAndFinalizedBlock(blockCtx)
	cancel()

	if err != nil {
		r.logger.Errorw("Failed to get latest block", "error", err)
		// Send batch-level error to coordinator
		r.sendBatchError(ctx, fmt.Errorf("failed to get finalized block: %w", err))
		return
	}
	if finalized == nil || latest == nil {
		r.logger.Errorw("nil block found during latest/finalized retrieval",
			"finalized=Nil", finalized == nil, "latest=Nil", latest == nil)
		r.sendBatchError(ctx, fmt.Errorf("finalized block is nil"))
		return
	}

	if latest.Number <= r.lastProcessedBlock.Uint64() {
		r.logger.Debugw("No new blocks to process",
			"lastProcessedBlock", r.lastProcessedBlock.String())
		return
	}

	// Query for logs
	logsCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	r.logger.Infow("Querying from block", "fromBlock", fromBlock.String())
	// Fetch message events from blockchain
	events, err := r.sourceReader.FetchMessageSentEvents(logsCtx, fromBlock, nil)
	if err != nil {
		r.logger.Errorw("Failed to query logs", "error", err,
			"fromBlock", fromBlock.String(),
			"toBlock", "latest")
		// Send batch-level error to coordinator
		r.sendBatchError(ctx, fmt.Errorf("failed to query logs from block %s to latest: %w",
			fromBlock.String(), err))
		return
	}

	// Convert MessageSentEvents to VerificationTasks
	now := time.Now()
	tasks := make([]VerificationTask, 0, len(events))
	for _, event := range events {
		if !r.filter.Filter(event) {
			r.logger.Debugw("Event filtered out",
				"txHash", event.TxHash,
				"blockNumber", event.BlockNumber,
				"messageID", event.MessageID,
			)
		}

		task := VerificationTask{
			Message:        event.Message,
			ReceiptBlobs:   event.Receipts,
			BlockNumber:    event.BlockNumber,
			TxHash:         event.TxHash,
			FirstSeenAt:    now,
			BlockTimestamp: event.BlockTimestamp,
		}
		tasks = append(tasks, task)
	}

	// Send batch if tasks were found
	if len(tasks) > 0 {
		// Send entire batch of tasks as BatchResult
		batch := batcher.BatchResult[VerificationTask]{
			Items: tasks,
			Error: nil,
		}

		// Send to verification channel (blocking - backpressure)
		select {
		case r.verificationTaskCh <- batch:
			r.logger.Infow("Verification task batch sent to channel",
				"batchSize", len(tasks),
				"fromBlock", fromBlock.String(),
				"toBlock", "latest")
		case <-ctx.Done():
			r.logger.Debugw("Context cancelled while sending batch")
			return
		}
	} else {
		r.logger.Debugw("No events found in range",
			"fromBlock", fromBlock.String(),
			"toBlock", "latest")
	}

	// Determine the block we've processed up to
	var processedToBlock *big.Int
	if len(tasks) > 0 {
		// Use the highest block from returned logs
		highestLogBlock := findHighestBlockInTasks(tasks)
		// We don't want to re-process the same block if it already had messages, so add 1
		processedToBlock = new(big.Int).Add(highestLogBlock, big.NewInt(1))
	} else {
		// No logs - use current position (fromBlock was captured under lock at cycle start)
		processedToBlock = new(big.Int).Set(fromBlock)
	}

	// Always advance at least to finalized (stable across all RPC nodes)
	finalizedBlock := new(big.Int).SetUint64(finalized.Number)
	if finalizedBlock.Cmp(processedToBlock) > 0 {
		processedToBlock = finalizedBlock
	}

	// Update processed block with optimistic locking check
	r.mu.Lock()
	currentVersion := r.resetVersion
	if currentVersion == startVersion {
		// No reset occurred - safe to update
		r.lastProcessedBlock = processedToBlock
	} else {
		// Reset occurred during this cycle - skip update to preserve reset value
		r.logger.Infow("Skipping lastProcessedBlock update due to concurrent reset",
			"cycleStartVersion", startVersion,
			"currentVersion", currentVersion,
			"wouldHaveSet", processedToBlock.String(),
			"preserving", r.lastProcessedBlock.String())
	}
	r.mu.Unlock()

	// Update chain status if no reset occurred
	if currentVersion == startVersion {
		r.updateChainStatus(ctx, processedToBlock)
	}

	r.logger.Debugw("Processed block range",
		"fromBlock", fromBlock.String(),
		"toBlock", "latest",
		"advancedTo", processedToBlock.String(),
		"eventsFound", len(tasks))
	if len(tasks) > 0 {
		r.logger.Debugw("Event details", "logs", tasks)
	}
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

func (r *SourceReaderService) LatestAndFinalizedBlock(ctx context.Context) (latest, finalized *protocol.BlockHeader, err error) {
	return r.sourceReader.LatestAndFinalizedBlock(ctx)
}
