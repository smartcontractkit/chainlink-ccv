package verifier

import (
	"context"
	"fmt"
	"math/big"
	"runtime/debug"
	"sync"
	"time"

	vservices "github.com/smartcontractkit/chainlink-ccv/verifier/services"

	"github.com/smartcontractkit/chainlink-ccv/common"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/batcher"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/services"
)

type SourceReaderService2 struct {
	services.StateMachine
	stopCh services.StopChan
	wg     sync.WaitGroup

	// config / deps
	logger                logger.Logger
	sourceReader          chainaccess.SourceReader
	chainSelector         protocol.ChainSelector
	curseDetector         common.CurseCheckerService
	reorgDetector         protocol.ReorgDetector
	pollInterval          time.Duration
	finalityCheckInterval time.Duration

	// exposed channel to coordinator: READY tasks
	readyTasksCh chan batcher.BatchResult[VerificationTask]

	// mutable per-chain state
	mu                 sync.RWMutex
	lastProcessedBlock *big.Int
	pendingTasks       []VerificationTask
	disabled           bool
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

// NewSourceReaderService2 Constructor: same style as SRS
func NewSourceReaderService2(
	sourceReader chainaccess.SourceReader,
	chainSelector protocol.ChainSelector,
	chainStatusManager protocol.ChainStatusManager,
	lggr logger.Logger,
	pollInterval time.Duration,
	curseDetector common.CurseCheckerService,
	finalityCheckInterval time.Duration,
) (*SourceReaderService2, error) {

	if sourceReader == nil {
		return nil, fmt.Errorf("sourceReader cannot be nil")
	}
	if chainStatusManager == nil {
		return nil, fmt.Errorf("chainStatusManager cannot be nil")
	}
	if lggr == nil {
		return nil, fmt.Errorf("logger cannot be nil")
	}
	if curseDetector == nil {
		return nil, fmt.Errorf("curseDetector cannot be nil")
	}
	if pollInterval <= 0 {
		return nil, fmt.Errorf("pollInterval must be positive")
	}
	if finalityCheckInterval <= 0 {
		return nil, fmt.Errorf("finalityCheckInterval must be positive")
	}

	reorgDetectorConfig := vservices.ReorgDetectorConfig{
		ChainSelector: chainSelector,
		PollInterval:  2 * time.Second, // TODO: make configurable
	}

	reorgDetector, err := vservices.NewReorgDetectorService(
		sourceReader,
		reorgDetectorConfig,
		logger.With(lggr, "component", "ReorgDetector", "chainID", chainSelector),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create reorg detector: %w", err)
	}

	return &SourceReaderService2{
		logger:                logger.With(lggr, "component", "SourceReaderService2", "chain", chainSelector),
		sourceReader:          sourceReader,
		chainSelector:         chainSelector,
		chainStatusManager:    chainStatusManager,
		curseDetector:         curseDetector,
		reorgDetector:         reorgDetector,
		pollInterval:          pollInterval,
		finalityCheckInterval: finalityCheckInterval,
		readyTasksCh:          make(chan batcher.BatchResult[VerificationTask]),
		stopCh:                make(chan struct{}),
	}, nil
}

func (r *SourceReaderService2) ReadyTasksChannel() <-chan batcher.BatchResult[VerificationTask] {
	return r.readyTasksCh
}

func (r *SourceReaderService2) Start(ctx context.Context) error {
	return r.StartOnce("SourceReaderService2", func() error {
		r.logger.Infow("Starting SourceReaderService2", "chainSelector", r.chainSelector)

		startBlock, err := r.initializeStartBlock(ctx)
		if err != nil {
			r.logger.Errorw("Failed to initialize start block", "error", err)
			return err
		}
		r.mu.Lock()
		r.lastProcessedBlock = startBlock
		r.mu.Unlock()
		r.logger.Infow("Initialized start block", "block", startBlock.String())

		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			r.eventMonitoringLoop()
		}()

		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			r.messageReadinessLoop(ctx)
		}()

		if r.reorgDetector != nil {
			statusCh, err := r.reorgDetector.Start(ctx)
			if err != nil {
				r.logger.Errorw("Failed to start reorg detector", "chainSelector", r.chainSelector, "error", err)
				return err
			}

			r.wg.Add(1)
			go func() {
				defer r.wg.Done()
				r.reorgLoop(ctx, statusCh)
			}()
		}

		r.logger.Infow("SourceReaderService2 started", "chainSelector", r.chainSelector)
		return nil
	})
}

func (r *SourceReaderService2) Stop() error {
	return r.StopOnce("SourceReaderService2", func() error {
		r.logger.Infow("Stopping SourceReaderService2", "chainSelector", r.chainSelector)

		close(r.stopCh)
		r.wg.Wait()
		close(r.readyTasksCh)

		r.logger.Infow("SourceReaderService2 stopped", "chainSelector", r.chainSelector)
		return nil
	})
}

// eventMonitoringLoop should:
//   - periodically query the chain via sourceReader (using pollInterval)
//   - build VerificationTask objects
//   - call s.addToPendingQueue(task) for each
//
// For now this is just a stub; you’ll transplant your current
// SourceReaderService.eventMonitoringLoop / processEventCycle logic here.
func (r *SourceReaderService2) eventMonitoringLoop() {
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

// processEventCycle processes a single cycle of event monitoring.
//
// Thread-safety:
// This method uses an optimistic locking pattern to coordinate with ResetToBlock().
// At the start, it captures both the resetVersion and lastProcessedBlock under a read lock.
// After performing potentially long-running RPC calls, it checks the version again before
// updating lastProcessedBlock. If a reset occurred during the RPC calls (version changed),
// this cycle skips its update to preserve the reset value.
func (r *SourceReaderService2) processEventCycle(ctx context.Context) {
	// Capture resetVersion and lastProcessedBlock atomically under read lock.
	// This establishes a "snapshot" that we'll validate before updating state later.
	r.mu.RLock()
	startVersion := r.resetVersion
	fromBlock := r.lastProcessedBlock
	r.mu.RUnlock()

	// Get current block (potentially slow RPC call - no locks held)
	// TODO: timeout should be less than pollInterval
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
		task := VerificationTask{
			Message:      event.Message,
			ReceiptBlobs: event.Receipts,
			BlockNumber:  event.BlockNumber,
			FirstSeenAt:  now,
		}
		r.addToPendingQueue(task)
	}

	if len(tasks) == 0 {
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

// calculateChainStatusBlock determines the safe chain status block (finalized - buffer).
// Takes lastProcessedBlock as parameter to avoid races with concurrent updates.
func (r *SourceReaderService2) calculateChainStatusBlock(ctx context.Context, lastProcessed *big.Int) (*big.Int, error) {
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
func (r *SourceReaderService2) updateChainStatus(ctx context.Context, lastProcessed *big.Int) {
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

// readChainStatusWithRetries tries to read chain status from aggregator with exponential backoff.
func (r *SourceReaderService2) readChainStatusWithRetries(ctx context.Context, maxAttempts int) (*protocol.ChainStatusInfo, error) {
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

// initializeStartBlock determines the starting block for event monitoring.
func (r *SourceReaderService2) initializeStartBlock(ctx context.Context) (*big.Int, error) {
	r.logger.Infow("Initializing start block for event monitoring")

	// Try to read chain status with retries
	chainStatuses, err := r.chainStatusManager.ReadChainStatuses(ctx, []protocol.ChainSelector{r.chainSelector})
	if err != nil {
		r.logger.Warnw("Failed to read chainStatus after retries, falling back to lookback hours window",
			"lookbackHours", StartupLookbackHours,
			"error", err)
		return nil, err
	}

	chainStatus := chainStatuses[r.chainSelector]

	if chainStatus == nil {
		r.logger.Infow("No chainStatus found, starting from block 1")
		_, finalized, err := r.sourceReader.LatestAndFinalizedBlock(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get finalized block: %w", err)
		}
		if finalized == nil {
			return nil, fmt.Errorf("finalized block is nil")
		}
		return r.fallbackBlockEstimate(finalized.Number, 500), nil
	}

	// Resume from chain status + 1
	startBlock := new(big.Int).Add(chainStatus.FinalizedBlockHeight, big.NewInt(1))
	r.logger.Infow("Resuming from chainStatus",
		"chainStatusBlock", chainStatus.FinalizedBlockHeight.String(),
		"disabled", chainStatus.Disabled,
		"startBlock", startBlock.String())

	return startBlock, nil
}

// fallbackBlockEstimate provides a conservative fallback when block time calculation fails.
func (r *SourceReaderService2) fallbackBlockEstimate(currentBlock uint64, lookbackBlocks int64) *big.Int {
	currentBlockBig := new(big.Int).SetUint64(currentBlock)
	fallBackBlock := new(big.Int).Sub(currentBlockBig, big.NewInt(lookbackBlocks))
	if fallBackBlock.Sign() < 0 {
		return big.NewInt(0)
	}

	r.logger.Infow("Using fallback block estimate",
		"currentBlock", currentBlock,
		"fallbackBlock", fallBackBlock.String())

	return fallBackBlock
}

// -----------------------------------------------------------------------------
// Pending queue + finality
// -----------------------------------------------------------------------------

func (r *SourceReaderService2) addToPendingQueue(task VerificationTask) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.disabled {
		return
	}

	if r.curseDetector != nil &&
		r.curseDetector.IsRemoteChainCursed(context.TODO(), task.Message.SourceChainSelector, task.Message.DestChainSelector) {
		r.logger.Warnw("Dropping task - lane is cursed (enqueue)",
			"chainSelector", r.chainSelector,
			"blockNumber", task.BlockNumber,
			"messageID", task.Message.MustMessageID())
		return
	}

	task.QueuedAt = time.Now()
	r.pendingTasks = append(r.pendingTasks, task)
}

func (r *SourceReaderService2) messageReadinessLoop(ctx context.Context) {
	ticker := time.NewTicker(r.finalityCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-r.stopCh:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.sendReadyMessages(ctx)
		}
	}
}

func (r *SourceReaderService2) sendReadyMessages(ctx context.Context) {
	latest, finalized, err := r.sourceReader.LatestAndFinalizedBlock(ctx)
	if err != nil {
		r.logger.Warnw("Failed to get latest/finalized block",
			"chainSelector", r.chainSelector,
			"error", err)
		return
	}
	if latest == nil || finalized == nil {
		r.logger.Warnw("Latest or finalized block is nil", "chainSelector", r.chainSelector)
		return
	}

	latestBlock := new(big.Int).SetUint64(latest.Number)
	latestFinalizedBlock := new(big.Int).SetUint64(finalized.Number)

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.disabled {
		return
	}

	ready := make([]VerificationTask, 0, len(r.pendingTasks))
	remaining := r.pendingTasks[:0]

	for _, task := range r.pendingTasks {
		// re-check curse at finality time
		if r.curseDetector != nil &&
			r.curseDetector.IsRemoteChainCursed(ctx, task.Message.SourceChainSelector, task.Message.DestChainSelector) {
			r.logger.Warnw("Dropping finalized task - lane is cursed",
				"chainSelector", r.chainSelector,
				"messageID", task.Message.MustMessageID())
			continue
		}

		ok, err := r.isMessageReadyForVerification(task, latestBlock, latestFinalizedBlock)
		if err != nil {
			r.logger.Warnw("Finality check failed; keeping task in queue",
				"chainSelector", r.chainSelector,
				"messageID", task.Message.MustMessageID(),
				"error", err)
			remaining = append(remaining, task)
			continue
		}

		if ok {
			ready = append(ready, task)
		} else {
			remaining = append(remaining, task)
		}
	}

	r.pendingTasks = remaining

	if len(ready) == 0 {
		return
	}

	r.logger.Infow("Emitting finalized messages",
		"chainSelector", r.chainSelector,
		"ready", len(ready),
		"remaining", len(remaining))

	batch := batcher.BatchResult[VerificationTask]{Items: ready}

	select {
	case r.readyTasksCh <- batch:
	case <-r.stopCh:
	}
}

func (r *SourceReaderService2) isMessageReadyForVerification(
	task VerificationTask,
	latestBlock *big.Int,
	latestFinalizedBlock *big.Int,
) (bool, error) {
	msgID, err := task.Message.MessageID()
	if err != nil {
		return false, fmt.Errorf("failed to compute message ID: %w", err)
	}

	f := task.Message.Finality
	msgBlock := new(big.Int).SetUint64(task.BlockNumber)

	if f == 0 {
		// default finality: msgBlock <= finalized
		return msgBlock.Cmp(latestFinalizedBlock) <= 0, nil
	}

	// custom finality: msgBlock + f <= latest
	required := new(big.Int).Add(msgBlock, new(big.Int).SetUint64(uint64(f)))
	r.logger.Infow("Checking custom finality",
		"messageID", msgID,
		"msgBlock", msgBlock.String(),
		"finality", f,
		"requiredBlock", required.String(),
		"latestBlock", latestBlock.String())

	return required.Cmp(latestBlock) <= 0, nil
}

// -----------------------------------------------------------------------------
// Reorg / finality violation
// -----------------------------------------------------------------------------

func (r *SourceReaderService2) reorgLoop(ctx context.Context, statusCh <-chan protocol.ChainStatus) {
	for {
		select {
		case <-r.stopCh:
			return
		case <-ctx.Done():
			return
		case status, ok := <-statusCh:
			if !ok {
				return
			}
			switch status.Type {
			case protocol.ReorgTypeNormal:
				r.handleReorg(status)
			case protocol.ReorgTypeFinalityViolation:
				r.handleFinalityViolation(ctx, status)
			default:
				r.logger.Warnw("Unexpected chain status type",
					"chainSelector", r.chainSelector,
					"type", status.Type)
			}
		}
	}
}

func (r *SourceReaderService2) handleReorg(status protocol.ChainStatus) {
	ancestor := status.ResetToBlock

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.disabled {
		return
	}

	flushed := 0
	remaining := r.pendingTasks[:0]
	for _, t := range r.pendingTasks {
		if t.BlockNumber > ancestor {
			flushed++
			continue
		}
		remaining = append(remaining, t)
	}
	r.pendingTasks = remaining

	if ancestor >= r.lastProcessedBlock.Uint64() {
		r.logger.Infow("ResetToBlock called with block >= lastProcessedBlock, no action taken",
			"block", ancestor,
			"lastProcessedBlock", r.lastProcessedBlock.Uint64())
		return
	}
	resetBlock := new(big.Int).SetUint64(ancestor)
	r.logger.Infow("Resetting source reader to block",
		"chainSelector", r.chainSelector,
		"fromBlock", r.lastProcessedBlock,
		"toBlock", resetBlock,
		"lastChainStatus", r.lastChainStatusBlock,
	)

	// Update to reset value (already holding lock from function entry)
	r.lastProcessedBlock = resetBlock
	r.resetVersion++
}

func (r *SourceReaderService2) handleFinalityViolation(ctx context.Context, status protocol.ChainStatus) {
	r.logger.Errorw("FINALITY VIOLATION - disabling chain",
		"chainSelector", r.chainSelector,
		"statusType", status.Type)

	r.mu.Lock()
	if r.disabled {
		r.mu.Unlock()
		return
	}
	flushed := len(r.pendingTasks)
	r.pendingTasks = nil
	r.disabled = true
	r.mu.Unlock()

	r.logger.Errorw("Flushed all pending tasks due to finality violation",
		"chainSelector", r.chainSelector,
		"flushed", flushed)

	// best-effort disable in DB
	if r.chainStatusManager != nil {
		_ = r.chainStatusManager.WriteChainStatuses(ctx, []protocol.ChainStatusInfo{
			{
				ChainSelector:        r.chainSelector,
				FinalizedBlockHeight: big.NewInt(0),
				Disabled:             true,
			},
		})
	}
}

// sendBatchError sends a batch-level error to the coordinator.
func (r *SourceReaderService2) sendBatchError(ctx context.Context, err error) {
	batch := batcher.BatchResult[VerificationTask]{
		Items: nil,
		Error: err,
	}

	select {
	case r.readyTasksCh <- batch:
		r.logger.Debugw("Batch error sent to coordinator", "error", err)
	case <-ctx.Done():
		r.logger.Debugw("Context cancelled while sending batch error")
	}
}
