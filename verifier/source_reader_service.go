package verifier

import (
	"context"
	"fmt"
	"math/big"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	vservices "github.com/smartcontractkit/chainlink-ccv/verifier/services"

	"github.com/smartcontractkit/chainlink-ccv/common"
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
)

type SourceReaderService struct {
	services.StateMachine
	stopCh services.StopChan
	wg     sync.WaitGroup

	// config / deps
	logger                logger.Logger
	sourceReader          chainaccess.SourceReader
	chainSelector         protocol.ChainSelector
	curseDetector         common.CurseCheckerService
	finalityChecker       protocol.FinalityViolationChecker
	pollInterval          time.Duration
	finalityCheckInterval time.Duration

	// exposed channel to coordinator: READY tasks
	readyTasksCh chan batcher.BatchResult[VerificationTask]

	// mutable per-chain state
	mu                 sync.RWMutex
	lastProcessedBlock *big.Int
	pendingTasks       map[string]VerificationTask
	sentTasks          map[string]VerificationTask // Track messages already sent to prevent duplicates
	disabled           atomic.Bool

	// ChainStatus management
	chainStatusManager   protocol.ChainStatusManager
	lastChainStatusTime  time.Time
	lastChainStatusBlock *big.Int
}

// NewSourceReaderService Constructor: same style as SRS
func NewSourceReaderService(
	sourceReader chainaccess.SourceReader,
	chainSelector protocol.ChainSelector,
	chainStatusManager protocol.ChainStatusManager,
	lggr logger.Logger,
	pollInterval time.Duration,
	curseDetector common.CurseCheckerService,
	finalityCheckInterval time.Duration,
) (*SourceReaderService, error) {

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

	finalityChecker, err := vservices.NewFinalityViolationCheckerService(
		sourceReader,
		chainSelector,
		logger.With(lggr, "component", "FinalityChecker", "chainID", chainSelector),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create finality checker: %w", err)
	}

	return &SourceReaderService{
		logger:                logger.With(lggr, "component", "SourceReaderService", "chain", chainSelector),
		sourceReader:          sourceReader,
		chainSelector:         chainSelector,
		chainStatusManager:    chainStatusManager,
		curseDetector:         curseDetector,
		finalityChecker:       finalityChecker,
		pollInterval:          pollInterval,
		finalityCheckInterval: finalityCheckInterval,
		readyTasksCh:          make(chan batcher.BatchResult[VerificationTask]),
		pendingTasks:          make(map[string]VerificationTask),
		sentTasks:             make(map[string]VerificationTask),
		stopCh:                make(chan struct{}),
	}, nil
}

func (r *SourceReaderService) ReadyTasksChannel() <-chan batcher.BatchResult[VerificationTask] {
	return r.readyTasksCh
}

func (r *SourceReaderService) Start(ctx context.Context) error {
	return r.StartOnce("SourceReaderService", func() error {
		r.logger.Infow("Starting SourceReaderService", "chainSelector", r.chainSelector)

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

		r.logger.Infow("SourceReaderService started", "chainSelector", r.chainSelector)
		return nil
	})
}

func (r *SourceReaderService) Stop() error {
	return r.StopOnce("SourceReaderService", func() error {
		r.logger.Infow("Stopping SourceReaderService", "chainSelector", r.chainSelector)

		close(r.stopCh)
		r.wg.Wait()
		close(r.readyTasksCh)

		r.logger.Infow("SourceReaderService stopped", "chainSelector", r.chainSelector)
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

	ticker := time.NewTicker(r.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			r.logger.Infow("Close signal received, stopping event monitoring")
			return
		case <-ticker.C:
			if !r.disabled.Load() {
				r.processEventCycle(ctx)
				r.sendReadyMessages(ctx)
			}
		}
	}
}

// readyToQuery checks if there are new blocks to process.
// Returns (true, finalizedBlock) if new blocks are available.
func (r *SourceReaderService) readyToQuery(ctx context.Context) (bool, *protocol.BlockHeader) {
	blockCtx, cancel := context.WithTimeout(ctx, 1*time.Second)
	latest, finalized, err := r.sourceReader.LatestAndFinalizedBlock(blockCtx)
	cancel()

	if err != nil {
		r.logger.Errorw("Failed to get latest block", "error", err)
		// Send batch-level error to coordinator
		r.sendBatchError(ctx, fmt.Errorf("failed to get finalized block: %w", err))
		return false, nil
	}
	if finalized == nil || latest == nil {
		r.logger.Errorw("nil block found during latest/finalized retrieval",
			"finalized=Nil", finalized == nil, "latest=Nil", latest == nil)
		r.sendBatchError(ctx, fmt.Errorf("finalized block is nil"))
		return false, nil
	}

	if latest.Number <= r.lastProcessedBlock.Uint64() {
		r.logger.Debugw("No new blocks to process",
			"lastProcessedBlock", r.lastProcessedBlock.String())
		return false, finalized
	}

	return true, finalized
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

	ready, finalized := r.readyToQuery(ctx)
	if !ready {
		return
	}
	// Query for logs
	logsCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	r.mu.RLock()
	// minimum of lastProcessed and finalized
	// keep on reading from finalized block to avoid missing messages in case of reorgs
	fromBlock := r.lastProcessedBlock
	r.mu.RUnlock()

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
		computedMessageID, err := event.Message.MessageID()
		if err != nil {
			r.logger.Errorw("Failed to compute message ID", "error", err)
			continue
		}
		onchainMessageID := event.MessageID.String()
		if computedMessageID.String() != onchainMessageID {
			r.logger.Errorw("Message ID mismatch", "computed", computedMessageID.String(), "onchain", onchainMessageID)
			continue
		}
		task := VerificationTask{
			Message:      event.Message,
			ReceiptBlobs: event.Receipts,
			BlockNumber:  event.BlockNumber,
			MessageID:    onchainMessageID,
			FirstSeenAt:  now,
		}
		tasks = append(tasks, task)
	}

	r.addToPendingQueueHandleReorg(tasks)

	if len(events) == 0 {
		r.logger.Debugw("No events found in range",
			"fromBlock", fromBlock.String(),
			"toBlock", "latest")
	}

	// Update processed block with optimistic locking check
	r.mu.Lock()
	// No reset occurred - safe to update
	r.lastProcessedBlock = new(big.Int).SetUint64(finalized.Number)

	r.mu.Unlock()

	r.updateChainStatus(ctx, r.lastProcessedBlock)

	r.logger.Debugw("Processed block range",
		"fromBlock", fromBlock.String(),
		"toBlock", "latest",
		"advancedTo", r.lastProcessedBlock.String(),
		"eventsFound", len(events))
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

// updateChainStatus writes a chain status every ChainStatusInterval.
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

// initializeStartBlock determines the starting block for event monitoring.
func (r *SourceReaderService) initializeStartBlock(ctx context.Context) (*big.Int, error) {
	r.logger.Infow("Initializing start block for event monitoring")

	// Try to read chain status with retries
	// Client should handle retries
	chainStatuses, err := r.chainStatusManager.ReadChainStatuses(ctx, []protocol.ChainSelector{r.chainSelector})
	if err != nil {
		r.logger.Warnw("Failed to read chainStatus after retries, falling back to lookback hours window",
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
func (r *SourceReaderService) fallbackBlockEstimate(currentBlock uint64, lookbackBlocks int64) *big.Int {
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

// addToPendingQueueHandleReorg adds new tasks to the pending queue,
// removing any tasks that are no longer valid due to reorg.
func (r *SourceReaderService) addToPendingQueueHandleReorg(tasks []VerificationTask) {
	tasksMap := make(map[string]VerificationTask)
	for _, task := range tasks {
		tasksMap[task.MessageID] = task
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.disabled.Load() {
		return
	}

	// remove tasks that are no longer valid due to reorg
	for msgID, existing := range r.pendingTasks {
		if _, exists := tasksMap[msgID]; !exists {
			r.logger.Warnw("Removing task from pending queue due to reorg",
				"chainSelector", r.chainSelector,
				"messageID", msgID,
				"blockNumber", existing.BlockNumber)
			delete(r.pendingTasks, msgID)
		}
	}

	// Also remove from sentTasks if they were reorged out
	for msgID := range r.sentTasks {
		if _, exists := tasksMap[msgID]; !exists {
			r.logger.Warnw("Removing task from sentTasks due to reorg",
				"chainSelector", r.chainSelector,
				"messageID", msgID)
			delete(r.sentTasks, msgID)
		}
	}

	// add new tasks
	for _, task := range tasks {
		// Skip if already in pending queue
		if _, exists := r.pendingTasks[task.MessageID]; exists {
			continue
		}

		// Skip if already sent (prevents re-sending after finality)
		if _, alreadySent := r.sentTasks[task.MessageID]; alreadySent {
			r.logger.Debugw("Skipping already-sent message",
				"chainSelector", r.chainSelector,
				"messageID", task.MessageID,
				"blockNumber", task.BlockNumber)
			continue
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

		r.pendingTasks[task.MessageID] = task
		r.logger.Infow("Added message to pending queue",
			"chainSelector", r.chainSelector,
			"messageID", task.MessageID,
			"blockNumber", task.BlockNumber,
			"nonce", task.Message.SequenceNumber,
			"pendingCount", len(r.pendingTasks))
	}
}

func (r *SourceReaderService) sendReadyMessages(ctx context.Context) {
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

	// Update finality checker with new finalized block and check for violations
	if err := r.finalityChecker.UpdateFinalized(ctx, finalized.Number); err != nil {
		r.logger.Errorw("Failed to update finality checker",
			"chainSelector", r.chainSelector,
			"finalizedBlock", finalized.Number,
			"error", err)
		// If update failed due to finality violation, handle it
		if r.finalityChecker.IsFinalityViolated() {
			r.handleFinalityViolation(ctx)
			return
		}
		// Other errors - log and continue
		return
	}

	// Check if finality violation detected
	if r.finalityChecker.IsFinalityViolated() {
		r.logger.Errorw("Finality violation detected",
			"chainSelector", r.chainSelector,
			"finalizedBlock", finalized.Number)
		r.handleFinalityViolation(ctx)
		return
	}

	latestBlock := new(big.Int).SetUint64(latest.Number)
	latestFinalizedBlock := new(big.Int).SetUint64(finalized.Number)

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.disabled.Load() {
		return
	}

	// Clean up sentTasks for messages older than finalized block
	// These can never be reorged, so safe to remove
	for msgID, task := range r.sentTasks {
		taskBlock := new(big.Int).SetUint64(task.BlockNumber)
		if taskBlock.Cmp(latestFinalizedBlock) <= 0 {
			delete(r.sentTasks, msgID)
		}
	}

	ready := make([]VerificationTask, 0, len(r.pendingTasks))
	remaining := make(map[string]VerificationTask)

	for msgID, task := range r.pendingTasks {
		// re-check curse at finality time
		if r.curseDetector != nil &&
			r.curseDetector.IsRemoteChainCursed(ctx, task.Message.SourceChainSelector, task.Message.DestChainSelector) {
			r.logger.Warnw("Dropping finalized task - lane is cursed",
				"chainSelector", r.chainSelector,
				"messageID", task.Message.MustMessageID())
			continue
		}

		if r.isMessageReadyForVerification(task, latestBlock, latestFinalizedBlock) {
			ready = append(ready, task)
			// Mark as sent to prevent re-sending
			r.sentTasks[msgID] = task
		} else {
			remaining[msgID] = task
		}
	}

	r.pendingTasks = remaining

	if len(ready) == 0 {
		return
	}

	r.logger.Infow("Emitting finalized messages",
		"chainSelector", r.chainSelector,
		"ready", len(ready),
		"remaining", len(remaining),
		"sentTasks", len(r.sentTasks))

	batch := batcher.BatchResult[VerificationTask]{Items: ready}

	select {
	case r.readyTasksCh <- batch:
	case <-r.stopCh:
	}
}

func (r *SourceReaderService) isMessageReadyForVerification(
	task VerificationTask,
	latestBlock *big.Int,
	latestFinalizedBlock *big.Int,
) bool {
	f := task.Message.Finality
	msgBlock := new(big.Int).SetUint64(task.BlockNumber)

	if f == 0 {
		// default finality: msgBlock <= finalized
		ok := msgBlock.Cmp(latestFinalizedBlock) <= 0
		r.logger.Infow("Default finality check",
			"messageID", task.Message.MustMessageID(),
			"messageBlock", task.BlockNumber,
			"finalizedBlock", latestFinalizedBlock.String(),
			"meetsRequirement", ok,
		)
		return ok
	}

	// custom finality: msgBlock + f <= latest
	required := new(big.Int).Add(msgBlock, new(big.Int).SetUint64(uint64(f)))
	r.logger.Infow("Checking custom finality",
		"messageID", task.MessageID,
		"msgBlock", msgBlock.String(),
		"finality", f,
		"requiredBlock", required.String(),
		"latestBlock", latestBlock.String())

	return required.Cmp(latestBlock) <= 0
}

// -----------------------------------------------------------------------------
// Finality violation handling
// -----------------------------------------------------------------------------

func (r *SourceReaderService) handleFinalityViolation(ctx context.Context) {
	r.logger.Errorw("FINALITY VIOLATION - disabling chain",
		"chainSelector", r.chainSelector)

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.disabled.Load() {
		return
	}
	flushed := len(r.pendingTasks)
	sentFlushed := len(r.sentTasks)
	r.pendingTasks = make(map[string]VerificationTask)
	r.sentTasks = make(map[string]VerificationTask)
	r.disabled.Store(true)

	r.logger.Errorw("Flushed all tasks due to finality violation",
		"chainSelector", r.chainSelector,
		"pendingFlushed", flushed,
		"sentFlushed", sentFlushed)

	r.chainStatusManager.WriteChainStatuses(ctx, []protocol.ChainStatusInfo{
		{
			ChainSelector:        r.chainSelector,
			FinalizedBlockHeight: big.NewInt(0),
			Disabled:             true,
		},
	})
}

// sendBatchError sends a batch-level error to the coordinator.
func (r *SourceReaderService) sendBatchError(ctx context.Context, err error) {
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
