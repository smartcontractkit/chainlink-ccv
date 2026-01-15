package verifier

import (
	"context"
	"fmt"
	"math/big"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/common"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/batcher"
	vservices "github.com/smartcontractkit/chainlink-ccv/verifier/services"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/services"
)

const (
	// ChainStatusInterval is how often to write statuses.
	ChainStatusInterval  = 300 * time.Second
	DefaultPollInterval  = 2100 * time.Millisecond
	DefaultPollTimeout   = 10 * time.Second
	DefaultMaxBlockRange = 5000
)

type SourceReaderService struct {
	services.StateMachine
	stopCh services.StopChan
	wg     sync.WaitGroup

	// config / deps
	logger          logger.Logger
	sourceReader    chainaccess.SourceReader
	chainSelector   protocol.ChainSelector
	curseDetector   common.CurseCheckerService
	finalityChecker protocol.FinalityViolationChecker
	pollInterval    time.Duration
	pollTimeout     time.Duration
	maxBlockRange   uint64
	sourceCfg       SourceConfig

	// exposed channel to coordinator: READY tasks
	readyTasksBatcher *batcher.Batcher[VerificationTask]

	// mutable per-chain state
	mu                          sync.RWMutex
	lastProcessedFinalizedBlock atomic.Pointer[big.Int]
	pendingTasks                map[string]VerificationTask
	sentTasks                   map[string]VerificationTask // Track messages already sent to prevent duplicates
	reorgTracker                *ReorgTracker               // Tracks seqNums affected by reorgs
	disabled                    atomic.Bool

	// ChainStatus management
	chainStatusManager   protocol.ChainStatusManager
	lastChainStatusTime  time.Time
	lastChainStatusBlock *big.Int

	filter chainaccess.MessageFilter
}

// NewSourceReaderService Constructor: same style as SRS.
func NewSourceReaderService(
	ctx context.Context,
	sourceReader chainaccess.SourceReader,
	chainSelector protocol.ChainSelector,
	chainStatusManager protocol.ChainStatusManager,
	lggr logger.Logger,
	sourceCfg SourceConfig,
	curseDetector common.CurseCheckerService,
	filter chainaccess.MessageFilter,
	metrics MetricLabeler,
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
	if metrics == nil {
		return nil, fmt.Errorf("metrics cannot be nil")
	}
	finalityChecker, err := vservices.NewFinalityViolationCheckerService(
		sourceReader,
		chainSelector,
		logger.With(lggr, "component", "FinalityChecker", "chainID", chainSelector),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create finality checker: %w", err)
	}

	var interval time.Duration
	interval = sourceCfg.PollInterval
	if sourceCfg.PollInterval <= 0 {
		interval = DefaultPollInterval
	}

	maxBlockRange := sourceCfg.MaxBlockRange
	if maxBlockRange <= 0 {
		maxBlockRange = DefaultMaxBlockRange
	}

	pollTimeout := sourceCfg.PollTimeout
	if pollTimeout <= 0 {
		pollTimeout = DefaultPollTimeout
	}

	batchSize, batchTimeout := readerConfigWithDefaults(lggr, sourceCfg)
	readyTaskBatcher := batcher.NewBatcher[VerificationTask](
		ctx,
		batchSize,
		batchTimeout,
		0,
	)

	return &SourceReaderService{
		logger:             logger.With(lggr, "component", "SourceReaderService", "chain", chainSelector),
		sourceReader:       sourceReader,
		chainSelector:      chainSelector,
		chainStatusManager: chainStatusManager,
		curseDetector:      curseDetector,
		finalityChecker:    finalityChecker,
		pollInterval:       interval,
		pollTimeout:        pollTimeout,
		sourceCfg:          sourceCfg,
		maxBlockRange:      maxBlockRange,
		pendingTasks:       make(map[string]VerificationTask),
		sentTasks:          make(map[string]VerificationTask),
		reorgTracker:       NewReorgTracker(logger.With(lggr, "component", "ReorgTracker"), metrics),
		stopCh:             make(chan struct{}),
		filter:             filter,
		readyTasksBatcher:  readyTaskBatcher,
	}, nil
}

func (r *SourceReaderService) RetryTasks(minDelay time.Duration, tasks ...VerificationTask) error {
	return r.readyTasksBatcher.Retry(minDelay, tasks...)
}

func (r *SourceReaderService) ReadyTasksChannel() <-chan batcher.BatchResult[VerificationTask] {
	return r.readyTasksBatcher.OutChannel()
}

func (r *SourceReaderService) Start(ctx context.Context) error {
	return r.StartOnce(r.Name(), func() error {
		r.logger.Infow("Starting SourceReaderService")

		startBlock, err := r.initializeStartBlock(ctx)
		if err != nil {
			r.logger.Errorw("Failed to initialize start block", "error", err)
			return err
		}
		r.lastProcessedFinalizedBlock.Store(startBlock)
		r.logger.Infow("Initialized start block", "block", startBlock.String())

		r.wg.Go(func() {
			r.eventMonitoringLoop()
		})

		r.logger.Infow("SourceReaderService started")
		return nil
	})
}

func (r *SourceReaderService) Close() error {
	return r.StopOnce(r.Name(), func() error {
		r.logger.Infow("Stopping SourceReaderService")
		close(r.stopCh)
		r.wg.Wait()

		// Note: We don't explicitly close the batcher here because it shares the same context
		// as the coordinator. When the coordinator cancels the context, the batcher will
		// automatically flush and close its output channel, allowing downstream consumers
		// (TaskVerifierProcessor) to complete their drain loops.

		r.logger.Infow("SourceReaderService stopped")
		return nil
	})
}

func (r *SourceReaderService) Name() string {
	return fmt.Sprintf("verifier.SourceReaderService[%s]", r.chainSelector)
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
				ready, latest, finalized := r.readyToQuery(ctx)
				if !ready {
					continue
				}
				r.processEventCycle(ctx, latest, finalized)
				r.sendReadyMessages(ctx, latest, finalized)
			}
		}
	}
}

// readyToQuery checks if there are new blocks to process.
// Returns (true, latest, finalized) if new blocks are available.
func (r *SourceReaderService) readyToQuery(ctx context.Context) (bool, *protocol.BlockHeader, *protocol.BlockHeader) {
	blockCtx, cancel := context.WithTimeout(ctx, r.pollInterval)
	latest, finalized, err := r.sourceReader.LatestAndFinalizedBlock(blockCtx)
	cancel()

	if err != nil {
		r.logger.Errorw("Failed to get latest block", "error", err)
		// Send batch-level error to coordinator
		r.sendBatchError(fmt.Errorf("failed to get finalized block: %w", err))
		return false, nil, nil
	}
	if finalized == nil || latest == nil {
		r.logger.Errorw("nil block found during latest/finalized retrieval",
			"finalized=Nil", finalized == nil, "latest=Nil", latest == nil)
		r.sendBatchError(fmt.Errorf("finalized block is nil"))
		return false, nil, nil
	}

	return true, latest, finalized
}

type blockRange struct {
	fromBlock *big.Int
	toBlock   *big.Int
}

func (r *SourceReaderService) getBlockRanges(fromBlock, latest uint64) []blockRange {
	if fromBlock >= latest {
		return []blockRange{{fromBlock: new(big.Int).SetUint64(fromBlock), toBlock: nil}}
	}

	var blockRanges []blockRange
	for fromBlock <= latest {
		toBlock := fromBlock + r.maxBlockRange
		if toBlock >= latest {
			blockRanges = append(blockRanges, blockRange{
				fromBlock: new(big.Int).SetUint64(fromBlock),
				toBlock:   nil,
			})
			break
		}
		blockRanges = append(blockRanges, blockRange{
			fromBlock: new(big.Int).SetUint64(fromBlock),
			toBlock:   new(big.Int).SetUint64(toBlock),
		})
		fromBlock = toBlock + 1
	}

	return blockRanges
}

func (r *SourceReaderService) loadEvents(ctx context.Context, fromBlock *big.Int, latest *protocol.BlockHeader) ([]protocol.MessageSentEvent, error) {
	blockRanges := r.getBlockRanges(fromBlock.Uint64(), latest.Number)

	allEvents := make([]protocol.MessageSentEvent, 0)
	for _, blockRange := range blockRanges {
		events, err := r.sourceReader.FetchMessageSentEvents(ctx, blockRange.fromBlock, blockRange.toBlock)
		if err != nil {
			return nil, err
		}
		allEvents = append(allEvents, events...)
	}
	return allEvents, nil
}

// processEventCycle processes a single cycle of event monitoring.
// It queries for new MessageSent events, converts them to VerificationTasks,
// and adds them to the pending queue, handling reorgs as needed.
func (r *SourceReaderService) processEventCycle(ctx context.Context, latest, finalized *protocol.BlockHeader) {
	r.logger.Infow("processEventCycle starting",
		"latestBlock", latest.Number,
		"finalizedBlock", finalized.Number)
	logsCtx, cancel := context.WithTimeout(ctx, r.pollTimeout)
	defer cancel()

	fromBlock := r.lastProcessedFinalizedBlock.Load()

	r.logger.Infow("Querying from block", "fromBlock", fromBlock.String())
	// Fetch message events from blockchain
	events, err := r.loadEvents(logsCtx, fromBlock, latest)
	if err != nil {
		r.logger.Errorw("Failed to query logs", "error", err,
			"fromBlock", fromBlock.String(),
			"toBlock", "latest")
		// Send batch-level error to coordinator
		r.sendBatchError(fmt.Errorf("failed to query logs from block %s to latest: %w",
			fromBlock.String(), err))
		return
	}

	// Convert MessageSentEvents to VerificationTasks
	now := time.Now()
	tasks := make([]VerificationTask, 0, len(events))
	for _, event := range events {
		if r.filter != nil && !r.filter.Filter(event) {
			r.logger.Infow("Message filtered out by filter",
				"messageID", event.MessageID.String(),
				"destChain", event.Message.DestChainSelector,
			)
			continue
		}
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
			TxHash:       event.TxHash,
			FirstSeenAt:  now,
		}
		tasks = append(tasks, task)
	}

	r.addToPendingQueueHandleReorg(tasks, fromBlock)

	if len(events) == 0 {
		r.logger.Debugw("No events found in range",
			"fromBlock", fromBlock.String(),
			"toBlock", "latest")
	}

	// Update to latest known finalized block
	newBlock := new(big.Int).SetUint64(finalized.Number)
	r.lastProcessedFinalizedBlock.Store(newBlock)

	r.updateChainStatus(ctx, newBlock)

	r.logger.Debugw("Processed block range",
		"fromBlock", fromBlock.String(),
		"toBlock", "latest",
		"advancedTo", newBlock.String(),
		"eventsFound", len(events))
}

// updateChainStatus writes a chain status every ChainStatusInterval.
func (r *SourceReaderService) updateChainStatus(ctx context.Context, latestFinalized *big.Int) {
	// Only chain status periodically
	if time.Since(r.lastChainStatusTime) < ChainStatusInterval {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Don't re-chain status the same block
	if r.lastChainStatusBlock != nil &&
		latestFinalized.Cmp(r.lastChainStatusBlock) <= 0 {
		r.logger.Debugw("Skipping chainStatus - no progress",
			"chainStatusBlock", latestFinalized.String(),
			"lastChainStatus", r.lastChainStatusBlock.String())
		return
	}

	// Write chain status (fire-and-forget, just log errors)
	err := r.chainStatusManager.WriteChainStatuses(ctx, []protocol.ChainStatusInfo{
		{
			ChainSelector:        r.chainSelector,
			FinalizedBlockHeight: latestFinalized,
		},
	})
	if err != nil {
		r.logger.Errorw("Failed to write chainStatus",
			"error", err,
		)
	} else {
		r.logger.Infow("ChainStatus updated",
			"latestFinalized", latestFinalized.String(),
		)
		r.lastChainStatusTime = time.Now()
		r.lastChainStatusBlock = new(big.Int).Set(latestFinalized)
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

	chainStatus, ok := chainStatuses[r.chainSelector]

	if !ok {
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
// fromBlock and toBlock define the queried range - only remove messages
// that are in this range but not found in the results.
func (r *SourceReaderService) addToPendingQueueHandleReorg(tasks []VerificationTask, fromBlock *big.Int) {
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
	// Only remove if the message is in the queried range but not found
	for msgID, existing := range r.pendingTasks {
		existingBlock := new(big.Int).SetUint64(existing.BlockNumber)

		// Only remove if:
		// 1. Message is in the queried range (fromBlock <= msgBlock)
		// 2. Message is not in the new results
		if existingBlock.Cmp(fromBlock) >= 0 {
			if _, exists := tasksMap[msgID]; !exists {
				r.logger.Warnw("Removing task from pending queue due to reorg",
					"messageID", msgID,
					"blockNumber", existing.BlockNumber,
					"seqNum", existing.Message.SequenceNumber,
					"destChain", existing.Message.DestChainSelector,
					"fromBlock", fromBlock.String(),
				)
				r.reorgTracker.Track(existing.Message.DestChainSelector, existing.Message.SequenceNumber)
				delete(r.pendingTasks, msgID)
			}
		}
	}

	// Also remove from sentTasks if they were reorged out (same logic)
	for msgID, task := range r.sentTasks {
		taskBlock := new(big.Int).SetUint64(task.BlockNumber)
		if taskBlock.Cmp(fromBlock) >= 0 {
			if _, exists := tasksMap[msgID]; !exists {
				r.logger.Warnw("Removing task from sentTasks due to reorg",
					"messageID", msgID,
					"seqNum", task.Message.SequenceNumber,
					"destChain", task.Message.DestChainSelector,
				)
				r.reorgTracker.Track(task.Message.DestChainSelector, task.Message.SequenceNumber)
				delete(r.sentTasks, msgID)
			}
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
				"messageID", task.MessageID,
				"blockNumber", task.BlockNumber)
			continue
		}

		task.QueuedAt = time.Now()

		r.pendingTasks[task.MessageID] = task
		r.logger.Infow("Added message to pending queue",
			"messageID", task.MessageID,
			"blockNumber", task.BlockNumber,
			"seqNum", task.Message.SequenceNumber,
			"pendingCount", len(r.pendingTasks))
	}
}

func (r *SourceReaderService) sendReadyMessages(ctx context.Context, latest, finalized *protocol.BlockHeader) {
	r.logger.Infow("Checking for ready messages to send",
		"latestBlock", latest.Number,
		"finalizedBlock", finalized.Number)

	// Update finality checker with new finalized block and check for violations
	if err := r.finalityChecker.UpdateFinalized(ctx, finalized.Number); err != nil {
		r.logger.Errorw("Failed to update finality checker",
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
		if taskBlock.Cmp(latestFinalizedBlock) < 0 {
			delete(r.sentTasks, msgID)
		}
	}

	ready := make([]VerificationTask, 0, len(r.pendingTasks))
	toBeDeleted := make([]string, 0)

	for msgID, task := range r.pendingTasks {
		// Mark cursed tasks for deletion
		if r.curseDetector.IsRemoteChainCursed(ctx, task.Message.SourceChainSelector, task.Message.DestChainSelector) {
			r.logger.Warnw("Dropping task - lane is cursed",
				"messageID", msgID,
				"sourceChain", task.Message.SourceChainSelector,
				"destChain", task.Message.DestChainSelector)
			toBeDeleted = append(toBeDeleted, msgID)
			continue
		}

		if r.isMessageReadyForVerification(task, latestBlock, latestFinalizedBlock) {
			ready = append(ready, task)
			// Mark as sent to prevent re-sending
			r.sentTasks[msgID] = task
			toBeDeleted = append(toBeDeleted, msgID)
			// If this seqNum was tracked due to reorg, remove it now that it's finalized
			r.reorgTracker.Remove(task.Message.DestChainSelector, task.Message.SequenceNumber)
		}
	}

	// Delete processed tasks from pending queue
	for _, msgID := range toBeDeleted {
		delete(r.pendingTasks, msgID)
	}

	if len(ready) == 0 {
		return
	}

	r.logger.Infow("Emitting finalized messages",
		"ready", len(ready),
		"pending", len(r.pendingTasks),
		"sentTasks", len(r.sentTasks))

	err := r.readyTasksBatcher.Add(ready...)
	if err != nil {
		r.logger.Errorw("Failed to add ready tasks to batcher", "error", err)
		return
	}
}

func (r *SourceReaderService) isMessageReadyForVerification(
	task VerificationTask,
	latestBlock *big.Int,
	latestFinalizedBlock *big.Int,
) bool {
	f := task.Message.Finality
	msgBlock := new(big.Int).SetUint64(task.BlockNumber)
	destChain := task.Message.DestChainSelector
	seqNum := task.Message.SequenceNumber

	// If this message's seqNum was part of a reorg, require full finalization
	// regardless of any custom finality setting
	if r.reorgTracker.RequiresFinalization(destChain, seqNum) {
		ready := msgBlock.Cmp(latestFinalizedBlock) <= 0
		r.logger.Infow("Reorg-affected message finality check",
			"messageID", task.MessageID,
			"seqNum", seqNum,
			"destChain", destChain,
			"messageBlock", task.BlockNumber,
			"finalizedBlock", latestFinalizedBlock.String(),
			"meetsRequirement", ready,
		)
		return ready
	}

	if f == 0 {
		// default finality: msgBlock <= finalized
		ok := msgBlock.Cmp(latestFinalizedBlock) <= 0
		r.logger.Infow("Default finality check",
			"messageID", task.MessageID,
			"messageBlock", task.BlockNumber,
			"finalizedBlock", latestFinalizedBlock.String(),
			"meetsRequirement", ok,
		)
		return ok
	}

	// custom finality: (msgBlock + f <= latest) OR (msgBlock <= finalized)
	// Cap at finalization to prevent DoS from malicious actors setting higher finality
	required := new(big.Int).Add(msgBlock, new(big.Int).SetUint64(uint64(f)))
	customFinalityMet := required.Cmp(latestBlock) <= 0
	cappedAtFinality := msgBlock.Cmp(latestFinalizedBlock) <= 0

	ready := customFinalityMet || cappedAtFinality
	r.logger.Infow("Custom finality check",
		"messageID", task.MessageID,
		"msgBlock", msgBlock.String(),
		"finality", f,
		"requiredBlock", required.String(),
		"latestBlock", latestBlock.String(),
		"customFinalityMet", customFinalityMet,
		"cappedAtFinality", cappedAtFinality,
		"ready", ready,
	)

	return ready
}

// -----------------------------------------------------------------------------
// Finality violation handling
// -----------------------------------------------------------------------------

func (r *SourceReaderService) handleFinalityViolation(ctx context.Context) {
	r.logger.Errorw("FINALITY VIOLATION - disabling chain")

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
		"pendingFlushed", flushed,
		"sentFlushed", sentFlushed)

	// client handles retries
	err := r.chainStatusManager.WriteChainStatuses(ctx, []protocol.ChainStatusInfo{
		{
			ChainSelector:        r.chainSelector,
			FinalizedBlockHeight: big.NewInt(0),
			Disabled:             true,
		},
	})
	if err != nil {
		r.logger.Errorw("Failed to write disabled chainStatus after finality violation",
			"error", err,
		)
	}
}

// sendBatchError sends a batch-level error to the coordinator.
func (r *SourceReaderService) sendBatchError(err error) {
	batch := batcher.BatchResult[VerificationTask]{
		Items: nil,
		Error: err,
	}

	if err1 := r.readyTasksBatcher.AddImmediate(batch); err1 != nil {
		r.logger.Debugw("Failed to add immediate tasks to batcher", "error", err1)
	}
}

func readerConfigWithDefaults(lggr logger.Logger, cfg SourceConfig) (int, time.Duration) {
	batchSize := cfg.BatchSize
	if batchSize <= 0 {
		batchSize = 20
		lggr.Debugw("Using default batch size", "batchSize", batchSize)
	}

	batchTimeout := cfg.BatchTimeout
	if batchTimeout <= 0 {
		batchTimeout = 500 * time.Millisecond
		lggr.Debugw("Using default batch timeout", "batchTimeout", batchTimeout)
	}

	return batchSize, batchTimeout
}
