package sourcereader

import (
	"context"
	"fmt"
	"math/big"
	"runtime/debug"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/common"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/jobqueue"
	verifier "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vtypes"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/services"
)

const (
	DefaultPollInterval  = 2100 * time.Millisecond
	DefaultPollTimeout   = 10 * time.Second
	DefaultMaxBlockRange = 1500
)

type blockRange struct {
	fromBlock *big.Int
	toBlock   *big.Int
}

// Service reads events from chain pushes ready tasks
// directly to the ccv_task_verifier_jobs job queue so that
// Processor can pick them up durably.
type Service struct {
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
	sourceCfg       verifier.SourceConfig

	// DB-backed task queue
	taskQueue jobqueue.JobQueue[verifier.VerificationTask]

	// mutable per-chain state
	mu                          sync.RWMutex
	lastProcessedFinalizedBlock atomic.Pointer[big.Int]
	pendingTasks                map[string]verifier.VerificationTask
	sentTasks                   map[string]verifier.VerificationTask
	reorgTracker                *ReorgTracker
	disabled                    atomic.Bool

	// ChainStatus management
	chainStatusManager protocol.ChainStatusManager

	filter chainaccess.MessageFilter
}

// NewService creates a DB-backed Service that publishes
// ready tasks directly to the ccv_task_verifier_jobs job queue.
func NewService(
	sourceReader chainaccess.SourceReader,
	chainSelector protocol.ChainSelector,
	chainStatusManager protocol.ChainStatusManager,
	lggr logger.Logger,
	sourceCfg verifier.SourceConfig,
	curseDetector common.CurseCheckerService,
	filter chainaccess.MessageFilter,
	metrics verifier.MetricLabeler,
	taskQueue jobqueue.JobQueue[verifier.VerificationTask],
) (*Service, error) {
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
	if taskQueue == nil {
		return nil, fmt.Errorf("taskQueue cannot be nil")
	}

	var finalityChecker protocol.FinalityViolationChecker
	var err error

	if sourceCfg.DisableFinalityChecker {
		lggr.Infow("FinalityViolationChecker is disabled by config", "chainSelector", chainSelector)
		finalityChecker = &NoOpFinalityViolationChecker{}
	} else {
		finalityChecker, err = NewFinalityViolationCheckerService(
			sourceReader,
			chainSelector,
			logger.With(lggr, "component", "FinalityChecker", "chainID", chainSelector),
			metrics,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create finality checker: %w", err)
		}
	}

	interval := sourceCfg.PollInterval
	if interval <= 0 {
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

	return &Service{
		logger:             logger.With(lggr, "component", "Service", "chain", chainSelector),
		sourceReader:       sourceReader,
		chainSelector:      chainSelector,
		chainStatusManager: chainStatusManager,
		curseDetector:      curseDetector,
		finalityChecker:    finalityChecker,
		pollInterval:       interval,
		pollTimeout:        pollTimeout,
		sourceCfg:          sourceCfg,
		maxBlockRange:      maxBlockRange,
		taskQueue:          taskQueue,
		pendingTasks:       make(map[string]verifier.VerificationTask), sentTasks: make(map[string]verifier.VerificationTask),
		reorgTracker: NewReorgTracker(logger.With(lggr, "component", "ReorgTracker"), metrics),
		stopCh:       make(chan struct{}),
		filter:       filter,
	}, nil
}

func (r *Service) Start(ctx context.Context) error {
	return r.StartOnce(r.Name(), func() error {
		r.logger.Infow("Starting Service")

		// Optional: chain SourceReader may also implement services.Service when it owns
		// long-lived subcomponents (e.g. Solana logpoller / EncodedLogCollector worker pool).
		// Pure pull readers skip this branch; no change to chainaccess.SourceReader interface.
		chainSrcReaderSvc, ok := r.sourceReader.(services.Service)
		chainSrcReaderStarted := false
		if ok {
			if err := chainSrcReaderSvc.Start(ctx); err != nil {
				return fmt.Errorf("start chain source reader service: %w", err)
			}
			chainSrcReaderStarted = true
		}

		startBlock, err := r.initializeStartBlock(ctx)
		if err != nil {
			r.logger.Errorw("Failed to initialize start block", "error", err)
			if chainSrcReaderStarted {
				if cErr := chainSrcReaderSvc.Close(); cErr != nil {
					r.logger.Warnw("close nested after init failure", "err", cErr)
				}
			}
			return err
		}
		r.lastProcessedFinalizedBlock.Store(startBlock)
		r.logger.Infow("Initialized start block", "block", startBlock.String())

		r.wg.Go(func() {
			r.eventMonitoringLoop()
		})

		r.logger.Infow("Service started")
		return nil
	})
}

func (r *Service) Close() error {
	return r.StopOnce(r.Name(), func() error {
		r.logger.Infow("Stopping Service")
		close(r.stopCh)
		r.wg.Wait()
		r.logger.Infow("Service stopped")

		if chainSrcReaderSvc, ok := r.sourceReader.(services.Service); ok {
			if err := chainSrcReaderSvc.Close(); err != nil {
				return fmt.Errorf("close chain source reader service: %w", err)
			}
		}
		return nil
	})
}

func (r *Service) Name() string {
	return fmt.Sprintf("verifier.Service[%s]", r.chainSelector)
}

func (r *Service) HealthReport() map[string]error {
	report := make(map[string]error)
	report[r.Name()] = r.Ready()
	return report
}

func (r *Service) eventMonitoringLoop() {
	ctx, cancel := r.stopCh.NewCtx()
	defer cancel()

	ticker := time.NewTicker(r.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			r.logger.Infow("Close signal received, stopping event monitoring")
			return
		case <-ticker.C:
			if !r.disabled.Load() {
				// Protect each iteration with panic recovery to keep the loop running
				func() {
					defer func() {
						if rec := recover(); rec != nil {
							r.logger.Errorw(
								"Recovered from panic in event monitoring loop iteration - continuing",
								"panic", rec,
								"stack", string(debug.Stack()),
							)
						}
					}()

					ready, latest, safe, finalized := r.readyToQuery(ctx)
					if !ready {
						return
					}
					r.processEventCycle(ctx, latest, finalized)
					r.sendReadyMessages(ctx, latest, safe, finalized)
				}()
			}
		}
	}
}

func (r *Service) readyToQuery(ctx context.Context) (bool, *protocol.BlockHeader, *protocol.BlockHeader, *protocol.BlockHeader) {
	blockCtx, cancel := context.WithTimeout(ctx, r.pollInterval)
	defer cancel()
	latest, finalized, err := r.sourceReader.LatestAndFinalizedBlock(blockCtx)
	if err != nil {
		r.logger.Errorw("Failed to get latest block", "error", err)
		return false, nil, nil, nil
	}
	if finalized == nil || latest == nil {
		r.logger.Errorw("nil block found during latest/finalized retrieval",
			"finalized=Nil", finalized == nil, "latest=Nil", latest == nil)
		return false, nil, nil, nil
	}

	safe, err := r.sourceReader.LatestSafeBlock(blockCtx)
	if err != nil {
		r.logger.Warnw("Failed to get safe block, safe-tag finality will fall back to full finality", "error", err)
		safe = nil
	}

	return true, latest, safe, finalized
}

func (r *Service) getBlockRanges(fromBlock, latest uint64) []blockRange {
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

func (r *Service) loadEvents(ctx context.Context, fromBlock *big.Int, latest *protocol.BlockHeader) ([]protocol.MessageSentEvent, *big.Int, error) {
	blockRanges := r.getBlockRanges(fromBlock.Uint64(), latest.Number)

	allEvents := make([]protocol.MessageSentEvent, 0)
	finalQueriedBlock := fromBlock
	for _, br := range blockRanges {
		events, err := r.sourceReader.FetchMessageSentEvents(ctx, br.fromBlock, br.toBlock)
		if err != nil {
			// Return all events so far to avoid losing progress
			return allEvents, finalQueriedBlock, err
		}
		allEvents = append(allEvents, events...)
		finalQueriedBlock = br.toBlock
	}
	return allEvents, finalQueriedBlock, nil
}

func (r *Service) processEventCycle(ctx context.Context, latest, finalized *protocol.BlockHeader) {
	r.logger.Infow("processEventCycle starting",
		"latestBlock", latest.Number,
		"finalizedBlock", finalized.Number)

	logsCtx, cancel := context.WithTimeout(ctx, r.pollTimeout)
	defer cancel()

	fromBlock := r.lastProcessedFinalizedBlock.Load()

	r.logger.Infow("Querying from block", "fromBlock", fromBlock.String())
	events, lastQueriedBlock, err := r.loadEvents(logsCtx, fromBlock, latest)
	if err != nil {
		r.logger.Warnw("Error when querying logs", "error", err,
			"fromBlock", fromBlock.String(),
			"toBlock", "latest")
	}

	tasks := make([]verifier.VerificationTask, 0, len(events))
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
		task := verifier.VerificationTask{
			Message:              event.Message,
			ReceiptBlobs:         event.Receipts,
			BlockNumber:          event.BlockNumber,
			MessageID:            onchainMessageID,
			TxHash:               event.TxHash,
			FinalizedBlockAtRead: finalized.Number,
		}
		tasks = append(tasks, task)
	}

	r.addToPendingQueueHandleReorg(tasks, fromBlock, lastQueriedBlock)

	if len(events) == 0 {
		r.logger.Debugw("No events found in range",
			"fromBlock", fromBlock.String(),
			"toBlock", lastQueriedBlock)
	}

	// Advance to min(lastQueriedBlock, finalized). A nil lastQueriedBlock means
	// the last chunk had no explicit upper bound (queried up to latest), so we
	// treat it as ∞ and always take finalized.
	newBlock := new(big.Int).SetUint64(finalized.Number)
	if lastQueriedBlock != nil && lastQueriedBlock.Cmp(newBlock) < 0 {
		newBlock = lastQueriedBlock
	}
	r.lastProcessedFinalizedBlock.Store(newBlock)

	r.logger.Debugw("Processed block range",
		"fromBlock", fromBlock.String(),
		"toBlock", "latest",
		"advancedTo", newBlock.String(),
		"eventsFound", len(events))
}

func (r *Service) initializeStartBlock(ctx context.Context) (*big.Int, error) {
	r.logger.Infow("Initializing start block for event monitoring")

	chainStatuses, err := r.chainStatusManager.ReadChainStatuses(ctx, []protocol.ChainSelector{r.chainSelector})
	if err != nil {
		r.logger.Warnw("Failed to read chainStatus, falling back to lookback window", "error", err)
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

	startBlock := new(big.Int).Add(chainStatus.FinalizedBlockHeight, big.NewInt(1))
	r.logger.Infow("Resuming from chainStatus",
		"chainStatusBlock", chainStatus.FinalizedBlockHeight.String(),
		"disabled", chainStatus.Disabled,
		"startBlock", startBlock.String())

	return startBlock, nil
}

func (r *Service) fallbackBlockEstimate(currentBlock uint64, lookbackBlocks int64) *big.Int {
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

func (r *Service) addToPendingQueueHandleReorg(tasks []verifier.VerificationTask, fromBlock, toBlock *big.Int) {
	tasksMap := make(map[string]verifier.VerificationTask)
	for _, task := range tasks {
		tasksMap[task.MessageID] = task
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.disabled.Load() {
		return
	}

	for msgID, existing := range r.pendingTasks {
		existingBlock := new(big.Int).SetUint64(existing.BlockNumber)
		if existingBlock.Cmp(fromBlock) >= 0 && (toBlock == nil || existingBlock.Cmp(toBlock) <= 0) {
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

	for msgID, task := range r.sentTasks {
		taskBlock := new(big.Int).SetUint64(task.BlockNumber)
		if taskBlock.Cmp(fromBlock) >= 0 && (toBlock == nil || taskBlock.Cmp(toBlock) <= 0) {
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

	for _, task := range tasks {
		if _, exists := r.pendingTasks[task.MessageID]; exists {
			continue
		}
		if _, alreadySent := r.sentTasks[task.MessageID]; alreadySent {
			r.logger.Debugw("Skipping already-sent message",
				"messageID", task.MessageID,
				"blockNumber", task.BlockNumber)
			continue
		}
		r.pendingTasks[task.MessageID] = task
		r.logger.Infow("Added message to pending queue",
			"messageID", task.MessageID,
			"blockNumber", task.BlockNumber,
			"seqNum", task.Message.SequenceNumber,
			"pendingCount", len(r.pendingTasks))
	}
}

// sendReadyMessages checks for finalized messages and publishes them directly to the task queue.
func (r *Service) sendReadyMessages(ctx context.Context, latest, safe, finalized *protocol.BlockHeader) {
	stringSafeBlock := "unavailable"
	if safe != nil {
		stringSafeBlock = strconv.FormatUint(safe.Number, 10)
	}

	r.logger.Infow("Checking for ready messages to send",
		"latestBlock", latest.Number,
		"safeBlock", stringSafeBlock,
		"finalizedBlock", finalized.Number)

	if err := r.finalityChecker.UpdateFinalized(ctx, finalized.Number); err != nil {
		r.logger.Errorw("Failed to update finality checker",
			"finalizedBlock", finalized.Number,
			"error", err)
		if r.finalityChecker.IsFinalityViolated() {
			r.handleFinalityViolation(ctx)
			return
		}
		return
	}

	if r.finalityChecker.IsFinalityViolated() {
		r.logger.Errorw("Finality violation detected", "finalizedBlock", finalized.Number)
		r.handleFinalityViolation(ctx)
		return
	}

	latestBlock := new(big.Int).SetUint64(latest.Number)
	latestFinalizedBlock := new(big.Int).SetUint64(finalized.Number)

	var latestSafeBlock *big.Int
	if safe != nil {
		latestSafeBlock = new(big.Int).SetUint64(safe.Number)
	}

	// advanceCheckpointTo captures the block value that should be checkpointed after releasing
	// the mutex. Zero means no checkpoint should be written this cycle.
	advanceCheckpointTo := func() uint64 {
		r.mu.Lock()
		defer r.mu.Unlock()
		hasCurseUnknown := false

		if r.disabled.Load() {
			return 0
		}

		for msgID, task := range r.sentTasks {
			taskBlock := new(big.Int).SetUint64(task.BlockNumber)
			if taskBlock.Cmp(latestFinalizedBlock) < 0 {
				delete(r.sentTasks, msgID)
			}
		}

		ready := make([]verifier.VerificationTask, 0, len(r.pendingTasks))
		toBeDeleted := make([]string, 0)

		for msgID, task := range r.pendingTasks {
			cursed, curseErr := r.curseDetector.IsRemoteChainCursed(ctx, task.Message.SourceChainSelector, task.Message.DestChainSelector)
			if cursed {
				if curseErr != nil {
					r.logger.Warnw("Blocking lane - curse state unknown",
						"messageID", msgID,
						"sourceChain", task.Message.SourceChainSelector,
						"destChain", task.Message.DestChainSelector,
						"error", curseErr)
					hasCurseUnknown = true
					// In this particular case we can't make a decision, so we'll just skip the task
					// Curse err should be transient so the next poll is likely to have the information
					continue
				}
				r.logger.Warnw("Dropping task - lane is cursed",
					"messageID", msgID,
					"sourceChain", task.Message.SourceChainSelector,
					"destChain", task.Message.DestChainSelector)
				toBeDeleted = append(toBeDeleted, msgID)
				continue
			}

			if r.isMessageReadyForVerification(task, latestBlock, latestSafeBlock, latestFinalizedBlock) {
				// Set the timestamp when message became ready for verification
				// This is the finalized block timestamp which represents when the message met finality criteria
				task.ReadyForVerificationAt = latest.Timestamp
				ready = append(ready, task)
			}
		}

		// Delete cursed tasks immediately (these are being dropped, not queued)
		for _, msgID := range toBeDeleted {
			delete(r.pendingTasks, msgID)
		}

		// Use lastProcessedFinalizedBlock as the safe checkpoint: it tracks how far SRS has
		// successfully scanned from chain (may be less than finalized if there were fetch errors).
		// Fall back to latestFinalizedBlock if not yet initialized (e.g. in unit tests that call
		// sendReadyMessages directly without starting the service first).
		safeCheckpoint := latestFinalizedBlock.Uint64()
		if lp := r.lastProcessedFinalizedBlock.Load(); lp != nil {
			safeCheckpoint = lp.Uint64()
		}

		if hasCurseUnknown {
			// When curse state is unknown we need to keep the checkpoint unchanged to avoid skipping messages
			r.logger.Warnw("Curse state unknown, keeping checkpoint unchanged to avoid skipped messages")
			safeCheckpoint = 0
		}

		if len(ready) == 0 {
			// No messages to publish this cycle; we can still advance the checkpoint because
			// all finalized messages have already been queued in previous cycles or dropped.
			return safeCheckpoint
		}

		r.logger.Infow("Publishing ready tasks to job queue",
			"ready", len(ready),
			"pending", len(r.pendingTasks),
			"sentTasks", len(r.sentTasks))

		// Set PushedToVerificationQueueAt timestamp when pushing to task verifier queue for queue latency tracking
		publishTime := time.Now()
		for i := range ready {
			ready[i].PushedToVerificationQueueAt = publishTime
		}

		// Publish directly to the DB-backed task queue instead of the batcher
		// Only update in-memory state AFTER successful DB write to prevent data loss.
		// If Publish fails due to transient DB issues, tasks remain in pendingTasks and will be
		// retried on the next cycle. This ensures no messages are lost if the DB goes offline.
		if err := r.taskQueue.Publish(ctx, ready...); err != nil {
			r.logger.Errorw("Failed to publish tasks to job queue - tasks will remain in pending queue for retry",
				"error", err,
				"count", len(ready))
			return 0 // Do not advance checkpoint on publish failure
		}

		// Success - now it's safe to update in-memory state
		for _, task := range ready {
			msgID := task.MessageID
			r.sentTasks[msgID] = task
			delete(r.pendingTasks, msgID)
			r.reorgTracker.Remove(task.Message.DestChainSelector, task.Message.SequenceNumber)
		}

		r.logger.Infow("Successfully published and tracked tasks",
			"published", len(ready),
			"remainingPending", len(r.pendingTasks),
			"totalSent", len(r.sentTasks))

		return safeCheckpoint
	}()

	if advanceCheckpointTo > 0 {
		r.writeCheckpoint(ctx, advanceCheckpointTo)
	}
}

// writeCheckpoint persists the finalized block checkpoint for this chain.
// It is called outside any mutex so the DB write does not block in-memory state operations.
func (r *Service) writeCheckpoint(ctx context.Context, finalizedBlock uint64) {
	checkpoint := new(big.Int).SetUint64(finalizedBlock)
	if err := r.chainStatusManager.WriteChainStatuses(ctx, []protocol.ChainStatusInfo{{
		ChainSelector:        r.chainSelector,
		FinalizedBlockHeight: checkpoint,
	}}); err != nil {
		r.logger.Errorw("Failed to write checkpoint", "error", err, "finalizedBlock", finalizedBlock)
	} else {
		r.logger.Infow("Checkpoint advanced", "finalizedBlock", finalizedBlock)
	}
}

// isMessageReadyForVerification decides whether a message has met its requested finality.
// Reorg-tracked messages always require full finality regardless of the requested mode;
// all other finality semantics are delegated to protocol.Finality.IsMessageReady.
func (r *Service) isMessageReadyForVerification(
	task verifier.VerificationTask,
	latestBlock *big.Int,
	latestSafeBlock *big.Int,
	latestFinalizedBlock *big.Int,
) bool {
	msgBlock := new(big.Int).SetUint64(task.BlockNumber)
	destChain := task.Message.DestChainSelector
	seqNum := task.Message.SequenceNumber

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

	ready, err := task.Message.Finality.IsMessageReady(msgBlock, latestBlock, latestSafeBlock, latestFinalizedBlock)
	if err != nil {
		r.logger.Errorw("Finality check failed due to nil block argument",
			"messageID", task.MessageID,
			"error", err,
		)
		return false
	}
	safeBlockString := "unavailable"
	if latestSafeBlock != nil {
		safeBlockString = latestSafeBlock.String()
	}
	r.logger.Infow("Finality check",
		"messageID", task.MessageID,
		"finality", task.Message.Finality,
		"messageBlock", task.BlockNumber,
		"latestBlock", latestBlock.String(),
		"safeBlock", safeBlockString,
		"finalizedBlock", latestFinalizedBlock.String(),
		"meetsRequirement", ready,
	)
	return ready
}

func (r *Service) handleFinalityViolation(ctx context.Context) {
	r.logger.Errorw("FINALITY VIOLATION - disabling chain")

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.disabled.Load() {
		return
	}
	flushed := len(r.pendingTasks)
	sentFlushed := len(r.sentTasks)
	r.pendingTasks = make(map[string]verifier.VerificationTask)
	r.sentTasks = make(map[string]verifier.VerificationTask)
	r.disabled.Store(true)

	r.logger.Errorw("Flushed all tasks due to finality violation",
		"pendingFlushed", flushed,
		"sentFlushed", sentFlushed)

	err := r.chainStatusManager.WriteChainStatuses(ctx, []protocol.ChainStatusInfo{
		{
			ChainSelector:        r.chainSelector,
			FinalizedBlockHeight: big.NewInt(0),
			Disabled:             true,
		},
	})
	if err != nil {
		r.logger.Errorw("Failed to write disabled chainStatus after finality violation", "error", err)
	}
}

var (
	_ services.Service        = (*Service)(nil)
	_ protocol.HealthReporter = (*Service)(nil)
)
