package sourcereader

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"runtime/debug"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	oteltrace "go.opentelemetry.io/otel/trace"

	"github.com/smartcontractkit/chainlink-ccv/common"
	"github.com/smartcontractkit/chainlink-ccv/common/jobqueue"
	"github.com/smartcontractkit/chainlink-ccv/common/monitoring/tracing"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/recovery"
	verifier "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vtypes"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/services"
)

const (
	DefaultPollInterval  = 2100 * time.Millisecond
	DefaultPollTimeout   = 10 * time.Second
	DefaultMaxBlockRange = 100
)

// toBlock of 0 means the range is open-ended (queries up to the latest block).
type blockRange struct {
	fromBlock uint64
	toBlock   uint64
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
	verifierID      string
	monitoring      verifier.Monitoring
	sourceReader    chainaccess.SourceReader
	chainSelector   protocol.ChainSelector
	curseDetector   common.CurseCheckerService
	messageRules    common.MessageRulesChecker
	finalityChecker protocol.FinalityViolationChecker
	pollInterval    time.Duration
	pollTimeout     time.Duration
	maxBlockRange   uint64
	sourceCfg       verifier.SourceConfig

	// DB-backed task queue
	taskQueue jobqueue.JobQueue[verifier.VerificationTask]

	// scannedThrough is the highest block the last scan covered, guarded by mu. Nil means no limit.
	scannedThrough *uint64

	// mutable per-chain state
	mu                          sync.RWMutex
	lastProcessedFinalizedBlock atomic.Uint64
	startBlockInitialized       atomic.Bool // guards lastProcessedFinalizedBlock; set by the background init in Start
	pendingTasks                map[string]verifier.VerificationTask
	pendingSince                map[string]time.Time
	pendingMetricDestinations   map[protocol.ChainSelector]struct{}
	sentTasks                   map[string]verifier.VerificationTask
	reorgTracker                *ReorgTracker
	disabled                    atomic.Bool
	finalityBlocked             atomic.Bool

	// ChainStatus management
	chainStatusManager protocol.ChainStatusManager

	recovery *recoveryRuntime
	filter   chainaccess.MessageFilter
}

// NewService creates a DB-backed Service that publishes
// ready tasks directly to the ccv_task_verifier_jobs job queue.
func NewService(
	verifierID string,
	sourceReader chainaccess.SourceReader,
	chainSelector protocol.ChainSelector,
	chainStatusManager protocol.ChainStatusManager,
	lggr logger.Logger,
	sourceCfg verifier.SourceConfig,
	curseDetector common.CurseCheckerService,
	filter chainaccess.MessageFilter,
	monitoring verifier.Monitoring,
	taskQueue jobqueue.JobQueue[verifier.VerificationTask],
	messageRules common.MessageRulesChecker,
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
	if monitoring == nil {
		return nil, fmt.Errorf("monitoring cannot be nil")
	}
	if taskQueue == nil {
		return nil, fmt.Errorf("taskQueue cannot be nil")
	}
	if messageRules == nil {
		return nil, fmt.Errorf("messageRules cannot be nil")
	}
	metrics := monitoring.Metrics()

	finalityChecker, err := newFinalityChecker(
		sourceCfg,
		sourceReader,
		chainSelector,
		logger.With(lggr, "component", "FinalityChecker", "chainID", chainSelector),
		metrics,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create finality checker: %w", err)
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
		verifierID:         verifierID,
		monitoring:         monitoring,
		sourceReader:       sourceReader,
		chainSelector:      chainSelector,
		chainStatusManager: chainStatusManager,
		curseDetector:      curseDetector,
		messageRules:       messageRules,
		finalityChecker:    finalityChecker,
		pollInterval:       interval,
		pollTimeout:        pollTimeout,
		sourceCfg:          sourceCfg,
		maxBlockRange:      maxBlockRange,
		taskQueue:          taskQueue,

		pendingTasks:              make(map[string]verifier.VerificationTask),
		pendingSince:              make(map[string]time.Time),
		pendingMetricDestinations: make(map[protocol.ChainSelector]struct{}),
		sentTasks:                 make(map[string]verifier.VerificationTask),

		reorgTracker: NewReorgTracker(logger.With(lggr, "component", "ReorgTracker"), metrics),
		stopCh:       make(chan struct{}),
		filter:       filter,
	}, nil
}

func (r *Service) Start(ctx context.Context) error {
	return r.StartOnce(r.Name(), func() error {
		r.logger.Infow("Starting Service")

		r.wg.Go(func() {
			r.initializeAndMonitor()
		})

		r.logger.Infow("Service started")
		return nil
	})
}

// initializeAndMonitor retries start-block initialization until it succeeds or the
// service stops, then hands off to the event monitoring loop. Start must not do
// this inline: the DB/RPC reads can hang or fail on transient errors and must
// never block or abort process startup (Ready reports the interim state instead).
func (r *Service) initializeAndMonitor() {
	ctx, cancel := r.stopCh.NewCtx()
	defer cancel()

	for {
		attemptCtx, attemptCancel := context.WithTimeout(ctx, r.pollTimeout)
		startBlock, err := r.initializeStartBlock(attemptCtx)
		attemptCancel()
		if err == nil {
			r.lastProcessedFinalizedBlock.Store(startBlock)
			if loader, ok := r.sourceReader.(chainaccess.SourceLoader); ok {
				loader.LoadFrom(startBlock)
			}
			r.startBlockInitialized.Store(true)
			r.metrics().SetSourceReaderLastProcessedFinalizedBlock(ctx, int64(startBlock)) // #nosec G115 -- chain block heights are within int64 range
			r.logger.Infow("Initialized start block", "block", startBlock)
			break
		}
		r.logger.Errorw("Failed to initialize start block, will retry", "error", err, "retryIn", r.pollInterval)
		select {
		case <-ctx.Done():
			return
		case <-time.After(r.pollInterval):
		}
	}

	r.eventMonitoringLoop()
}

func (r *Service) Close() error {
	return r.StopOnce(r.Name(), func() error {
		r.logger.Infow("Stopping Service")
		close(r.stopCh)
		r.wg.Wait()
		if closer, ok := r.sourceReader.(io.Closer); ok {
			if err := closer.Close(); err != nil {
				r.logger.Warnw("Failed to close source reader", "error", err)
			}
		}
		r.logger.Infow("Service stopped")
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

func (r *Service) Ready() error {
	if err := r.StateMachine.Ready(); err != nil {
		return err
	}
	if !r.startBlockInitialized.Load() {
		return errors.New("start block not yet initialized")
	}
	if r.finalityBlocked.Load() {
		return errors.New("finality blocked")
	}
	return nil
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

				r.recoveryControl(ctx)
				if r.disabled.Load() {
					r.recordDisabledState(ctx)
					return
				}
				ready, latest, safe, finalized := r.readyToQuery(ctx)
				if !ready {
					return
				}
				r.recoveryHeartbeat(ctx, &latest.Number)
				if r.recovery != nil && r.recovery.rebuildingID != "" {
					if r.checkFinality(ctx, finalized) {
						r.recoverRange(ctx, latest, safe, finalized)
					}
					return
				}
				pollSucceeded := r.processEventCycle(ctx, latest, finalized)
				if pollSucceeded {
					r.metrics().SetSourceReaderLastSuccessfulPollTimestamp(ctx, time.Now().Unix())
					r.metrics().SetSourceReaderState(ctx, monitoring.SourceReaderStateRunning)
				} else {
					r.metrics().SetSourceReaderState(ctx, monitoring.SourceReaderStatePollError)
				}
				if r.sendReadyMessages(ctx, latest, safe, finalized) && r.recoveryOpsDue() {
					r.recoverRange(ctx, latest, safe, finalized)
				}
			}()
		}
	}
}

func (r *Service) readyToQuery(ctx context.Context) (bool, *protocol.BlockHeader, *protocol.BlockHeader, *protocol.BlockHeader) {
	// The head-fetch budget is the dedicated poll timeout, not the poll interval.
	blockCtx, cancel := context.WithTimeout(ctx, r.pollTimeout)
	defer cancel()
	latest, finalized, err := r.sourceReader.LatestAndFinalizedBlock(blockCtx)
	if err != nil {
		r.metrics().SetSourceReaderState(ctx, monitoring.SourceReaderStatePollError)
		r.logger.Errorw("Failed to get latest block", "error", err)
		return false, nil, nil, nil
	}
	if finalized == nil || latest == nil {
		r.metrics().SetSourceReaderState(ctx, monitoring.SourceReaderStatePollError)
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
		return []blockRange{{fromBlock: fromBlock}}
	}

	var blockRanges []blockRange
	for fromBlock <= latest {
		// Compare the remaining distance before adding: fromBlock+maxBlockRange wraps
		// below fromBlock near MaxUint64, emitting a bogus inverted range.
		if latest-fromBlock <= r.maxBlockRange {
			blockRanges = append(blockRanges, blockRange{fromBlock: fromBlock})
			break
		}
		toBlock := fromBlock + r.maxBlockRange
		blockRanges = append(blockRanges, blockRange{
			fromBlock: fromBlock,
			toBlock:   toBlock,
		})
		fromBlock = toBlock + 1
	}

	return blockRanges
}

// loadEvents fetches events in chunks. The returned block is the upper bound of the last
// completed chunk; 0 means it was open-ended (queried up to the latest block).
func (r *Service) loadEvents(ctx context.Context, fromBlock uint64, latest *protocol.BlockHeader) ([]protocol.MessageSentEvent, uint64, error) {
	blockRanges := r.getBlockRanges(fromBlock, latest.Number)

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

func (r *Service) processEventCycle(ctx context.Context, latest, finalized *protocol.BlockHeader) bool {
	r.logger.Debugw("processEventCycle starting",
		"latestBlock", latest.Number,
		"finalizedBlock", finalized.Number)

	logsCtx, cancel := context.WithTimeout(ctx, r.pollTimeout)
	defer cancel()

	fromBlock := r.lastProcessedFinalizedBlock.Load()

	r.logger.Debugw("Querying from block", "fromBlock", fromBlock)
	events, lastQueriedBlock, err := r.loadEvents(logsCtx, fromBlock, latest)
	if err != nil {
		r.logReadError(err, fromBlock)

		// Only return early when no progress was made
		if lastQueriedBlock == fromBlock {
			r.setScannedThrough(blockBefore(fromBlock))
			return false
		}
	}

	tasks := r.tasksFromEvents(ctx, events, latest, finalized)

	r.addToPendingQueueHandleReorg(tasks, fromBlock, lastQueriedBlock)
	if lastQueriedBlock == 0 {
		r.setScannedThrough(latest.Number)
	} else {
		r.setScannedThrough(lastQueriedBlock)
	}

	// Spans for pending tasks stay open here - sendReadyMessages reuses them
	// instead of opening a new one per poll. Dropped tasks' spans are ended in
	// addToPendingQueueHandleReorg instead.

	if len(events) == 0 {
		r.logger.Debugw("No events found in range",
			"fromBlock", fromBlock,
			"toBlock", lastQueriedBlock)
	}

	// Advance to min(lastQueriedBlock, finalized). A 0 lastQueriedBlock means
	// the last chunk had no explicit upper bound (queried up to latest), so we
	// treat it as ∞ and always take finalized.
	newBlock := finalized.Number
	if lastQueriedBlock != 0 && lastQueriedBlock < newBlock {
		newBlock = lastQueriedBlock
	}
	r.lastProcessedFinalizedBlock.Store(newBlock)
	r.metrics().SetSourceReaderLastProcessedFinalizedBlock(ctx, int64(newBlock)) // #nosec G115 -- chain block heights are within int64 range

	r.logger.Debugw("Processed block range",
		"fromBlock", fromBlock,
		"toBlock", "latest",
		"advancedTo", newBlock,
		"eventsFound", len(events))
	return err == nil
}

// logReadError logs a failed event read; a source still loading is expected on startup, so it is
// logged at info. Metrics are unchanged: the loop still records poll_error.
func (r *Service) logReadError(err error, fromBlock uint64) {
	if errors.Is(err, chainaccess.ErrSourceNotReady) {
		r.logger.Infow("Source not ready yet, waiting", "fromBlock", fromBlock, "error", err)
		return
	}
	r.logger.Warnw("Error when querying logs", "error", err, "fromBlock", fromBlock, "toBlock", "latest")
}

func (r *Service) setScannedThrough(block uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.scannedThrough = &block
}

func blockBefore(block uint64) uint64 {
	if block == 0 {
		return 0
	}
	return block - 1
}

// tasksFromEvents shares filtering, ID validation and reader metadata between
// normal discovery and bounded source recovery.
func (r *Service) tasksFromEvents(ctx context.Context, events []protocol.MessageSentEvent, latest, finalized *protocol.BlockHeader) []verifier.VerificationTask {
	tasks := make([]verifier.VerificationTask, 0, len(events))
	for _, event := range events {
		if r.filter != nil && !r.filter.Filter(event) {
			r.messageMetrics(event.Message).IncrementMessageTransition(
				ctx,
				monitoring.MessageTransitionStageSourceRead,
				monitoring.MessageTransitionOutcomeFiltered,
				monitoring.MessageTransitionReasonFilter)
			r.logger.Debugw("Message filtered out by filter",
				protocol.LogKeyMessageID, event.MessageID.String(),
				protocol.LogKeyDestChain, event.Message.DestChainSelector,
			)
			continue
		}
		computedMessageID, err := event.Message.MessageID()
		if err != nil {
			r.messageMetrics(event.Message).IncrementMessageTransition(
				ctx,
				monitoring.MessageTransitionStageSourceRead,
				monitoring.MessageTransitionOutcomeMessageIDMismatch,
				monitoring.MessageTransitionReasonMessageIDComputeFailed)
			r.logger.Errorw("Failed to compute message ID", "error", err)
			continue
		}
		onchainMessageID := event.MessageID.String()
		if computedMessageID.String() != onchainMessageID {
			r.messageMetrics(event.Message).IncrementMessageTransition(
				ctx,
				monitoring.MessageTransitionStageSourceRead,
				monitoring.MessageTransitionOutcomeMessageIDMismatch,
				monitoring.MessageTransitionReasonMessageIDMismatch)
			r.logger.Errorw("Message ID mismatch", "computed", computedMessageID.String(), "onchain", onchainMessageID)
			continue
		}

		task := verifier.VerificationTask{
			Message:              event.Message,
			ReceiptBlobs:         event.Receipts,
			BlockNumber:          event.BlockNumber,
			MessageID:            onchainMessageID,
			TxHash:               event.TxHash,
			SourceBlockHash:      event.BlockHash,
			FeeToken:             event.FeeToken,
			SourceBlockTimestamp: sourceBlockTimestamp(event.BlockNumber, event.BlockTimestamp, latest, finalized),
			FinalizedBlockAtRead: finalized.Number,
		}

		r.mu.RLock()
		_, alreadyPending := r.pendingTasks[onchainMessageID]
		_, alreadySent := r.sentTasks[onchainMessageID]
		r.mu.RUnlock()
		if !alreadyPending && !alreadySent {
			sCtx, span := r.monitoring.Tracing().StartMessageSpan(ctx, monitoring.MessageDiscoverySpanName(r.verifierID), event.MessageID,
				tracing.AlwaysSampled(),
				tracing.WithAttributes(
					tracing.VerifierIDKey, r.verifierID,
					tracing.BlockNumberKey, strconv.FormatUint(event.BlockNumber, 10),
					tracing.TxHashKey, event.TxHash.String(),
					tracing.SourceChainNameKey, event.Message.SourceChainSelector.ChainName(),
					tracing.SourceChainSelectorKey, event.Message.SourceChainSelector.String(),
					tracing.DestChainNameKey, event.Message.DestChainSelector.ChainName(),
					tracing.DestChainSelectorKey, event.Message.DestChainSelector.String(),
				),
			)
			carrier := propagation.MapCarrier{}
			otel.GetTextMapPropagator().Inject(sCtx, carrier)
			span.AddEvent(monitoring.EventChainEventDiscovered, oteltrace.WithAttributes(attribute.String(tracing.MessageIDKey, onchainMessageID)))

			task.TraceParent = carrier.Get("traceparent")
			task.TraceContext = sCtx
		}

		tasks = append(tasks, task)
		r.messageMetrics(event.Message).IncrementMessageTransition(
			ctx,
			monitoring.MessageTransitionStageSourceRead,
			monitoring.MessageTransitionOutcomeDiscovered,
			monitoring.MessageTransitionReasonNone)
	}

	return tasks
}

// sourceBlockTimestamp reuses a header already fetched for this poll only if it is the
// event's block. The current head's timestamp is not a substitute for a historical block's time.
func sourceBlockTimestamp(blockNumber uint64, known time.Time, headers ...*protocol.BlockHeader) time.Time {
	if !known.IsZero() {
		return known
	}
	for _, header := range headers {
		if header != nil && header.Number == blockNumber && !header.Timestamp.IsZero() {
			return header.Timestamp
		}
	}
	return time.Time{}
}

func (r *Service) initializeStartBlock(ctx context.Context) (uint64, error) {
	r.logger.Infow("Initializing start block for event monitoring")

	chainStatuses, err := r.chainStatusManager.ReadChainStatuses(ctx, []protocol.ChainSelector{r.chainSelector})
	if err != nil {
		r.logger.Warnw("Failed to read chainStatus, falling back to lookback window", "error", err)
		return 0, err
	}

	chainStatus, ok := chainStatuses[r.chainSelector]
	if !ok {
		r.logger.Infow("No chainStatus found, starting from block 1")
		_, finalized, err := r.sourceReader.LatestAndFinalizedBlock(ctx)
		if err != nil {
			return 0, fmt.Errorf("failed to get finalized block: %w", err)
		}
		if finalized == nil {
			return 0, fmt.Errorf("finalized block is nil")
		}
		return r.fallbackBlockEstimate(finalized.Number, 500), nil
	}

	r.disabled.Store(chainStatus.Disabled)
	// FinalizedBlockHeight is an arbitrary-precision persisted value: Uint64() silently
	// truncates an out-of-range checkpoint and +1 wraps a MaxUint64 one, either restarting
	// the scan at an unrelated historical block. Reject checkpoints without a representable next block.
	if !chainStatus.FinalizedBlockHeight.IsUint64() || chainStatus.FinalizedBlockHeight.Uint64() == math.MaxUint64 {
		return 0, fmt.Errorf("persisted finalized block %s cannot produce a representable next block",
			chainStatus.FinalizedBlockHeight.String())
	}
	startBlock := chainStatus.FinalizedBlockHeight.Uint64() + 1
	r.logger.Infow("Resuming from chainStatus",
		"chainStatusBlock", chainStatus.FinalizedBlockHeight,
		"disabled", chainStatus.Disabled,
		"startBlock", startBlock)

	return startBlock, nil
}

func (r *Service) fallbackBlockEstimate(currentBlock uint64, lookbackBlocks int64) uint64 {
	var fallBackBlock uint64
	if lookback := uint64(max(lookbackBlocks, 0)); lookback < currentBlock {
		fallBackBlock = currentBlock - lookback
	}
	r.logger.Infow("Using fallback block estimate",
		"currentBlock", currentBlock,
		"fallbackBlock", fallBackBlock)
	return fallBackBlock
}

// addToPendingQueueHandleReorg drops queued tasks absent from the re-scanned range
// [fromBlock, toBlock]; a toBlock of 0 means the range was open-ended (queried up to latest).
func (r *Service) addToPendingQueueHandleReorg(tasks []verifier.VerificationTask, fromBlock, toBlock uint64) {
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
		if existing.BlockNumber >= fromBlock && (toBlock == 0 || existing.BlockNumber <= toBlock) {
			if _, exists := tasksMap[msgID]; !exists {
				r.removeReorgedPendingLocked(msgID, existing, fromBlock)
			}
		}
	}

	for msgID, task := range r.sentTasks {
		if task.BlockNumber >= fromBlock && (toBlock == 0 || task.BlockNumber <= toBlock) {
			if _, exists := tasksMap[msgID]; !exists {
				span := tracing.SpanFromContext(task.TraceContext)
				span.AddEvent(monitoring.EventReorgRemovedSent,
					oteltrace.WithAttributes(
						attribute.String(tracing.BlockNumberKey, strconv.FormatUint(task.BlockNumber, 10)),
						attribute.String(tracing.SourceChainNameKey, task.Message.SourceChainSelector.ChainName()),
						attribute.String(tracing.SourceChainSelectorKey, task.Message.SourceChainSelector.String()),
						attribute.String(tracing.DestChainNameKey, task.Message.DestChainSelector.ChainName()),
						attribute.String(tracing.DestChainSelectorKey, task.Message.DestChainSelector.String()),
					),
				)
				span.End()
				r.logger.Warnw("Removing task from sentTasks due to reorg",
					protocol.LogKeyMessageID, msgID,
					protocol.LogKeySeqNum, task.Message.SequenceNumber,
					protocol.LogKeyDestChain, task.Message.DestChainSelector,
				)
				r.reorgTracker.Track(task.Message.DestChainSelector, task.Message.SequenceNumber)
				delete(r.sentTasks, msgID)
			}
		}
	}

	for _, task := range tasks {
		span := tracing.SpanFromContext(task.TraceContext)
		if existing, exists := r.pendingTasks[task.MessageID]; exists {
			if existing.BlockNumber != task.BlockNumber || !bytes.Equal(existing.SourceBlockHash, task.SourceBlockHash) ||
				!bytes.Equal(existing.TxHash, task.TxHash) {
				r.updatePendingObservationLocked(existing, task)
			}
			// already tracked - span is a throwaway
			span.AddEvent(monitoring.EventAlreadyTracked)
			span.End()
			continue
		}
		if sent, alreadySent := r.sentTasks[task.MessageID]; alreadySent {
			if sent.BlockNumber != task.BlockNumber || !bytes.Equal(sent.SourceBlockHash, task.SourceBlockHash) {
				r.logger.Warnw("Sent message found in a different block",
					protocol.LogKeyMessageID, task.MessageID,
					"previousBlock", sent.BlockNumber,
					"blockNumber", task.BlockNumber)
				sent.BlockNumber = task.BlockNumber
				sent.SourceBlockHash = task.SourceBlockHash
				r.sentTasks[task.MessageID] = sent
			}
			r.logger.Debugw("Skipping already-sent message",
				protocol.LogKeyMessageID, task.MessageID,
				"blockNumber", task.BlockNumber)
			// already sent - span is a throwaway
			span.AddEvent(monitoring.EventAlreadySent)
			span.End()
			continue
		}
		r.pendingTasks[task.MessageID] = task
		r.pendingSince[task.MessageID] = time.Now()
		r.messageMetrics(task.Message).IncrementMessageTransition(
			context.Background(),
			monitoring.MessageTransitionStagePendingFinality,
			monitoring.MessageTransitionOutcomeQueued,
			monitoring.MessageTransitionReasonNone)

		// Not terminal - the message is still in flight (curse/disable checks,
		// finality wait, publish). Only add the event; the span stays open
		// until a terminal path (reorg drop, cursed/disabled drop, or
		// task_published) ends it.
		span.AddEvent(monitoring.EventAddedToPending,
			oteltrace.WithAttributes(
				attribute.String(tracing.BlockNumberKey, strconv.FormatUint(task.BlockNumber, 10)),
			),
		)

		r.logger.Debugw("Added message to pending queue",
			protocol.LogKeyMessageID, task.MessageID,
			"blockNumber", task.BlockNumber,
			protocol.LogKeySeqNum, task.Message.SequenceNumber,
			"pendingCount", len(r.pendingTasks))
	}
}

// removeReorgedPendingLocked drops a pending task whose source event is not on the canonical chain.
func (r *Service) removeReorgedPendingLocked(msgID string, existing verifier.VerificationTask, fromBlock uint64) {
	span := tracing.SpanFromContext(existing.TraceContext)
	span.AddEvent(monitoring.EventReorgRemovedPending,
		oteltrace.WithAttributes(
			attribute.String(tracing.BlockNumberKey, strconv.FormatUint(existing.BlockNumber, 10)),
			attribute.String(tracing.SourceChainNameKey, existing.Message.SourceChainSelector.ChainName()),
			attribute.String(tracing.SourceChainSelectorKey, existing.Message.SourceChainSelector.String()),
			attribute.String(tracing.DestChainNameKey, existing.Message.DestChainSelector.ChainName()),
			attribute.String(tracing.DestChainSelectorKey, existing.Message.DestChainSelector.String()),
		),
	)
	span.End()
	r.logger.Warnw("Removing task from pending queue due to reorg",
		protocol.LogKeyMessageID, msgID,
		"blockNumber", existing.BlockNumber,
		protocol.LogKeySeqNum, existing.Message.SequenceNumber,
		protocol.LogKeyDestChain, existing.Message.DestChainSelector,
		"fromBlock", fromBlock,
	)
	r.reorgTracker.Track(existing.Message.DestChainSelector, existing.Message.SequenceNumber)
	delete(r.pendingSince, msgID)
	delete(r.pendingTasks, msgID)
}

// confirmBlockHashesLocked keeps the ready tasks whose block is still canonical. Tasks without a
// block hash pass unchanged. unconfirmed is true when a task stays pending this cycle.
func (r *Service) confirmBlockHashesLocked(ctx context.Context, ready []verifier.VerificationTask) (confirmed []verifier.VerificationTask, unconfirmed bool) {
	blocks := make([]uint64, 0, len(ready))
	for _, task := range ready {
		if len(task.SourceBlockHash) > 0 {
			blocks = append(blocks, task.BlockNumber)
		}
	}
	slices.Sort(blocks)
	blocks = slices.Compact(blocks)
	if len(blocks) == 0 {
		return ready, false
	}

	headerCtx, cancel := context.WithTimeout(ctx, r.pollTimeout)
	defer cancel()
	headers, err := r.sourceReader.GetBlocksHeaders(headerCtx, blocks)
	if err != nil {
		r.logger.Warnw("Failed to get block headers for ready tasks, retrying next cycle", "error", err)
		headers = nil
	}

	confirmed = make([]verifier.VerificationTask, 0, len(ready))
	for _, task := range ready {
		if len(task.SourceBlockHash) == 0 {
			confirmed = append(confirmed, task)
			continue
		}
		header, ok := headers[task.BlockNumber]
		switch {
		case !ok:
			unconfirmed = true
		case bytes.Equal(header.Hash[:], task.SourceBlockHash):
			confirmed = append(confirmed, task)
		default:
			unconfirmed = true
			r.rescanFromLocked(task)
		}
	}
	return confirmed, unconfirmed
}

// rescanFromLocked keeps a task whose block hash changed and moves the scan cursor below its block.
// The next scan then finds the message in its current block or removes the task.
func (r *Service) rescanFromLocked(task verifier.VerificationTask) {
	r.logger.Warnw("Block hash of a ready task changed, scanning its block again",
		protocol.LogKeyMessageID, task.MessageID,
		"blockNumber", task.BlockNumber)
	r.reorgTracker.Track(task.Message.DestChainSelector, task.Message.SequenceNumber)

	rewindTo := blockBefore(task.BlockNumber)
	if r.lastProcessedFinalizedBlock.Load() > rewindTo {
		r.lastProcessedFinalizedBlock.Store(rewindTo)
	}
	if r.scannedThrough == nil || *r.scannedThrough > rewindTo {
		r.scannedThrough = &rewindTo
	}
}

// updatePendingObservationLocked replaces the source observation of a pending task and keeps its trace.
func (r *Service) updatePendingObservationLocked(existing, observed verifier.VerificationTask) {
	r.logger.Warnw("Pending message found in a different block, using the new block",
		protocol.LogKeyMessageID, existing.MessageID,
		"previousBlock", existing.BlockNumber,
		"blockNumber", observed.BlockNumber)
	tracing.SpanFromContext(existing.TraceContext).AddEvent(monitoring.EventReorgMovedPending,
		oteltrace.WithAttributes(attribute.String(tracing.BlockNumberKey, strconv.FormatUint(observed.BlockNumber, 10))))
	r.reorgTracker.Track(existing.Message.DestChainSelector, existing.Message.SequenceNumber)

	observed.TraceContext = existing.TraceContext
	observed.TraceParent = existing.TraceParent
	r.pendingTasks[existing.MessageID] = observed
}

func (r *Service) sendReadyMessages(ctx context.Context, latest, safe, finalized *protocol.BlockHeader) bool {
	stringSafeBlock := "unavailable"
	if safe != nil {
		stringSafeBlock = strconv.FormatUint(safe.Number, 10)
	}

	r.logger.Debugw("Checking for ready messages to send",
		"latestBlock", latest.Number,
		"safeBlock", stringSafeBlock,
		"finalizedBlock", finalized.Number)

	if !r.checkFinality(ctx, finalized) {
		return false
	}

	latestBlock := latest.Number
	latestFinalizedBlock := finalized.Number

	var latestSafeBlock uint64 // 0 = chain does not expose a safe head
	if safe != nil {
		latestSafeBlock = safe.Number
	}

	// advanceCheckpointTo captures the block value that should be checkpointed after releasing
	// the mutex. Zero means no checkpoint should be written this cycle.
	advanceCheckpointTo := func() uint64 {
		r.mu.Lock()
		defer r.mu.Unlock()
		defer r.recordPendingMetricsLocked(ctx)
		// Each flag holds the checkpoint back for one cause, so the warning can name it.
		var admissionUnknown, awaitingScan, unconfirmed bool

		if r.disabled.Load() {
			return 0
		}

		for msgID, task := range r.sentTasks {
			if task.BlockNumber < latestFinalizedBlock {
				delete(r.sentTasks, msgID)
			}
		}

		ready := make([]verifier.VerificationTask, 0, len(r.pendingTasks))
		toBeDeleted := make([]string, 0)
		auditDrops := make([]recovery.Event, 0)

		checkpointCandidate := latestFinalizedBlock
		if r.startBlockInitialized.Load() {
			checkpointCandidate = r.lastProcessedFinalizedBlock.Load()
		}

		for msgID, task := range r.pendingTasks {
			taskSpan := tracing.SpanFromContext(task.TraceContext)

			if r.scannedThrough != nil && task.BlockNumber > *r.scannedThrough {
				// Restart resumes at checkpoint+1, so an unpublished task
				// at or below the checkpoint must prevent advancement.
				if task.BlockNumber <= checkpointCandidate {
					awaitingScan = true
				}
				continue
			}
			decision, reason, admissionErr := r.admission(ctx, task, latestBlock, latestSafeBlock, latestFinalizedBlock)
			if admissionErr != nil {
				r.logger.Warnw("Blocking message - admission state unknown", "messageID", msgID, "reason", reason, "error", admissionErr)
				r.messageMetrics(task.Message).IncrementMessageTransition(ctx, monitoring.MessageTransitionStageAdmission, reason, reason)
				admissionUnknown = true
				// Recorded but not ended - transient/unknown; the same span is reused next poll.
				taskSpan.RecordError(admissionErr)
				taskSpan.SetStatus(codes.Error, admissionErr.Error())
				continue
			}
			if decision == admissionDrop {
				if r.recovery != nil {
					auditDrops = append(auditDrops, r.dropEvent(task, reason, ""))
				}
				outcome := monitoring.MessageTransitionOutcomeLaneCursed
				if reason == monitoring.MessageTransitionReasonMessageDisablementRule {
					outcome = monitoring.MessageTransitionOutcomeMessageDisabled
				}
				logMessage, eventName := "Dropping task - lane is cursed", monitoring.EventCursedDropped
				if reason == monitoring.MessageTransitionReasonMessageDisablementRule {
					logMessage, eventName = "Dropping task - message matched a disablement rule", monitoring.EventDisabledDropped
				}
				taskSpan.AddEvent(eventName,
					oteltrace.WithAttributes(
						attribute.String(tracing.SourceChainNameKey, task.Message.SourceChainSelector.ChainName()),
						attribute.String(tracing.SourceChainSelectorKey, task.Message.SourceChainSelector.String()),
						attribute.String(tracing.DestChainNameKey, task.Message.DestChainSelector.ChainName()),
						attribute.String(tracing.DestChainSelectorKey, task.Message.DestChainSelector.String()),
					),
				)
				taskSpan.End()
				r.logger.Warnw(logMessage, protocol.LogKeyMessageID, msgID, protocol.LogKeySourceChain, task.Message.SourceChainSelector, protocol.LogKeyDestChain, task.Message.DestChainSelector, "sourceBlock", task.BlockNumber, "reason", reason)
				r.messageMetrics(task.Message).IncrementMessageTransition(ctx, monitoring.MessageTransitionStageAdmission, outcome, reason)
				// Terminal-drop marker so rediscovery doesn't reopen a new span
				// every poll; evicted from sentTasks once the block finalizes.
				r.sentTasks[msgID] = task
				toBeDeleted = append(toBeDeleted, msgID)
				continue
			}
			if decision != admissionReady {
				// Finality still pending; the span stays open and is reused next poll.
				continue
			}

			task.SourceBlockTimestamp = sourceBlockTimestamp(task.BlockNumber, task.SourceBlockTimestamp, latest, safe, finalized)

			// Set the timestamp when message became ready for verification
			// This is the finalized block timestamp which represents when the message met finality criteria
			task.ReadyForVerificationAt = latest.Timestamp

			// The finalized head as of now. The policy hook publishes this as
			// finalized_block_number and derives block_depth from it, so an
			// operator's endpoint can see how deeply confirmed a message was when
			// the verifier decided it was ready (see verifier/pkg/policy/contract.go).
			// FinalizedBlockAtRead cannot serve that: it is captured at discovery,
			// when the message's own block is still ahead of the finalized head, so
			// a depth computed from it is 0 for every message that took the normal
			// path to finality.
			task.FinalizedBlockAtReady = latestFinalizedBlock

			ready = append(ready, task)

			taskSpan.AddEvent(
				monitoring.EventReadyForVerification,
				oteltrace.WithAttributes(
					attribute.String(tracing.BlockNumberKey, strconv.FormatUint(task.BlockNumber, 10)),
					attribute.String(tracing.LatestBlockNumberKey, strconv.FormatUint(latestBlock, 10)),
					attribute.String(tracing.LatestSafeBlockNumberKey, stringSafeBlock),
					attribute.String(tracing.LatestFinalizedBlockNumberKey, strconv.FormatUint(latestFinalizedBlock, 10)),
				),
			)
			// Not ended here - still open until the publish step below ends it.
		}

		if len(auditDrops) > 0 {
			r.recordDrops(ctx, auditDrops)
		}

		// Delete dropped tasks immediately (these are not queued)
		for _, msgID := range toBeDeleted {
			delete(r.pendingSince, msgID)
			delete(r.pendingTasks, msgID)
		}

		ready, unconfirmed = r.confirmBlockHashesLocked(ctx, ready)

		// Use lastProcessedFinalizedBlock as the safe checkpoint: it tracks how far SRS has
		// successfully scanned from chain (may be less than finalized if there were fetch errors).
		// Fall back to latestFinalizedBlock if not yet initialized (e.g. in unit tests that call
		// sendReadyMessages directly without starting the service first).
		safeCheckpoint := latestFinalizedBlock
		if r.startBlockInitialized.Load() {
			safeCheckpoint = r.lastProcessedFinalizedBlock.Load()
		}

		if admissionUnknown || awaitingScan || unconfirmed {
			r.logger.Warnw("Pending tasks not settled, keeping checkpoint unchanged to avoid skipped messages",
				"admissionStateUnknown", admissionUnknown,
				"sourceBlockUnconfirmed", unconfirmed,
				"awaitingScan", awaitingScan)
			safeCheckpoint = 0
		}

		if len(ready) == 0 {
			// No messages to publish this cycle; we can still advance the checkpoint because
			// all finalized messages have already been queued in previous cycles or dropped.
			return safeCheckpoint
		}

		r.logger.Debugw("Publishing ready tasks to job queue",
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
		err := r.taskQueue.Publish(ctx, ready...)
		if err != nil {
			for _, task := range ready {
				r.messageMetrics(task.Message).IncrementMessageTransition(
					ctx,
					monitoring.MessageTransitionStageAdmission,
					monitoring.MessageTransitionOutcomeQueuePublishError,
					monitoring.MessageTransitionReasonQueuePublishFailed)
			}
			r.logger.Errorw("Failed to publish tasks to job queue - tasks will remain in pending queue for retry",
				"error", err,
				"count", len(ready))
			for _, task := range ready {
				span := tracing.SpanFromContext(task.TraceContext)
				span.RecordError(err)
				span.SetStatus(codes.Error, err.Error())
			}
			return 0 // Do not advance checkpoint on publish failure
		}

		// Success - now it's safe to update in-memory state
		for _, task := range ready {
			msgID := task.MessageID
			r.sentTasks[msgID] = task
			delete(r.pendingTasks, msgID)
			delete(r.pendingSince, msgID)
			r.messageMetrics(task.Message).IncrementMessageTransition(
				ctx,
				monitoring.MessageTransitionStageAdmission,
				monitoring.MessageTransitionOutcomePublished,
				monitoring.MessageTransitionReasonNone)
			r.reorgTracker.Remove(task.Message.DestChainSelector, task.Message.SequenceNumber)

			span := tracing.SpanFromContext(task.TraceContext)
			span.AddEvent(monitoring.EventTaskPublished,
				oteltrace.WithAttributes(
					attribute.String(tracing.BlockNumberKey, strconv.FormatUint(task.BlockNumber, 10)),
				),
			)
			span.End()
		}

		r.logger.Debugw("Successfully published and tracked tasks",
			"published", len(ready),
			"remainingPending", len(r.pendingTasks),
			"totalSent", len(r.sentTasks))

		return safeCheckpoint
	}()

	if advanceCheckpointTo > 0 {
		r.writeCheckpoint(ctx, advanceCheckpointTo)
	}
	return !r.disabled.Load()
}

func (r *Service) checkFinality(ctx context.Context, finalized *protocol.BlockHeader) bool {
	if err := r.finalityChecker.UpdateFinalized(ctx, finalized.Number); err != nil {
		r.logger.Errorw("Failed to update finality checker",
			"finalizedBlock", finalized.Number,
			"error", err)
		if r.finalityChecker.IsFinalityViolated() {
			r.handleFinalityViolation(ctx)
			return false
		}
		return false
	}

	if r.finalityChecker.IsFinalityViolated() {
		r.logger.Errorw("Finality violation detected", "finalizedBlock", finalized.Number)
		r.handleFinalityViolation(ctx)
		return false
	}

	return !r.disabled.Load()
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
		r.logger.Debugw("Checkpoint advanced", "finalizedBlock", finalizedBlock)
	}
}

// isMessageReadyForVerification decides whether a message has met its requested finality.
// Reorg-tracked messages always require full finality regardless of the requested mode;
// all other finality semantics are delegated to protocol.Finality.IsMessageReady.
func (r *Service) isMessageReadyForVerification(
	task verifier.VerificationTask,
	latestBlock uint64,
	latestSafeBlock uint64,
	latestFinalizedBlock uint64,
) bool {
	msgBlock := task.BlockNumber
	destChain := task.Message.DestChainSelector
	seqNum := task.Message.SequenceNumber

	if r.reorgTracker.RequiresFinalization(destChain, seqNum) {
		ready := msgBlock <= latestFinalizedBlock
		r.logger.Debugw("Reorg-affected message finality check",
			protocol.LogKeyMessageID, task.MessageID,
			protocol.LogKeySeqNum, seqNum,
			protocol.LogKeyDestChain, destChain,
			"messageBlock", task.BlockNumber,
			"finalizedBlock", latestFinalizedBlock,
			"meetsRequirement", ready,
		)
		return ready
	}

	ready := task.Message.Finality.IsMessageReady(msgBlock, latestBlock, latestSafeBlock, latestFinalizedBlock)
	safeBlockString := "unavailable"
	if latestSafeBlock != 0 {
		safeBlockString = strconv.FormatUint(latestSafeBlock, 10)
	}
	r.logger.Debugw("Finality check",
		protocol.LogKeyMessageID, task.MessageID,
		"finality", task.Message.Finality,
		"messageBlock", task.BlockNumber,
		"latestBlock", latestBlock,
		"safeBlock", safeBlockString,
		"finalizedBlock", latestFinalizedBlock,
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
	r.finalityBlocked.Store(true)
	r.disabled.Store(true)
	r.recordFinalityIncident(ctx)
	flushed := len(r.pendingTasks)
	sentFlushed := len(r.sentTasks)
	for _, task := range r.pendingTasks {
		r.messageMetrics(task.Message).IncrementMessageTransition(
			ctx,
			monitoring.MessageTransitionStagePendingFinality,
			monitoring.MessageTransitionOutcomeFinalityBlocked,
			monitoring.MessageTransitionReasonFinalityViolation)

		// task's span has been open since discovery
		span := tracing.SpanFromContext(task.TraceContext)
		span.AddEvent(monitoring.EventFinalityBlocked)
		span.End()
	}
	r.pendingTasks = make(map[string]verifier.VerificationTask)
	r.pendingSince = make(map[string]time.Time)
	r.sentTasks = make(map[string]verifier.VerificationTask)
	r.metrics().SetSourceReaderState(ctx, monitoring.SourceReaderStateFinalityBlocked)

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

func (r *Service) metrics() verifier.MetricLabeler {
	return r.monitoring.Metrics().With(
		"verifier_id", r.verifierID,
		"source_chain", r.chainSelector.String(),
		"source_chain_name", r.chainSelector.ChainName(),
	)
}

func (r *Service) recordDisabledState(ctx context.Context) {
	state := monitoring.SourceReaderStateDisabled
	if r.finalityBlocked.Load() {
		state = monitoring.SourceReaderStateFinalityBlocked
	}
	r.metrics().SetSourceReaderState(ctx, state)
}

func (r *Service) messageMetrics(message protocol.Message) verifier.MetricLabeler {
	return r.metrics().With(
		"dest_chain", message.DestChainSelector.String(),
		"dest_chain_name", message.DestChainSelector.ChainName(),
	)
}

// recordPendingMetricsLocked emits a consistent snapshot of pending task state.
// The caller must hold r.mu.
func (r *Service) recordPendingMetricsLocked(ctx context.Context) {
	type pendingState struct {
		count  int64
		oldest time.Time
	}
	byDestination := make(map[protocol.ChainSelector]pendingState)
	for messageID, task := range r.pendingTasks {
		state := byDestination[task.Message.DestChainSelector]
		state.count++
		seen := r.pendingSince[messageID]
		if state.oldest.IsZero() || (!seen.IsZero() && seen.Before(state.oldest)) {
			state.oldest = seen
		}
		byDestination[task.Message.DestChainSelector] = state
	}
	for destination := range r.pendingMetricDestinations {
		if _, ok := byDestination[destination]; !ok {
			byDestination[destination] = pendingState{}
		}
	}
	r.pendingMetricDestinations = make(map[protocol.ChainSelector]struct{}, len(byDestination))
	for destination, state := range byDestination {
		metrics := r.metrics().With("dest_chain", destination.String(), "dest_chain_name", destination.ChainName())
		metrics.RecordMessagesInFlight(ctx, monitoring.MessageInFlightStatePendingFinality, state.count)
		if !state.oldest.IsZero() {
			metrics.RecordOldestMessageAge(ctx, monitoring.MessageInFlightStatePendingFinality, time.Since(state.oldest))
		} else {
			metrics.RecordOldestMessageAge(ctx, monitoring.MessageInFlightStatePendingFinality, 0)
		}
		if state.count > 0 {
			r.pendingMetricDestinations[destination] = struct{}{}
		}
	}
}

var (
	_ services.Service        = (*Service)(nil)
	_ protocol.HealthReporter = (*Service)(nil)
)
