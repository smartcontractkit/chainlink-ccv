package verifier

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/common"
	cursecheckerimpl "github.com/smartcontractkit/chainlink-ccv/integration/pkg/cursechecker"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/batcher"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/services"
)

const (
	DefaultSourceReaderPollInterval = 2 * time.Second
	DefaultFinalityCheckInterval    = 500 * time.Millisecond
)

// -----------------------------------------------------------------------------
// Per-chain state
// -----------------------------------------------------------------------------

type sourceState struct {
	reader        *SourceReaderService2
	readyTasksCh  <-chan batcher.BatchResult[VerificationTask]
	reorgDetector protocol.ReorgDetector // kept only so we can Close() it if needed
	chainSelector protocol.ChainSelector
}

func (s *sourceState) Close() error {
	if s == nil {
		return nil
	}
	// SRS2 owns underlying reader + reorg detector lifecycle
	if s.reader != nil {
		return s.reader.Stop()
	}
	return nil
}

// -----------------------------------------------------------------------------
// Coordinator
// -----------------------------------------------------------------------------

type Coordinator struct {
	services.StateMachine

	cancel       context.CancelFunc
	verifyingWg  sync.WaitGroup // Tracks in-flight verification tasks (must complete before closing error channels)
	backgroundWg sync.WaitGroup // Tracks background goroutines

	verifier       Verifier
	storage        protocol.CCVNodeDataWriter
	lggr           logger.Logger
	monitoring     Monitoring
	messageTracker MessageLatencyTracker
	config         CoordinatorConfig

	// Per-chain state
	sourceStates map[protocol.ChainSelector]*sourceState

	// Dependencies
	sourceReaders      map[protocol.ChainSelector]chainaccess.SourceReader
	reorgDetectors     map[protocol.ChainSelector]protocol.ReorgDetector
	chainStatusManager protocol.ChainStatusManager

	// Curse detector is created & owned by coordinator
	curseDetector common.CurseCheckerService

	// Finality
	finalityCheckInterval time.Duration

	// Storage batching (kept in coordinator as requested)
	storageBatcher   *batcher.Batcher[protocol.VerifierNodeResult]
	batchedCCVDataCh chan batcher.BatchResult[protocol.VerifierNodeResult]

	// Errors
	errCh chan error

	// For tests / metrics if you need them
	started atomic.Bool
}

// -----------------------------------------------------------------------------
// Options
// -----------------------------------------------------------------------------

type Option func(*Coordinator)

func WithChainStatusManager(manager protocol.ChainStatusManager) Option {
	return func(vc *Coordinator) {
		vc.chainStatusManager = manager
	}
}

func WithSourceReaders(sourceReaders map[protocol.ChainSelector]chainaccess.SourceReader) Option {
	return func(vc *Coordinator) {
		if vc.sourceReaders == nil {
			vc.sourceReaders = make(map[protocol.ChainSelector]chainaccess.SourceReader)
		}
		for chainSelector, reader := range sourceReaders {
			vc.sourceReaders[chainSelector] = reader
		}
	}
}

func AddSourceReader(chainSelector protocol.ChainSelector, sourceReader chainaccess.SourceReader) Option {
	return WithSourceReaders(map[protocol.ChainSelector]chainaccess.SourceReader{chainSelector: sourceReader})
}

func WithReorgDetectors(reorgDetectors map[protocol.ChainSelector]protocol.ReorgDetector) Option {
	return func(vc *Coordinator) {
		if vc.reorgDetectors == nil {
			vc.reorgDetectors = make(map[protocol.ChainSelector]protocol.ReorgDetector)
		}
		for chainSelector, detector := range reorgDetectors {
			vc.reorgDetectors[chainSelector] = detector
		}
	}
}

func AddReorgDetector(chainSelector protocol.ChainSelector, detector protocol.ReorgDetector) Option {
	return WithReorgDetectors(map[protocol.ChainSelector]protocol.ReorgDetector{chainSelector: detector})
}

func WithCurseDetector(detector common.CurseCheckerService) Option {
	return func(vc *Coordinator) {
		vc.curseDetector = detector
	}
}

// -----------------------------------------------------------------------------
// Construction / config
// -----------------------------------------------------------------------------

func NewCoordinator(
	lggr logger.Logger,
	verifier Verifier,
	sourceReaders map[protocol.ChainSelector]chainaccess.SourceReader,
	storage protocol.CCVNodeDataWriter,
	config CoordinatorConfig,
	messageTracker MessageLatencyTracker,
	monitoring Monitoring,
	finalityCheckInterval time.Duration,
	opts ...Option,
) (*Coordinator, error) {
	vc := &Coordinator{
		lggr:                  lggr,
		verifier:              verifier,
		sourceReaders:         sourceReaders,
		storage:               storage,
		config:                config,
		messageTracker:        messageTracker,
		monitoring:            monitoring,
		finalityCheckInterval: finalityCheckInterval,
		sourceStates:          make(map[protocol.ChainSelector]*sourceState),
		reorgDetectors:        make(map[protocol.ChainSelector]protocol.ReorgDetector),
		errCh:                 make(chan error),
	}

	for _, opt := range opts {
		opt(vc)
	}

	if err := vc.validateConfig(); err != nil {
		return nil, fmt.Errorf("invalid coordinator configuration: %w", err)
	}
	vc.applyConfigDefaults()

	return vc, nil
}

func (vc *Coordinator) validateConfig() error {
	if vc.verifier == nil {
		return errors.New("verifier is required")
	}
	if vc.storage == nil {
		return errors.New("storage is required")
	}
	if vc.lggr == nil {
		return errors.New("logger is required")
	}
	if vc.config.SourceConfigs == nil {
		return errors.New("source configs are required")
	}
	return nil
}

// applyConfigDefaults sets default values for config fields that are not set.
func (vc *Coordinator) applyConfigDefaults() {
	// Default storage batch size: 50 items
	if vc.config.StorageBatchSize <= 0 {
		vc.config.StorageBatchSize = 50
		if vc.lggr != nil {
			vc.lggr.Debugw("Using default StorageBatchSize", "value", vc.config.StorageBatchSize)
		}
	}

	// Default storage batch timeout: 1 second
	if vc.config.StorageBatchTimeout <= 0 {
		vc.config.StorageBatchTimeout = time.Second
		if vc.lggr != nil {
			vc.lggr.Debugw("Using default StorageBatchTimeout", "value", vc.config.StorageBatchTimeout)
		}
	}

	// Default finality check interval if not set externally
	if vc.finalityCheckInterval <= 0 {
		vc.finalityCheckInterval = time.Second
	}
}

// -----------------------------------------------------------------------------
// Start / Stop
// -----------------------------------------------------------------------------

func (vc *Coordinator) Start(ctx context.Context) error {
	return vc.StartOnce("Coordinator", func() error {
		vc.lggr.Infow("Starting verifier coordinator")
		vc.started.Store(true)

		ctx, vc.cancel = context.WithCancel(ctx)

		// 1) Read chain statuses (to skip disabled chains) if manager is available
		statusMap := make(map[protocol.ChainSelector]*protocol.ChainStatusInfo)
		if vc.chainStatusManager != nil {
			allSelectors := make([]protocol.ChainSelector, 0, len(vc.sourceReaders))
			for selector := range vc.sourceReaders {
				allSelectors = append(allSelectors, selector)
			}

			var err error
			statusMap, err = vc.chainStatusManager.ReadChainStatuses(ctx, allSelectors)
			if err != nil {
				vc.lggr.Errorw("Failed to read chain statuses, proceeding with all chains", "error", err)
				statusMap = make(map[protocol.ChainSelector]*protocol.ChainStatusInfo)
			}
		}

		// 2) Initialize per-chain SourceReaderService2 pipelines and collect RMN readers
		rmnReaders := make(map[protocol.ChainSelector]chainaccess.RMNCurseReader)

		for chainSelector, sourceReader := range vc.sourceReaders {
			if sourceReader == nil {
				continue
			}

			vc.lggr.Infow("Chain Status",
				"chainSelector", chainSelector,
				"status", statusMap[chainSelector])

			// Skip disabled chains
			if chainStatus := statusMap[chainSelector]; chainStatus != nil && chainStatus.Disabled {
				vc.lggr.Warnw("Chain is disabled in aggregator DB, skipping initialization",
					"chain", chainSelector,
					"blockHeight", chainStatus.FinalizedBlockHeight)
				continue
			}

			sourceCfg, ok := vc.config.SourceConfigs[chainSelector]
			if !ok {
				vc.lggr.Warnw("No source config for chain selector, skipping",
					"chainSelector", chainSelector)
				continue
			}

			// Underlying reader service
			sourcePollInterval := DefaultSourceReaderPollInterval
			if sourceCfg.PollInterval > 0 {
				sourcePollInterval = sourceCfg.PollInterval
			}

			readerLogger := logger.With(vc.lggr, "component", "SourceReader", "chainID", chainSelector)
			srs := NewSourceReaderService(
				sourceReader,
				chainSelector,
				vc.chainStatusManager,
				readerLogger,
				sourcePollInterval,
			)

			// Reorg detector for this chain (if any)
			detector := vc.reorgDetectors[chainSelector]

			// Wrap with SourceReaderService2 pipeline
			srs2 := NewSourceReaderService2(
				srs,
				logger.With(vc.lggr, "component", "SourceReaderService2", "chain", chainSelector),
				vc.curseDetector, // will be started below (startCurseDetector)
				vc.chainStatusManager,
				detector,
				vc.finalityCheckInterval,
			)

			if err := srs2.Start(ctx); err != nil {
				vc.lggr.Errorw("Failed to start SourceReaderService2",
					"chainSelector", chainSelector,
					"error", err)
				return err
			}

			state := &sourceState{
				reader:        srs2,
				readyTasksCh:  srs2.ReadyTasksChannel(),
				reorgDetector: detector,
				chainSelector: chainSelector,
			}
			vc.sourceStates[chainSelector] = state

			// If this reader also implements RMNCurseReader, collect it for curse detector
			if r, ok := sourceReader.(chainaccess.RMNCurseReader); ok {
				rmnReaders[chainSelector] = r
			}
		}

		if len(vc.sourceStates) == 0 {
			return errors.New("no enabled/initialized chain sources, nothing to coordinate")
		}

		// 3) Start curse detector (same pattern as current code)
		if err := vc.startCurseDetector(ctx, rmnReaders); err != nil {
			return fmt.Errorf("failed to start curse detector: %w", err)
		}

		// 4) Initialize storage batcher in coordinator (same pattern as current code)
		vc.batchedCCVDataCh = make(chan batcher.BatchResult[protocol.VerifierNodeResult], 10)
		vc.storageBatcher = batcher.NewBatcher(
			ctx,
			vc.config.StorageBatchSize,
			vc.config.StorageBatchTimeout,
			vc.batchedCCVDataCh,
		)

		// 5) Start background loops
		//   - cc v data loop (consume storage batcher results)
		vc.backgroundWg.Add(1)
		go func() {
			defer vc.backgroundWg.Done()
			vc.ccvDataLoop(ctx)
		}()

		//   - per-chain ready tasks loops
		for _, state := range vc.sourceStates {
			vc.backgroundWg.Add(1)
			go func(s *sourceState) {
				defer vc.backgroundWg.Done()
				vc.readyTasksLoop(ctx, s)
			}(state)
		}

		vc.lggr.Infow("Coordinator started successfully")
		return nil
	})
}

func (vc *Coordinator) Stop() error {
	return vc.StopOnce("Coordinator", func() error {
		if !vc.started.Load() {
			return nil
		}

		vc.lggr.Infow("Stopping verifier coordinator")

		// Cancel context so batcher + loops drain
		if vc.cancel != nil {
			vc.cancel()
		}

		// Wait for any in-flight verification tasks to complete.
		vc.verifyingWg.Wait()

		// Close storage batcher (this also flushes remaining items)
		if vc.storageBatcher != nil {
			if err := vc.storageBatcher.Close(); err != nil {
				vc.lggr.Errorw("Error closing storage batcher", "error", err)
			}
		}

		// Stop curse detector
		if vc.curseDetector != nil {
			if err := vc.curseDetector.Close(); err != nil {
				vc.lggr.Errorw("Error closing curse detector", "error", err)
			}
		}

		// Stop per-chain pipelines (includes underlying readers and reorg detectors)
		for chainSelector, state := range vc.sourceStates {
			if err := state.Close(); err != nil {
				vc.lggr.Errorw("Error closing source state",
					"chainSelector", chainSelector,
					"error", err)
			}
		}

		// Wait for background goroutines
		vc.backgroundWg.Wait()

		vc.lggr.Infow("Verifier coordinator stopped")
		return nil
	})
}

// -----------------------------------------------------------------------------
// Loops
// -----------------------------------------------------------------------------

// readyTasksLoop consumes ready tasks from a chain's SRS2 and sends them for verification.
func (vc *Coordinator) readyTasksLoop(ctx context.Context, state *sourceState) {
	for {
		select {
		case <-ctx.Done():
			return
		case batch, ok := <-state.readyTasksCh:
			if !ok {
				vc.lggr.Infow("ReadyTasksChannel closed; exiting readyTasksLoop",
					"chain", state.chainSelector)
				return
			}
			if batch.Error != nil {
				vc.lggr.Errorw("Error batch received from SourceReaderService2",
					"chain", state.chainSelector,
					"error", batch.Error)
				continue
			}
			vc.processReadyTasks(ctx, batch.Items)
		}
	}
}

// ccvDataLoop consumes results from the storage batcher (if you need to log errors, etc).
func (vc *Coordinator) ccvDataLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case batch, ok := <-vc.batchedCCVDataCh:
			if !ok {
				return
			}
			if batch.Error != nil {
				vc.lggr.Errorw("Error writing CCV node data", "error", batch.Error)
				continue
			}
			// Actual writes happen in the batcher handler; nothing else to do here.
		}
	}
}

// -----------------------------------------------------------------------------
// Core verification flow
// -----------------------------------------------------------------------------

// processReadyTasks receives tasks that are already ready (finality + curses handled
// by SRS2) and fans out verification per source chain.
func (vc *Coordinator) processReadyTasks(ctx context.Context, tasks []VerificationTask) {
	if len(tasks) == 0 {
		return
	}

	vc.lggr.Debugw("Processing batch of finalized messages", "batchSize", len(tasks))

	// Metrics: finality wait duration based on QueuedAt set in SRS2
	for _, task := range tasks {
		if !task.QueuedAt.IsZero() && vc.monitoring != nil {
			finalityWaitDuration := time.Since(task.QueuedAt)
			vc.monitoring.Metrics().
				With("source_chain", task.Message.SourceChainSelector.String(), "verifier_id", vc.config.VerifierID).
				RecordFinalityWaitDuration(ctx, finalityWaitDuration)
		}
	}

	// Group tasks by source chain
	tasksByChain := make(map[protocol.ChainSelector][]VerificationTask)
	for _, task := range tasks {
		tasksByChain[task.Message.SourceChainSelector] = append(tasksByChain[task.Message.SourceChainSelector], task)
	}

	// Process each chain's tasks as a batch
	for chainSelector, chainTasks := range tasksByChain {
		state, ok := vc.sourceStates[chainSelector]
		if !ok {
			vc.lggr.Errorw("No source state found for finalized messages",
				"chainSelector", chainSelector,
				"taskCount", len(chainTasks))
			continue
		}

		_ = state // currently unused beyond existence check; kept for symmetry

		vc.verifyingWg.Add(1)
		go func(tasks []VerificationTask, chain protocol.ChainSelector) {
			defer vc.verifyingWg.Done()

			errorBatch := vc.verifier.VerifyMessages(ctx, tasks, vc.storageBatcher)
			vc.handleVerificationErrors(ctx, errorBatch, chain, len(tasks))
		}(chainTasks, chainSelector)
	}
}

// handleVerificationErrors processes and logs errors from a verification batch.
func (vc *Coordinator) handleVerificationErrors(ctx context.Context, errorBatch batcher.BatchResult[VerificationError], chainSelector protocol.ChainSelector, totalTasks int) {
	if len(errorBatch.Items) <= 0 {
		vc.lggr.Debugw("Verification batch completed successfully",
			"chainSelector", chainSelector,
			"totalTasks", totalTasks)
		return
	}

	vc.lggr.Infow("Verification batch completed with errors",
		"chainSelector", chainSelector,
		"totalTasks", totalTasks,
		"errorCount", len(errorBatch.Items))

	// Log and record metrics for each error
	for _, verificationError := range errorBatch.Items {
		message := verificationError.Task.Message

		// Record verification error metric
		vc.monitoring.Metrics().
			With("source_chain", message.SourceChainSelector.String(), "dest_chain", message.DestChainSelector.String(), "verifier_id", vc.config.VerifierID).
			IncrementMessagesVerificationFailed(ctx)

		vc.lggr.Errorw("Message verification failed",
			"error", verificationError.Error,
			"messageID", message.MustMessageID(),
			"nonce", message.SequenceNumber,
			"sourceChain", message.SourceChainSelector,
			"destChain", message.DestChainSelector,
			"timestamp", verificationError.Timestamp,
			"chainSelector", chainSelector,
		)
	}
}

// -----------------------------------------------------------------------------
// Curse detector wiring (kept in coordinator as requested)
// -----------------------------------------------------------------------------

// startCurseDetector creates, configures, and starts a curse detector service from RMN readers.
// Uses CursePollInterval from config, defaulting to 2s if not set.
func (vc *Coordinator) startCurseDetector(
	ctx context.Context,
	rmnReaders map[protocol.ChainSelector]chainaccess.RMNCurseReader,
) error {
	if len(rmnReaders) == 0 {
		vc.lggr.Infow("No RMN readers provided; curse detector will not be started")
		return nil
	}

	if vc.curseDetector != nil {
		vc.lggr.Infow("Curse detector already injected; skipping creation from RMN readers")
		return nil
	}

	cursePollInterval := vc.config.CursePollInterval
	if cursePollInterval <= 0 {
		cursePollInterval = 2 * time.Second
	}

	// if a curse detector service is already set, use it; otherwise create a new one
	curseDetectorSvc := vc.curseDetector
	if curseDetectorSvc == nil {
		cd, err := cursecheckerimpl.NewCurseDetectorService(
			rmnReaders,
			vc.config.CursePollInterval,
			vc.lggr,
		)
		if err != nil {
			vc.lggr.Errorw("Failed to create curse detector service", "error", err)
			return fmt.Errorf("failed to create curse detector: %w", err)
		}
		curseDetectorSvc = cd
	}

	if err := curseDetectorSvc.Start(ctx); err != nil {
		vc.lggr.Errorw("Failed to start curse detector", "error", err)
		return fmt.Errorf("failed to start curse detector: %w", err)
	}

	vc.curseDetector = curseDetectorSvc
	vc.lggr.Infow("Curse detector started", "chainCount", len(rmnReaders))

	return nil
}
