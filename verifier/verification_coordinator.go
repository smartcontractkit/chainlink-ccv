package verifier

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"sync/atomic"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/batcher"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/chainaccess"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

const (
	DefaultSourceReaderPollInterval = 2 * time.Second
)

// sourceState manages state for a single source chain reader.
type sourceState struct {
	reader             *SourceReaderService
	verificationTaskCh <-chan batcher.BatchResult[VerificationTask]
	chainSelector      protocol.ChainSelector

	// Reorg detection (per-source)
	reorgDetector   protocol.ReorgDetector
	reorgStatusCh   <-chan protocol.ChainStatus // Receive-only, from detector.Start()
	chainStatus     protocol.ChainStatus
	chainStatusMu   sync.RWMutex
	reorgInProgress atomic.Bool // Set during reorg handling to prevent new tasks from being added

	// Per-chain pending task queue
	pendingTasks []VerificationTask
	pendingMu    sync.RWMutex
}

// Coordinator orchestrates the verification workflow using the new message format with finality awareness.
type Coordinator struct {
	verifier              Verifier
	storage               protocol.CCVNodeDataWriter
	lggr                  logger.Logger
	monitoring            Monitoring
	sourceStates          map[protocol.ChainSelector]*sourceState
	cancel                context.CancelFunc
	config                CoordinatorConfig
	finalityCheckInterval time.Duration
	// Timestamp tracking for E2E latency measurement
	messageTimestamps map[protocol.Bytes32]time.Time
	timestampsMu      sync.RWMutex
	mu                sync.RWMutex
	verifyingWg       sync.WaitGroup // Tracks in-flight verification tasks (must complete before closing error channels)
	backgroundWg      sync.WaitGroup // Tracks background goroutines: run() and finalityCheckingLoop() (must complete after error channels closed)
	running           bool

	// Storage batching
	storageBatcher   *batcher.Batcher[protocol.CCVData]
	batchedCCVDataCh chan batcher.BatchResult[protocol.CCVData]

	// Configuration
	chainStatusManager protocol.ChainStatusManager
	sourceReaders      map[protocol.ChainSelector]SourceReader
	headTrackers       map[protocol.ChainSelector]chainaccess.HeadTracker
	reorgDetectors     map[protocol.ChainSelector]protocol.ReorgDetector
}

// Option is the functional option type for Coordinator.
type Option func(*Coordinator)

// WithVerifier sets the verifier implementation.
func WithVerifier(verifier Verifier) Option {
	return func(vc *Coordinator) {
		vc.verifier = verifier
	}
}

// WithChainStatusManager sets the chain status manager.
func WithChainStatusManager(manager protocol.ChainStatusManager) Option {
	return func(vc *Coordinator) {
		vc.chainStatusManager = manager
	}
}

// WithSourceReaders sets multiple source readers.
func WithSourceReaders(sourceReaders map[protocol.ChainSelector]SourceReader) Option {
	return func(vc *Coordinator) {
		if vc.sourceReaders == nil {
			vc.sourceReaders = make(map[protocol.ChainSelector]SourceReader)
		}

		for chainSelector, reader := range sourceReaders {
			vc.sourceReaders[chainSelector] = reader
		}
	}
}

// AddSourceReader adds a single source reader to the existing map.
func AddSourceReader(chainSelector protocol.ChainSelector, sourceReader SourceReader) Option {
	return WithSourceReaders(map[protocol.ChainSelector]SourceReader{chainSelector: sourceReader})
}

// WithHeadTrackers sets multiple head trackers.
func WithHeadTrackers(headTrackers map[protocol.ChainSelector]chainaccess.HeadTracker) Option {
	return func(vc *Coordinator) {
		if vc.headTrackers == nil {
			vc.headTrackers = make(map[protocol.ChainSelector]chainaccess.HeadTracker)
		}

		for chainSelector, tracker := range headTrackers {
			vc.headTrackers[chainSelector] = tracker
		}
	}
}

// AddHeadTracker adds a single head tracker to the existing map.
func AddHeadTracker(chainSelector protocol.ChainSelector, headTracker chainaccess.HeadTracker) Option {
	return WithHeadTrackers(map[protocol.ChainSelector]chainaccess.HeadTracker{chainSelector: headTracker})
}

// WithStorage sets the storage writer.
func WithStorage(storage protocol.CCVNodeDataWriter) Option {
	return func(vc *Coordinator) {
		vc.storage = storage
	}
}

// WithConfig sets the coordinator configuration.
func WithConfig(config CoordinatorConfig) Option {
	return func(vc *Coordinator) {
		vc.config = config
	}
}

// WithLogger sets the logger.
func WithLogger(lggr logger.Logger) Option {
	return func(vc *Coordinator) {
		vc.lggr = lggr
	}
}

// WithFinalityCheckInterval sets the finality check interval.
func WithFinalityCheckInterval(interval time.Duration) Option {
	return func(vc *Coordinator) {
		vc.finalityCheckInterval = interval
	}
}

// WithMonitoring sets the monitoring implementation.
func WithMonitoring(monitoring Monitoring) Option {
	return func(vc *Coordinator) {
		vc.monitoring = monitoring
	}
}

// WithReorgDetectors sets the reorg detectors for each source chain.
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

// AddReorgDetector adds a single reorg detector for a specific chain.
func AddReorgDetector(chainSelector protocol.ChainSelector, detector protocol.ReorgDetector) Option {
	return WithReorgDetectors(map[protocol.ChainSelector]protocol.ReorgDetector{chainSelector: detector})
}

// NewCoordinator creates a new verification coordinator.
func NewCoordinator(opts ...Option) (*Coordinator, error) {
	vc := &Coordinator{
		sourceStates:          make(map[protocol.ChainSelector]*sourceState),
		messageTimestamps:     make(map[protocol.Bytes32]time.Time),
		finalityCheckInterval: 500 * time.Millisecond, // Default finality check interval
	}

	// Apply all options
	for _, opt := range opts {
		opt(vc)
	}

	// Validate required components
	if err := vc.validate(); err != nil {
		return nil, fmt.Errorf("invalid coordinator configuration: %w", err)
	}

	// Apply defaults to config if not set
	vc.applyConfigDefaults()

	// Initialize source states map (services will be created in Start())
	if vc.sourceStates == nil {
		vc.sourceStates = make(map[protocol.ChainSelector]*sourceState)
	}

	return vc, nil
}

// Start begins the verification coordinator processing.
func (vc *Coordinator) Start(ctx context.Context) error {
	vc.mu.Lock()
	defer vc.mu.Unlock()

	if vc.running {
		return fmt.Errorf("coordinator already running")
	}

	ctx, cancel := context.WithCancel(ctx)
	vc.cancel = cancel

	// Initialize source states with reorg detection
	for chainSelector, sourceReader := range vc.sourceReaders {
		if sourceReader == nil {
			continue
		}

		sourceCfg, ok := vc.config.SourceConfigs[chainSelector]
		if !ok {
			vc.lggr.Warnw("skipping source reader: no source config found for chain selector", "chainSelector", chainSelector)
			continue
		}

		sourcePollInterval := DefaultSourceReaderPollInterval
		if sourceCfg.PollInterval > 0 {
			sourcePollInterval = sourceCfg.PollInterval
		}

		// Get the corresponding HeadTracker for this chain
		headTracker, ok := vc.headTrackers[chainSelector]
		if !ok {
			vc.lggr.Errorw("skipping source reader: no head tracker found for chain selector", "chainSelector", chainSelector)
			continue
		}

		service := NewSourceReaderService(
			sourceReader,
			headTracker,
			chainSelector,
			vc.chainStatusManager,
			vc.lggr,
			sourcePollInterval,
		)

		err := service.Start(ctx)
		if err != nil {
			return fmt.Errorf("failed to start source reader for chain %d: %w", chainSelector, err)
		}
		// Create source state
		state := &sourceState{
			reader:             service,
			chainSelector:      chainSelector,
			verificationTaskCh: service.VerificationTaskChannel(),
		}

		// Setup ReorgDetector (if provided)
		if detector, hasDetector := vc.reorgDetectors[chainSelector]; hasDetector {
			// Start detector (blocks until initial tail is built and subscription is established)
			reorgStatusCh, err := detector.Start(ctx)
			if err != nil {
				vc.lggr.Errorw("Failed to start reorg detector",
					"chainSelector", chainSelector,
					"error", err)
				// TODO: Should we make the reorg detector mandatory to the point we stop the
				// 	reader as I'm doing here?
				_ = service.Stop()
			} else {
				// Store reorg detection components
				state.reorgDetector = detector
				state.reorgStatusCh = reorgStatusCh

				vc.lggr.Infow("Reorg detector started successfully",
					"chainSelector", chainSelector)

				// Spawn processReorgUpdates goroutine
				vc.backgroundWg.Add(1)
				go func(s *sourceState) {
					defer vc.backgroundWg.Done()
					vc.processReorgUpdates(ctx, s)
				}(state)
			}
		} else {
			vc.lggr.Infow("No reorg detector provided for chain, reorg detection disabled", "chainSelector", chainSelector)
		}

		vc.sourceStates[chainSelector] = state
	}

	vc.running = true

	// Initialize storage batcher (will automatically flush when ctx is canceled)
	vc.batchedCCVDataCh = make(chan batcher.BatchResult[protocol.CCVData], 10)
	vc.storageBatcher = batcher.NewBatcher(
		ctx,
		vc.config.StorageBatchSize,
		vc.config.StorageBatchTimeout,
		vc.batchedCCVDataCh,
	)

	// Start processing loop and finality checking
	vc.backgroundWg.Add(1)
	go func() {
		defer vc.backgroundWg.Done()
		vc.run(ctx)
	}()

	vc.backgroundWg.Add(1)
	go func() {
		defer vc.backgroundWg.Done()
		vc.finalityCheckingLoop(ctx)
	}()

	vc.lggr.Infow("Coordinator started with finality checking and reorg detection",
		"coordinatorID", vc.config.VerifierID,
	)

	return nil
}

// Close stops the verification coordinator processing.
func (vc *Coordinator) Close() error {
	vc.mu.Lock()
	if !vc.running {
		vc.mu.Unlock()
		return fmt.Errorf("coordinator not running")
	}
	vc.mu.Unlock()

	// 1. Signal all goroutines to stop processing new work.
	// This will also trigger the batcher to flush remaining items.
	vc.cancel()

	// 2. Wait for any in-flight verification tasks to complete.
	vc.verifyingWg.Wait()

	// 3. Wait for storage batcher goroutine to finish flushing
	if vc.storageBatcher != nil {
		if err := vc.storageBatcher.Close(); err != nil {
			vc.lggr.Errorw("Error closing storage batcher", "error", err)
		}
	}

	// 4. Close reorg detectors
	for chainSelector, state := range vc.sourceStates {
		if state.reorgDetector != nil {
			if err := state.reorgDetector.Close(); err != nil {
				vc.lggr.Errorw("Error closing reorg detector", "error", err, "chainSelector", chainSelector)
			}
		}
	}

	// 5. Close source readers.
	for chainSelector, state := range vc.sourceStates {
		if err := state.reader.Stop(); err != nil {
			vc.lggr.Errorw("Error stopping source reader", "error", err, "chainSelector", chainSelector)
		}
	}

	// 6. Wait for background goroutines (run, finalityCheckingLoop, and processReorgUpdates) to finish.
	vc.backgroundWg.Wait()

	vc.mu.Lock()
	vc.running = false
	vc.mu.Unlock()

	vc.lggr.Infow("Coordinator stopped")

	return nil
}

// run is the main processing loop.
func (vc *Coordinator) run(ctx context.Context) {
	// Start goroutines for each source state
	var wg sync.WaitGroup
	for _, state := range vc.sourceStates {
		wg.Add(1)
		go vc.processSourceMessages(ctx, &wg, state)
	}

	// Main loop - process batched storage writes
	for {
		select {
		case <-ctx.Done():
			vc.lggr.Infow("Context cancelled, stopping coordinator")
			wg.Wait()
			return

		case ccvDataBatch, ok := <-vc.batchedCCVDataCh:
			if !ok {
				vc.lggr.Infow("Storage batcher channel closed")
				wg.Wait()
				return
			}

			// Handle batch-level errors from batcher (should be rare)
			if ccvDataBatch.Error != nil {
				vc.lggr.Errorw("Batch-level error from CCVData batcher",
					"error", ccvDataBatch.Error,
					"errorType", "batcher_failure")
				continue
			}

			// Skip empty batches
			if len(ccvDataBatch.Items) == 0 {
				vc.lggr.Debugw("Received empty CCVData batch")
				continue
			}

			// Write batch of CCVData to offchain storage
			storageStart := time.Now()
			if err := vc.storage.WriteCCVNodeData(ctx, ccvDataBatch.Items); err != nil {
				vc.monitoring.Metrics().IncrementStorageWriteErrors(ctx)
				vc.lggr.Errorw("Error storing CCV data batch",
					"error", err,
					"batchSize", len(ccvDataBatch.Items),
				)
				// Log individual messageIDs in failed batch
				for _, ccvData := range ccvDataBatch.Items {
					vc.lggr.Errorw("Failed to store CCV data in batch",
						"messageID", ccvData.MessageID,
						"nonce", ccvData.Nonce,
						"sourceChain", ccvData.SourceChainSelector,
					)
				}
			} else {
				storageDuration := time.Since(storageStart)

				// Record storage write duration
				vc.monitoring.Metrics().
					With("verifier_id", vc.config.VerifierID).
					RecordStorageWriteDuration(ctx, storageDuration)

				// Calculate and record E2E latency for each message in the batch
				vc.timestampsMu.Lock()
				for _, ccvData := range ccvDataBatch.Items {
					if createdAt, exists := vc.messageTimestamps[ccvData.MessageID]; exists {
						e2eDuration := time.Since(createdAt)
						vc.monitoring.Metrics().
							With("source_chain", ccvData.SourceChainSelector.String(), "verifier_id", vc.config.VerifierID).
							RecordMessageE2ELatency(ctx, e2eDuration)

						// Clean up timestamp entry
						delete(vc.messageTimestamps, ccvData.MessageID)
					}
				}
				vc.timestampsMu.Unlock()

				vc.lggr.Infow("CCV data batch stored successfully",
					"batchSize", len(ccvDataBatch.Items),
				)
			}
		}
	}
}

// processSourceMessages handles message processing for a single source state.
func (vc *Coordinator) processSourceMessages(ctx context.Context, wg *sync.WaitGroup, state *sourceState) {
	defer wg.Done()
	chainSelector := state.chainSelector

	vc.lggr.Debugw("Starting source message processor", "chainSelector", chainSelector)
	defer vc.lggr.Debugw("Source message processor stopped", "chainSelector", chainSelector)

	for {
		select {
		case <-ctx.Done():
			vc.lggr.Debugw("Source message processor stopped due to context cancellation", "chainSelector", chainSelector)
			return

		case taskBatch, ok := <-state.verificationTaskCh:
			if !ok {
				vc.lggr.Debugw("Message channel closed for source", "chainSelector", chainSelector)
				return
			}

			// Handle batch-level errors (RPC failures, log query errors, etc.)
			if taskBatch.Error != nil {
				vc.lggr.Errorw("Batch-level error from source reader - skipping cycle",
					"chainSelector", chainSelector,
					"error", taskBatch.Error,
					"errorType", "source_read_failure")
				// Batch-level errors indicate infrastructure/chain issues
				// The source reader will retry on next cycle
				continue
			}

			// Skip empty batches
			if len(taskBatch.Items) == 0 {
				vc.lggr.Debugw("Received empty batch from source reader",
					"chainSelector", chainSelector)
				continue
			}

			// Drop tasks if reorg is in progress for this chain
			if state.reorgInProgress.Load() {
				vc.lggr.Warnw("Dropping task batch due to ongoing reorg",
					"chainSelector", chainSelector,
					"droppedCount", len(taskBatch.Items))
				continue
			}

			// Process all tasks in the batch
			vc.lggr.Debugw("Received verification task batch",
				"chainSelector", chainSelector,
				"batchSize", len(taskBatch.Items))

			for _, verificationTask := range taskBatch.Items {
				// Add to pending queue for finality checking
				vc.addToPendingQueue(verificationTask, state)
			}
		}
	}
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

	// Default storage batch timeout: 100ms
	if vc.config.StorageBatchTimeout <= 0 {
		vc.config.StorageBatchTimeout = 100 * time.Millisecond
		if vc.lggr != nil {
			vc.lggr.Debugw("Using default StorageBatchTimeout", "value", vc.config.StorageBatchTimeout)
		}
	}
}

// validate checks that all required components are configured.
func (vc *Coordinator) validate() error {
	var errs []error
	appendIfNil := func(field any, fieldName string) {
		if field == nil {
			errs = append(errs, fmt.Errorf("%s is not set", fieldName))
		}
	}

	appendIfNil(vc.verifier, "verifier")
	appendIfNil(vc.storage, "storage")
	appendIfNil(vc.lggr, "logger")
	appendIfNil(vc.monitoring, "monitoring")
	// chain statusManager is optional, not required

	if len(vc.sourceReaders) == 0 {
		errs = append(errs, fmt.Errorf("at least one source reader is required"))
	}

	// Validate that all configured sources have corresponding readers
	for chainSelector := range vc.config.SourceConfigs {
		if _, exists := vc.sourceReaders[chainSelector]; !exists {
			errs = append(errs, fmt.Errorf("source reader not found for chain selector %d", chainSelector))
		}
	}

	if vc.config.VerifierID == "" {
		errs = append(errs, fmt.Errorf("coordinator ID cannot be empty"))
	}

	return errors.Join(errs...)
}

// Ready returns nil if the coordinator is ready, or an error otherwise.
func (vc *Coordinator) Ready() error {
	vc.mu.RLock()
	defer vc.mu.RUnlock()

	if !vc.running {
		return errors.New("coordinator not running")
	}

	return nil
}

// HealthReport returns a full health report of the coordinator and its dependencies.
func (vc *Coordinator) HealthReport() map[string]error {
	vc.mu.RLock()
	defer vc.mu.RUnlock()

	report := make(map[string]error)
	report[vc.Name()] = vc.Ready()

	return report
}

// Name returns the fully qualified name of the coordinator.
func (vc *Coordinator) Name() string {
	return fmt.Sprintf("verifier.Coordinator[%s]", vc.config.VerifierID)
}

// addToPendingQueue adds a verification task to the per-chain pending queue for finality checking.
func (vc *Coordinator) addToPendingQueue(task VerificationTask, state *sourceState) {
	state.pendingMu.Lock()
	defer state.pendingMu.Unlock()

	// Double-checked locking: Check if reorg started while we were waiting for lock
	// The caller already checked reorgInProgress before calling, but reorg may have
	// started between that check and acquiring this lock
	if state.reorgInProgress.Load() {
		vc.lggr.Debugw("Reorg started while acquiring lock, dropping task",
			"chain", state.chainSelector,
			"blockNumber", task.BlockNumber)
		return
	}

	// Set QueuedAt timestamp for finality wait duration tracking
	task.QueuedAt = time.Now()
	state.pendingTasks = append(state.pendingTasks, task)

	messageID, err := task.Message.MessageID()
	if err != nil {
		vc.lggr.Errorw("Failed to compute message ID for queuing", "error", err)
		return
	}

	// Track message creation time for E2E latency measurement
	vc.timestampsMu.Lock()
	if task.CreatedAt.IsZero() {
		// If CreatedAt was not set by source reader, set it now
		task.CreatedAt = time.Now()
	}
	vc.messageTimestamps[messageID] = task.CreatedAt
	vc.timestampsMu.Unlock()

	vc.lggr.Infow("Message added to finality queue",
		"messageID", messageID,
		"chainSelector", state.chainSelector,
		"blockNumber", task.BlockNumber,
		"nonce", task.Message.Nonce,
		"queueSize", len(state.pendingTasks),
	)
}

// finalityCheckingLoop runs the finality checking loop for all chains.
func (vc *Coordinator) finalityCheckingLoop(ctx context.Context) {
	ticker := time.NewTicker(vc.finalityCheckInterval)
	defer ticker.Stop()

	cleanupTicker := time.NewTicker(5 * time.Minute)
	defer cleanupTicker.Stop()

	vc.lggr.Infow("🔄 Starting finality checking loop")

	for {
		select {
		case <-ctx.Done():
			vc.lggr.Infow("🛑 Finality checking stopped due to context cancellation")
			return
		case <-ticker.C:
			// Process finality for each chain independently
			for _, state := range vc.sourceStates {
				vc.processFinalityQueueForChain(ctx, state)
			}
		case <-cleanupTicker.C:
			vc.cleanupOldTimestamps()
		}
	}
}

// cleanupOldTimestamps removes stale message timestamps older than 1 hour.
func (vc *Coordinator) cleanupOldTimestamps() {
	vc.timestampsMu.Lock()
	defer vc.timestampsMu.Unlock()

	cutoff := time.Now().Add(-1 * time.Hour)
	for msgID, createdAt := range vc.messageTimestamps {
		if createdAt.Before(cutoff) {
			delete(vc.messageTimestamps, msgID)
			vc.lggr.Warnw("Cleaned up stale message timestamp",
				"messageID", msgID,
				"age", time.Since(createdAt))
		}
	}
}

// processFinalityQueueForChain processes the pending queue for a single chain.
func (vc *Coordinator) processFinalityQueueForChain(ctx context.Context, state *sourceState) {
	// Fast path: Skip if reorg is in progress (avoids lock contention)
	if state.reorgInProgress.Load() {
		vc.lggr.Debugw("Skipping finality check during reorg",
			"chain", state.chainSelector)
		return
	}

	state.pendingMu.Lock()
	defer state.pendingMu.Unlock()

	// Double-checked locking: Recheck after acquiring lock to handle TOCTOU race
	// where reorg completed between first check and lock acquisition
	if state.reorgInProgress.Load() {
		vc.lggr.Debugw("Reorg started while acquiring lock, aborting finality check",
			"chain", state.chainSelector)
		return
	}

	if len(state.pendingTasks) == 0 {
		return
	}

	chainSelector := state.chainSelector

	// Record queue size metric
	vc.monitoring.Metrics().
		With("source_chain", chainSelector.String(), "verifier_id", vc.config.VerifierID).
		RecordFinalityQueueSize(ctx, int64(len(state.pendingTasks)))

	var readyTasks []VerificationTask
	var remainingTasks []VerificationTask

	// Get latest and finalized block headers for this chain
	latest, finalized, err := state.reader.LatestAndFinalizedBlock(ctx)
	if err != nil {
		vc.lggr.Errorw("Failed to get latest and finalized blocks", "error", err, "chain", chainSelector)
		return
	}
	if latest == nil || finalized == nil {
		vc.lggr.Errorw("Received nil block headers", "chain", chainSelector)
		return
	}

	latestBlock := new(big.Int).SetUint64(latest.Number)
	latestFinalizedBlock := new(big.Int).SetUint64(finalized.Number)

	// Record chain state metrics
	vc.monitoring.Metrics().
		With("source_chain", chainSelector.String(), "verifier_id", vc.config.VerifierID).
		RecordSourceChainLatestBlock(ctx, latestBlock.Int64())
	vc.monitoring.Metrics().
		With("source_chain", chainSelector.String(), "verifier_id", vc.config.VerifierID).
		RecordSourceChainFinalizedBlock(ctx, latestFinalizedBlock.Int64())

	// Check finality for each task
	for _, task := range state.pendingTasks {
		ready, err := vc.isMessageReadyForVerification(task, latestBlock, latestFinalizedBlock)
		if err != nil {
			messageID, _ := task.Message.MessageID()
			vc.lggr.Warnw("Failed to check finality for message",
				"messageID", messageID,
				"error", err,
				"chain", chainSelector)
			// Keep in queue to retry later
			remainingTasks = append(remainingTasks, task)
			continue
		}

		if ready {
			readyTasks = append(readyTasks, task)
		} else {
			remainingTasks = append(remainingTasks, task)
		}
	}

	// Update the pending queue for this chain
	state.pendingTasks = remainingTasks

	if len(readyTasks) > 0 {
		vc.lggr.Infow("✅ Processing finalized messages",
			"chain", chainSelector,
			"readyCount", len(readyTasks),
			"remainingCount", len(remainingTasks),
		)

		// Process ready tasks with verifier
		vc.processReadyTasks(ctx, readyTasks)
	}
}

// processReadyTasks processes a batch of tasks that have met their finality requirements.
func (vc *Coordinator) processReadyTasks(ctx context.Context, tasks []VerificationTask) {
	if len(tasks) == 0 {
		return
	}

	vc.lggr.Debugw("Processing batch of finalized messages", "batchSize", len(tasks))

	// Record finality wait duration for each task
	for _, task := range tasks {
		if !task.QueuedAt.IsZero() && vc.monitoring != nil {
			finalityWaitDuration := time.Since(task.QueuedAt)
			vc.monitoring.Metrics().
				With("source_chain", task.Message.SourceChainSelector.String(), "verifier_id", vc.config.VerifierID).
				RecordFinalityWaitDuration(ctx, finalityWaitDuration)
		}
	}

	// Group tasks by source chain for better logging/organization
	tasksByChain := make(map[protocol.ChainSelector][]VerificationTask)
	for _, task := range tasks {
		tasksByChain[task.Message.SourceChainSelector] = append(tasksByChain[task.Message.SourceChainSelector], task)
	}

	// Process each chain's tasks as a batch
	for chainSelector, chainTasks := range tasksByChain {
		state, exists := vc.sourceStates[chainSelector]
		if !exists {
			vc.lggr.Errorw("No source state found for finalized messages",
				"chainSelector", chainSelector,
				"taskCount", len(chainTasks))
			continue
		}

		// Check chain status before processing
		state.chainStatusMu.RLock()
		isFinalityViolated := state.chainStatus.Type == protocol.ReorgTypeFinalityViolation
		state.chainStatusMu.RUnlock()

		if isFinalityViolated {
			vc.lggr.Warnw("Skipping message processing due to finality violation",
				"chain", chainSelector,
				"taskCount", len(chainTasks))
			// TODO: Record dropped messages metric - this method needs to be added to monitoring interface
			// vc.monitoring.Metrics().With("source_chain", chainSelector.String(), "verifier_id", vc.config.VerifierID).AddMessagesDroppedDueToFinalityViolation(ctx, int64(len(chainTasks)))
			continue
		}

		// Process the batch of tasks for this chain
		vc.verifyingWg.Add(1)
		go func(tasks []VerificationTask, chain protocol.ChainSelector) {
			defer vc.verifyingWg.Done()

			// Call verifier and get error batch
			errorBatch := vc.verifier.VerifyMessages(ctx, tasks, vc.storageBatcher)

			// Process errors from the batch
			vc.handleVerificationErrors(ctx, errorBatch, chain, len(tasks))
		}(chainTasks, chainSelector)
	}
}

// handleVerificationErrors processes and logs errors from a verification batch.
func (vc *Coordinator) handleVerificationErrors(ctx context.Context, errorBatch batcher.BatchResult[VerificationError], chainSelector protocol.ChainSelector, totalTasks int) {
	if len(errorBatch.Items) > 0 {
		vc.lggr.Infow("Verification batch completed with errors",
			"chainSelector", chainSelector,
			"totalTasks", totalTasks,
			"errorCount", len(errorBatch.Items))

		// Log and record metrics for each error
		for _, verificationError := range errorBatch.Items {
			message := verificationError.Task.Message
			messageID, err := message.MessageID()
			if err != nil {
				vc.lggr.Errorw("Failed to compute message ID for error logging", "error", err)
				messageID = protocol.Bytes32{} // Use empty message ID as fallback
			}

			// Record verification error metric
			vc.monitoring.Metrics().
				With("source_chain", message.SourceChainSelector.String(), "dest_chain", message.DestChainSelector.String(), "verifier_id", vc.config.VerifierID).
				IncrementMessagesVerificationFailed(ctx)

			vc.lggr.Errorw("Message verification failed",
				"error", verificationError.Error,
				"messageID", messageID,
				"nonce", message.Nonce,
				"sourceChain", message.SourceChainSelector,
				"destChain", message.DestChainSelector,
				"timestamp", verificationError.Timestamp,
				"chainSelector", chainSelector,
			)
		}
	} else {
		vc.lggr.Debugw("Verification batch completed successfully",
			"chainSelector", chainSelector,
			"taskCount", totalTasks)
	}
}

// processReorgUpdates handles reorg status updates from the reorg detector.
func (vc *Coordinator) processReorgUpdates(ctx context.Context, state *sourceState) {
	for {
		select {
		case <-ctx.Done():
			vc.lggr.Debugw("Reorg updates processor stopped", "chain", state.chainSelector)
			return
		case newStatus := <-state.reorgStatusCh:
			// Update chain status
			state.chainStatusMu.Lock()
			state.chainStatus = newStatus
			state.chainStatusMu.Unlock()

			// Handle based on type (only receive problem events)
			switch newStatus.Type {
			case protocol.ReorgTypeNormal:
				vc.handleReorg(ctx, state, newStatus)

			case protocol.ReorgTypeFinalityViolation:
				vc.handleFinalityViolation(ctx, state, newStatus)

			default:
				vc.lggr.Warnw("Received unknown chain status type",
					"chain", state.chainSelector,
					"statusType", newStatus.Type)
			}
		}
	}
}

// handleReorg handles a regular reorg event.
// Sets reorgInProgress flag to prevent new tasks from being added during handling.
func (vc *Coordinator) handleReorg(
	ctx context.Context,
	state *sourceState,
	reorgStatus protocol.ChainStatus,
) {
	chainSelector := state.chainSelector
	commonAncestor := reorgStatus.ResetToBlock

	// Set reorgInProgress flag to stop new tasks from being added
	state.reorgInProgress.Store(true)
	defer state.reorgInProgress.Store(false)

	vc.lggr.Infow("Handling reorg",
		"chain", chainSelector,
		"type", reorgStatus.Type.String(),
		"commonAncestor", commonAncestor)

	// 1. Flush pending tasks from reorged blocks (per-chain queue)
	state.pendingMu.Lock()
	remaining := make([]VerificationTask, 0, len(state.pendingTasks))
	flushedCount := 0
	for _, task := range state.pendingTasks {
		if task.BlockNumber > commonAncestor {
			flushedCount++
			continue
		}
		remaining = append(remaining, task)
	}
	state.pendingTasks = remaining
	state.pendingMu.Unlock()

	// 2. Reset SourceReaderService synchronously
	// Note: For regular reorgs, the common ancestor is always >= last chain status,
	// so ResetToBlock will update in-memory position without writing chain status.
	// Periodic chain status chain statuses will naturally advance from this point.
	resetCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	if err := state.reader.ResetToBlock(resetCtx, commonAncestor); err != nil {
		vc.lggr.Errorw("Failed to reset source reader after reorg",
			"error", err,
			"chain", chainSelector,
			"resetBlock", commonAncestor)
		// Log error but continue - source reader will retry on next cycle
	} else {
		vc.lggr.Infow("Source reader reset successfully",
			"chain", chainSelector,
			"resetBlock", commonAncestor)
	}

	vc.lggr.Infow("Reorg handled successfully",
		"chain", chainSelector,
		"commonAncestor", commonAncestor,
		"flushedTasks", flushedCount)

	// TODO: Record metrics - these methods need to be added to the monitoring interface
	// vc.monitoring.Metrics().With("source_chain", chainSelector.String(), "verifier_id", vc.config.VerifierID).IncrementReorgDetected(ctx)
	// vc.monitoring.Metrics().With("source_chain", chainSelector.String(), "verifier_id", vc.config.VerifierID).RecordReorgDepth(ctx, int64(depth))
	// vc.monitoring.Metrics().With("source_chain", chainSelector.String(), "verifier_id", vc.config.VerifierID).AddTasksFlushedDueToReorg(ctx, int64(flushedCount))
}

// handleFinalityViolation handles a finality violation event.
// Finality violations indicate the chain's security model is broken.
// We immediately stop the reader and require manual intervention - no safe reset point exists.
func (vc *Coordinator) handleFinalityViolation(
	ctx context.Context,
	state *sourceState,
	violationStatus protocol.ChainStatus,
) {
	chainSelector := state.chainSelector

	vc.lggr.Errorw("FINALITY VIOLATION DETECTED - stopping chain reader immediately",
		"chain", chainSelector,
		"type", violationStatus.Type.String())

	// 1. Flush ALL pending tasks for this chain (per-chain queue)
	state.pendingMu.Lock()
	flushedCount := len(state.pendingTasks)
	state.pendingTasks = nil // Clear entire queue
	state.pendingMu.Unlock()

	vc.lggr.Warnw("Flushed all tasks due to finality violation",
		"chain", chainSelector,
		"flushedCount", flushedCount)

	// Stop SourceReaderService immediately
	// No reset - finality violation means there's no safe block to reset to
	if err := state.reader.Stop(); err != nil {
		vc.lggr.Errorw("Failed to stop source reader after finality violation",
			"error", err,
			"chain", chainSelector)
	} else {
		vc.lggr.Errorw("Source reader stopped due to finality violation - manual intervention required",
			"chain", chainSelector)
	}
	// TODO: Use Pause() instead of Stop() when implemented (separate PR)

	// TODO: These methods need to be added to the monitoring interface
	// vc.monitoring.Metrics().With("source_chain", chainSelector.String(), "verifier_id", vc.config.VerifierID).IncrementFinalityViolation(ctx)
	// vc.monitoring.Metrics().With("source_chain", chainSelector.String(), "verifier_id", vc.config.VerifierID).AddTasksFlushedDueToReorg(ctx, int64(flushedCount))
}

// isMessageReadyForVerification determines if a message meets its finality requirements.
// This implements the same logic as Python's commit_verifier.py finality checking.
func (vc *Coordinator) isMessageReadyForVerification(
	task VerificationTask,
	latestBlock *big.Int,
	latestFinalizedBlock *big.Int,
) (bool, error) {
	messageID, err := task.Message.MessageID()
	if err != nil {
		return false, fmt.Errorf("failed to compute message ID: %w", err)
	}

	// Parse extra args to get finality configuration
	finalityConfig := task.Message.Finality

	messageBlockNumber := new(big.Int).SetUint64(task.BlockNumber)

	ready := false
	if finalityConfig == 0 {
		// Default finality: wait for chain finalization
		ready = messageBlockNumber.Cmp(latestFinalizedBlock) <= 0
		if ready {
			vc.lggr.Debugw("✅ Message meets default finality requirement",
				"messageID", messageID,
				"messageBlock", messageBlockNumber.String(),
				"finalizedBlock", latestFinalizedBlock.String(),
			)
		}
	} else {
		// Custom finality: message_block + finality_config <= latest_block
		requiredBlock := new(big.Int).Add(messageBlockNumber, new(big.Int).SetUint64(uint64(finalityConfig)))
		ready = requiredBlock.Cmp(latestBlock) <= 0
		if ready {
			vc.lggr.Debugw("✅ Message meets custom finality requirement",
				"messageID", messageID,
				"messageBlock", messageBlockNumber.String(),
				"finalityConfig", finalityConfig,
				"requiredBlock", requiredBlock.String(),
				"latestBlock", latestBlock.String(),
			)
		}
	}
	return ready, nil
}
