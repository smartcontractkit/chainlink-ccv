package verifier

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/batcher"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/common"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// sourceState manages state for a single source chain reader.
type sourceState struct {
	reader              *SourceReaderService
	verificationTaskCh  <-chan batcher.BatchResult[VerificationTask]
	verificationErrorCh chan VerificationError
	chainSelector       protocol.ChainSelector
}

// Coordinator orchestrates the verification workflow using the new message format with finality awareness.
type Coordinator struct {
	verifier                 Verifier
	storage                  protocol.CCVNodeDataWriter
	lggr                     logger.Logger
	monitoring               common.VerifierMonitoring
	sourceStates             map[protocol.ChainSelector]*sourceState
	cancel                   context.CancelFunc
	ccvDataCh                chan protocol.CCVData
	pendingTasks             []VerificationTask
	config                   CoordinatorConfig
	finalityCheckInterval    time.Duration
	sourceReaderPollInterval time.Duration
	// Timestamp tracking for E2E latency measurement
	messageTimestamps map[protocol.Bytes32]time.Time
	timestampsMu      sync.RWMutex
	mu                sync.RWMutex
	pendingMu         sync.RWMutex
	verifyingWg       sync.WaitGroup // Tracks in-flight verification tasks (must complete before closing error channels)
	backgroundWg      sync.WaitGroup // Tracks background goroutines: run() and finalityCheckingLoop() (must complete after error channels closed)
	running           bool

	// Storage batching
	storageBatcher      *batcher.Batcher[protocol.CCVData]
	batchedCCVDataCh    chan batcher.BatchResult[protocol.CCVData]
	storageBatcherWg    sync.WaitGroup
	storageBatcherClose func() // Function to close the batcher

	// Configuration
	checkpointManager protocol.CheckpointManager
	sourceReaders     map[protocol.ChainSelector]SourceReader
}

// Option is the functional option type for Coordinator.
type Option func(*Coordinator)

// WithVerifier sets the verifier implementation.
func WithVerifier(verifier Verifier) Option {
	return func(vc *Coordinator) {
		vc.verifier = verifier
	}
}

// WithCheckpointManager sets the checkpoint manager.
func WithCheckpointManager(manager protocol.CheckpointManager) Option {
	return func(vc *Coordinator) {
		vc.checkpointManager = manager
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

// WithSourceReaderPollInterval sets the poll interval for source reader services (useful for testing).
func WithSourceReaderPollInterval(interval time.Duration) Option {
	return func(vc *Coordinator) {
		vc.sourceReaderPollInterval = interval
	}
}

// WithMonitoring sets the monitoring implementation.
func WithMonitoring(monitoring common.VerifierMonitoring) Option {
	return func(vc *Coordinator) {
		vc.monitoring = monitoring
	}
}

// NewVerificationCoordinator creates a new verification coordinator.
func NewVerificationCoordinator(opts ...Option) (*Coordinator, error) {
	vc := &Coordinator{
		// TODO: channels should have a buffer of 0 or 1, why is it 1000?
		ccvDataCh:             make(chan protocol.CCVData, 1000),
		sourceStates:          make(map[protocol.ChainSelector]*sourceState),
		pendingTasks:          make([]VerificationTask, 0),
		messageTimestamps:     make(map[protocol.Bytes32]time.Time),
		finalityCheckInterval: 3 * time.Second, // Default finality check interval
	}

	// Apply all options
	for _, opt := range opts {
		opt(vc)
	}

	// Validate required components
	if err := vc.validate(); err != nil {
		return nil, fmt.Errorf("invalid coordinator configuration: %w", err)
	}

	// Initialize source states from provided source readers and configuration.
	if vc.sourceStates == nil {
		vc.sourceStates = make(map[protocol.ChainSelector]*sourceState)
	}
	for chainSelector, sourceReader := range vc.sourceReaders {
		if sourceReader != nil {
			if _, ok := vc.config.SourceConfigs[chainSelector]; !ok {
				vc.lggr.Warnw("skipping source reader: no source config found for chain selector %d", chainSelector)
				continue
			}

			// Build service options
			var serviceOpts []SourceReaderServiceOption
			if vc.sourceReaderPollInterval > 0 {
				serviceOpts = append(serviceOpts, WithPollInterval(vc.sourceReaderPollInterval))
			}

			service := NewSourceReaderService(sourceReader, chainSelector, vc.checkpointManager, vc.lggr, serviceOpts...)
			vc.sourceStates[chainSelector] = &sourceState{
				chainSelector:      chainSelector,
				reader:             service,
				verificationTaskCh: service.VerificationTaskChannel(),
				// TODO: channels should have a buffer of 0 or 1, why is it 100?
				verificationErrorCh: make(chan VerificationError, 100), // Buffered error channel
			}
		}
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

	// Start all source readers
	for chainSelector, state := range vc.sourceStates {
		if err := state.reader.Start(ctx); err != nil {
			return fmt.Errorf("failed to start source reader for chain %d: %w", chainSelector, err)
		}
	}

	vc.running = true

	ctx, cancel := context.WithCancel(ctx)
	vc.cancel = cancel

	// Initialize storage batcher
	vc.batchedCCVDataCh = make(chan batcher.BatchResult[protocol.CCVData], 10)
	vc.storageBatcher = batcher.NewBatcher(
		ctx,
		vc.config.StorageBatchSize,
		vc.config.StorageBatchTimeout,
		vc.batchedCCVDataCh,
	)
	vc.storageBatcherClose = func() {
		if err := vc.storageBatcher.Close(); err != nil {
			vc.lggr.Errorw("Error closing storage batcher", "error", err)
		}
	}

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

	vc.lggr.Infow("Coordinator started with finality checking",
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
	vc.cancel()

	// 2. Wait for any in-flight verification tasks to complete.
	// These are the tasks that might write to verificationErrorCh.
	vc.verifyingWg.Wait()

	// Close the storage batcher to flush remaining items
	if vc.storageBatcherClose != nil {
		vc.storageBatcherClose()
	}

	// 3. Close source readers and close error channels.
	for chainSelector, state := range vc.sourceStates {
		if err := state.reader.Stop(); err != nil {
			vc.lggr.Errorw("Error stopping source reader", "error", err, "chainSelector", chainSelector)
		}
		// Now it is safe to close the error channel, as there are no more writers.
		// This will also signal processSourceErrors to stop.
		close(state.verificationErrorCh)
	}

	// 4. Wait for background goroutines (run and finalityCheckingLoop) to finish.
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

		// Start error processing goroutine for each source
		wg.Add(1)
		go vc.processSourceErrors(ctx, &wg, state)
	}

	// Ticker for periodic channel size sampling
	channelSizeTicker := time.NewTicker(10 * time.Second)
	defer channelSizeTicker.Stop()

	// Main loop - focus solely on ccvDataCh processing and storage
	for {
		select {
		case <-ctx.Done():
			vc.lggr.Infow("Coordinator processing stopped due to context cancellation")
			wg.Wait()
			return
		case ccvData, ok := <-vc.ccvDataCh:
			if !ok {
				vc.lggr.Infow("CCVData channel closed, stopping processing")
				wg.Wait()
				return
			}

			// Add CCVData to batcher for batched storage writes
			if err := vc.storageBatcher.Add(ccvData); err != nil {
				vc.lggr.Errorw("Error adding CCV data to batcher",
					"error", err,
					"messageID", ccvData.MessageID,
					"nonce", ccvData.Nonce,
					"sourceChain", ccvData.SourceChainSelector,
				)
			}

		case ccvDataBatch, ok := <-vc.batchedCCVDataCh:
			if !ok {
				vc.lggr.Infow("Batched CCVData channel closed, stopping processing")
				wg.Wait()
				return
			}

			// Handle batch error if present
			if ccvDataBatch.Error != nil {
				vc.lggr.Errorw("Error in CCVData batch", "error", ccvDataBatch.Error)
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

		case <-channelSizeTicker.C:
			// Periodic channel size sampling for monitoring
			vc.monitoring.Metrics().
				With("verifier_id", vc.config.VerifierID).
				RecordCCVDataChannelSize(ctx, int64(len(vc.ccvDataCh)))
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
				vc.lggr.Errorw("Message channel closed for source", "chainSelector", chainSelector)
				return
			}

			// Handle batch error if present
			if taskBatch.Error != nil {
				vc.lggr.Errorw("Error in verification task batch",
					"chainSelector", chainSelector,
					"error", taskBatch.Error)
				continue
			}

			// Process all tasks in the batch
			vc.lggr.Debugw("Received verification task batch",
				"chainSelector", chainSelector,
				"batchSize", len(taskBatch.Items))

			for _, verificationTask := range taskBatch.Items {
				// Add to pending queue for finality checking
				vc.addToPendingQueue(verificationTask, chainSelector)
			}
		}
	}
}

// processSourceErrors handles error processing for a single source state.
func (vc *Coordinator) processSourceErrors(ctx context.Context, wg *sync.WaitGroup, state *sourceState) {
	defer wg.Done()
	chainSelector := state.chainSelector

	vc.lggr.Debugw("Starting source error processor", "chainSelector", chainSelector)
	defer vc.lggr.Debugw("Source error processor stopped", "chainSelector", chainSelector)

	for {
		select {
		case <-ctx.Done():
			vc.lggr.Debugw("Source error processor stopped due to context cancellation", "chainSelector", chainSelector)
			return
		case verificationError, ok := <-state.verificationErrorCh:
			if !ok {
				vc.lggr.Infow("Verification error channel closed for source", "chainSelector", chainSelector)
				return
			}

			// Handle verification errors for this specific source
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

			vc.lggr.Errorw("Verification error received",
				"error", verificationError.Error,
				"messageID", messageID,
				"nonce", message.Nonce,
				"sourceChain", message.SourceChainSelector,
				"destChain", message.DestChainSelector,
				"timestamp", verificationError.Timestamp,
				"chainSelector", chainSelector,
			)
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
	// checkpointManager is optional, not required

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

// addToPendingQueue adds a verification task to the pending queue for finality checking.
func (vc *Coordinator) addToPendingQueue(task VerificationTask, chainSelector protocol.ChainSelector) {
	vc.pendingMu.Lock()
	defer vc.pendingMu.Unlock()

	// Set QueuedAt timestamp for finality wait duration tracking
	task.QueuedAt = time.Now()
	vc.pendingTasks = append(vc.pendingTasks, task)

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

	vc.lggr.Infow("📋 Message added to finality queue",
		"messageID", messageID,
		"chainSelector", chainSelector,
		"blockNumber", task.BlockNumber,
		"nonce", task.Message.Nonce,
		"queueSize", len(vc.pendingTasks),
	)
}

// finalityCheckingLoop runs the finality checking loop similar to Python's _check_finalization_periodically.
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
			vc.processFinalityQueue(ctx)
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

// processFinalityQueue processes the pending queue and verifies ready messages.
func (vc *Coordinator) processFinalityQueue(ctx context.Context) {
	vc.pendingMu.Lock()
	defer vc.pendingMu.Unlock()

	if len(vc.pendingTasks) == 0 {
		return
	}

	vc.monitoring.Metrics().
		With("verifier_id", vc.config.VerifierID).
		RecordFinalityQueueSize(ctx, int64(len(vc.pendingTasks)))

	var readyTasks []VerificationTask
	var remainingTasks []VerificationTask

	// Get latest blocks and finalized blocks for all chains
	latestBlocks := make(map[protocol.ChainSelector]*big.Int)
	for chainSelector, state := range vc.sourceStates {
		latestBlock, err := state.reader.GetSourceReader().LatestBlockHeight(ctx)
		if err != nil {
			vc.lggr.Errorw("Failed to get latest block", "error", err)
			continue
		}
		latestBlocks[chainSelector] = latestBlock

		// Record chain state metric
		vc.monitoring.Metrics().
			With("source_chain", chainSelector.String(), "verifier_id", vc.config.VerifierID).
			RecordSourceChainLatestBlock(ctx, latestBlock.Int64())
	}
	latestFinalizedBlocks := make(map[protocol.ChainSelector]*big.Int)
	for chainSelector, state := range vc.sourceStates {
		latestFinalizedBlock, err := state.reader.GetSourceReader().LatestFinalizedBlockHeight(ctx)
		if err != nil {
			vc.lggr.Errorw("Failed to get latest finalized block", "error", err)
			continue
		}
		latestFinalizedBlocks[chainSelector] = latestFinalizedBlock

		// Record chain state metric
		vc.monitoring.Metrics().
			With("source_chain", chainSelector.String(), "verifier_id", vc.config.VerifierID).
			RecordSourceChainFinalizedBlock(ctx, latestFinalizedBlock.Int64())
	}

	for _, task := range vc.pendingTasks {
		ready, err := vc.isMessageReadyForVerification(task, latestBlocks, latestFinalizedBlocks)
		if err != nil {
			messageID, _ := task.Message.MessageID()
			vc.lggr.Warnw("Failed to check finality for message",
				"messageID", messageID,
				"error", err)
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

	// Update the pending queue
	vc.pendingTasks = remainingTasks

	if len(readyTasks) > 0 {
		vc.lggr.Infow("✅ Processing finalized messages",
			"readyCount", len(readyTasks),
			"remainingCount", len(remainingTasks),
		)

		// Process ready tasks with verifier
		for _, task := range readyTasks {
			vc.processReadyTask(ctx, task)
		}
	}
}

// processReadyTask processes a task that has met its finality requirements.
func (vc *Coordinator) processReadyTask(ctx context.Context, task VerificationTask) {
	messageID, err := task.Message.MessageID()
	if err != nil {
		vc.lggr.Errorw("Failed to compute message ID for ready task", "error", err)
		return
	}

	// Record finality wait duration
	if !task.QueuedAt.IsZero() && vc.monitoring != nil {
		finalityWaitDuration := time.Since(task.QueuedAt)
		vc.monitoring.Metrics().
			With("source_chain", task.Message.SourceChainSelector.String(), "verifier_id", vc.config.VerifierID).
			RecordFinalityWaitDuration(ctx, finalityWaitDuration)
	}

	vc.lggr.Debugw("📤 Processing finalized message",
		"messageID", messageID,
		"blockNumber", task.BlockNumber,
		"nonce", task.Message.Nonce,
	)

	// Find the appropriate error channel for this chain
	sourceState, exists := vc.sourceStates[task.Message.SourceChainSelector]
	if !exists {
		vc.lggr.Errorw("No source state found for finalized message",
			"chainSelector", task.Message.SourceChainSelector)
		return
	}

	// Process message event using the verifier asynchronously
	vc.verifyingWg.Add(1)
	go func() {
		defer vc.verifyingWg.Done()
		vc.verifier.VerifyMessage(ctx, task, vc.ccvDataCh, sourceState.verificationErrorCh)
	}()
}

// isMessageReadyForVerification determines if a message meets its finality requirements.
// This implements the same logic as Python's commit_verifier.py finality checking.
func (vc *Coordinator) isMessageReadyForVerification(
	task VerificationTask,
	latestBlocks map[protocol.ChainSelector]*big.Int,
	latestFinalizedBlocks map[protocol.ChainSelector]*big.Int,
) (bool, error) {
	messageID, err := task.Message.MessageID()
	if err != nil {
		return false, fmt.Errorf("failed to compute message ID: %w", err)
	}

	latestBlock, ok := latestBlocks[task.Message.SourceChainSelector]
	if !ok {
		return false, fmt.Errorf("no latest block found for chain %d", task.Message.SourceChainSelector)
	}

	latestFinalizedBlock, ok := latestFinalizedBlocks[task.Message.SourceChainSelector]
	if !ok {
		return false, fmt.Errorf("no latest finalized block found for chain %d", task.Message.SourceChainSelector)
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
