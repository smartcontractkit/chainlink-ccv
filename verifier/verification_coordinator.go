package verifier

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/reader"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/types"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	protocol "github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
)

// Coordinator orchestrates the verification workflow using the new message format with finality awareness.
type Coordinator struct {
	verifier              types.Verifier
	storage               protocol.CCVNodeDataWriter
	lggr                  logger.Logger
	sourceStates          map[protocol.ChainSelector]*sourceState
	cancel                context.CancelFunc
	doneCh                chan struct{}
	ccvDataCh             chan protocol.CCVData
	pendingTasks          []types.VerificationTask
	config                types.CoordinatorConfig
	finalityCheckInterval time.Duration
	mu                    sync.RWMutex
	pendingMu             sync.RWMutex
	started               bool
	stopped               bool
}

// Option is the functional option type for Coordinator.
type Option func(*Coordinator)

// WithVerifier sets the verifier implementation.
func WithVerifier(verifier types.Verifier) Option {
	return func(vc *Coordinator) {
		vc.verifier = verifier
	}
}

// WithSourceReaders sets multiple source readers.
func WithSourceReaders(sourceReaders map[protocol.ChainSelector]reader.SourceReader) Option {
	return func(vc *Coordinator) {
		if vc.sourceStates == nil {
			vc.sourceStates = make(map[protocol.ChainSelector]*sourceState)
		}
		for chainSelector, reader := range sourceReaders {
			if reader != nil {
				vc.sourceStates[chainSelector] = newSourceState(chainSelector, reader)
			}
		}
	}
}

// AddSourceReader adds a single source reader to the existing map.
func AddSourceReader(chainSelector protocol.ChainSelector, sourceReader reader.SourceReader) Option {
	return func(vc *Coordinator) {
		if vc.sourceStates == nil {
			vc.sourceStates = make(map[protocol.ChainSelector]*sourceState)
		}
		vc.sourceStates[chainSelector] = newSourceState(chainSelector, sourceReader)
	}
}

// WithStorage sets the storage writer.
func WithStorage(storage protocol.CCVNodeDataWriter) Option {
	return func(vc *Coordinator) {
		vc.storage = storage
	}
}

// WithConfig sets the coordinator configuration.
func WithConfig(config types.CoordinatorConfig) Option {
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

// NewVerificationCoordinator creates a new verification coordinator.
func NewVerificationCoordinator(opts ...Option) (*Coordinator, error) {
	vc := &Coordinator{
		ccvDataCh:             make(chan protocol.CCVData, 1000),
		doneCh:                make(chan struct{}),
		sourceStates:          make(map[protocol.ChainSelector]*sourceState),
		pendingTasks:          make([]types.VerificationTask, 0),
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

	return vc, nil
}

// Start begins the verification coordinator processing.
func (vc *Coordinator) Start(ctx context.Context) error {
	vc.mu.Lock()
	defer vc.mu.Unlock()

	if vc.started {
		return fmt.Errorf("coordinator already started")
	}

	if vc.stopped {
		return errors.New("coordinator stopped")
	}

	// Start all source readers
	for chainSelector, state := range vc.sourceStates {
		if err := state.reader.Start(ctx); err != nil {
			return fmt.Errorf("failed to start source reader for chain %d: %w", chainSelector, err)
		}
	}

	vc.started = true

	ctx, cancel := context.WithCancel(ctx)
	vc.cancel = cancel

	// Start processing loop and finality checking
	go vc.run(ctx)
	go vc.finalityCheckingLoop(ctx)

	vc.lggr.Infow("Coordinator started with finality checking",
		"coordinatorID", vc.config.VerifierID,
	)

	return nil
}

// Stop stops the verification coordinator processing.
func (vc *Coordinator) Stop() error {
	vc.mu.Lock()
	defer vc.mu.Unlock()

	if vc.stopped {
		return nil
	}

	vc.stopped = true
	vc.started = false

	// Stop all source readers and close error channels
	for chainSelector, state := range vc.sourceStates {
		if err := state.reader.Stop(); err != nil {
			vc.lggr.Errorw("Error stopping source reader", "error", err, "chainSelector", chainSelector)
		}
		// Close the per-source error channel
		close(state.verificationErrorCh)
	}

	// Wait for processing to finish
	vc.cancel()
	<-vc.doneCh

	vc.lggr.Infow("Coordinator stopped")

	return nil
}

// run is the main processing loop.
func (vc *Coordinator) run(ctx context.Context) {
	defer close(vc.doneCh)

	// Start goroutines for each source state
	var wg sync.WaitGroup
	for _, state := range vc.sourceStates {
		wg.Add(1)
		go vc.processSourceMessages(ctx, &wg, state)

		// Start error processing goroutine for each source
		wg.Add(1)
		go vc.processSourceErrors(ctx, &wg, state)
	}

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

			// Write CCVData to offchain storage
			if err := vc.storage.WriteCCVNodeData(ctx, []protocol.CCVData{ccvData}); err != nil {
				vc.lggr.Errorw("Error storing CCV data",
					"error", err,
					"messageID", ccvData.MessageID,
					"nonce", ccvData.Nonce,
					"sourceChain", ccvData.SourceChainSelector,
				)
			} else {
				vc.lggr.Infow("CCV data stored successfully",
					"messageID", ccvData.MessageID,
					"nonce", ccvData.Nonce,
					"sourceChain", ccvData.SourceChainSelector,
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
		case verificationTask, ok := <-state.verificationTaskCh:
			if !ok {
				vc.lggr.Errorw("Message channel closed for source", "chainSelector", chainSelector)
				return
			}
			// Add to pending queue for finality checking
			vc.addToPendingQueue(verificationTask, chainSelector)
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

	if len(vc.sourceStates) == 0 {
		errs = append(errs, fmt.Errorf("at least one source reader is required"))
	}

	// Validate that all configured sources have corresponding readers
	for chainSelector := range vc.config.SourceConfigs {
		if _, exists := vc.sourceStates[chainSelector]; !exists {
			errs = append(errs, fmt.Errorf("source reader not found for chain selector %d", chainSelector))
		}
	}

	if vc.verifier == nil {
		errs = append(errs, fmt.Errorf("verifier is required"))
	}

	if vc.storage == nil {
		errs = append(errs, fmt.Errorf("storage writer is required"))
	}

	if vc.lggr == nil {
		errs = append(errs, fmt.Errorf("logger is required"))
	}

	if vc.config.VerifierID == "" {
		errs = append(errs, fmt.Errorf("coordinator ID cannot be empty"))
	}

	return errors.Join(errs...)
}

// HealthCheck returns the current health status.
func (vc *Coordinator) HealthCheck(ctx context.Context) error {
	vc.mu.RLock()
	defer vc.mu.RUnlock()

	if vc.stopped {
		return errors.New("coordinator stopped")
	}

	if !vc.started {
		return errors.New("coordinator not started")
	}

	// Check all source readers health
	for chainSelector, state := range vc.sourceStates {
		if err := state.reader.HealthCheck(ctx); err != nil {
			return fmt.Errorf("source reader unhealthy for chain %d: %w", chainSelector, err)
		}
	}

	return nil
}

// addToPendingQueue adds a verification task to the pending queue for finality checking.
func (vc *Coordinator) addToPendingQueue(task types.VerificationTask, chainSelector protocol.ChainSelector) {
	vc.pendingMu.Lock()
	defer vc.pendingMu.Unlock()

	vc.pendingTasks = append(vc.pendingTasks, task)

	messageID, err := task.Message.MessageID()
	if err != nil {
		vc.lggr.Errorw("Failed to compute message ID for queuing", "error", err)
		return
	}

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

	vc.lggr.Infow("🔄 Starting finality checking loop")

	for {
		select {
		case <-ctx.Done():
			vc.lggr.Infow("🛑 Finality checking stopped due to context cancellation")
			return
		case <-ticker.C:
			vc.processFinalityQueue(ctx)
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

	var readyTasks []types.VerificationTask
	var remainingTasks []types.VerificationTask

	// Get latest blocks and finalized blocks for all chains
	latestBlocks := make(map[protocol.ChainSelector]*big.Int)
	for chainSelector, state := range vc.sourceStates {
		latestBlock, err := state.reader.LatestBlock(ctx)
		if err != nil {
			vc.lggr.Errorw("Failed to get latest block", "error", err)
			continue
		}
		latestBlocks[chainSelector] = latestBlock
	}
	latestFinalizedBlocks := make(map[protocol.ChainSelector]*big.Int)
	for chainSelector, state := range vc.sourceStates {
		latestFinalizedBlock, err := state.reader.LatestFinalizedBlock(ctx)
		if err != nil {
			vc.lggr.Errorw("Failed to get latest finalized block", "error", err)
			continue
		}
		latestFinalizedBlocks[chainSelector] = latestFinalizedBlock
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
func (vc *Coordinator) processReadyTask(ctx context.Context, task types.VerificationTask) {
	messageID, err := task.Message.MessageID()
	if err != nil {
		vc.lggr.Errorw("Failed to compute message ID for ready task", "error", err)
		return
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
	go vc.verifier.VerifyMessage(ctx, task, vc.ccvDataCh, sourceState.verificationErrorCh)
}

// isMessageReadyForVerification determines if a message meets its finality requirements.
// This implements the same logic as Python's commit_verifier.py finality checking.
func (vc *Coordinator) isMessageReadyForVerification(
	task types.VerificationTask,
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
