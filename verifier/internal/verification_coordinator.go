package internal

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/reader"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/types"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	protocol "github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
)

// VerificationCoordinator orchestrates the verification workflow using the new message format.
type VerificationCoordinator struct {
	verifier     types.Verifier
	storage      protocol.OffchainStorageWriter
	lggr         logger.Logger
	ccvDataCh    chan protocol.CCVData
	stopCh       chan struct{}
	doneCh       chan struct{}
	sourceStates map[protocol.ChainSelector]*sourceState
	config       types.CoordinatorConfig
	mu           sync.RWMutex
	started      bool
	stopped      bool
}

// Option is the functional option type for VerificationCoordinator.
type Option func(*VerificationCoordinator)

// WithVerifier sets the verifier implementation.
func WithVerifier(verifier types.Verifier) Option {
	return func(vc *VerificationCoordinator) {
		vc.verifier = verifier
	}
}

// WithSourceReaders sets multiple source readers.
func WithSourceReaders(sourceReaders map[protocol.ChainSelector]reader.SourceReader) Option {
	return func(vc *VerificationCoordinator) {
		if vc.sourceStates == nil {
			vc.sourceStates = make(map[protocol.ChainSelector]*sourceState)
		}
		for chainSelector, reader := range sourceReaders {
			vc.sourceStates[chainSelector] = newSourceState(chainSelector, reader)
		}
	}
}

// AddSourceReader adds a single source reader to the existing map.
func AddSourceReader(chainSelector protocol.ChainSelector, sourceReader reader.SourceReader) Option {
	return func(vc *VerificationCoordinator) {
		if vc.sourceStates == nil {
			vc.sourceStates = make(map[protocol.ChainSelector]*sourceState)
		}
		vc.sourceStates[chainSelector] = newSourceState(chainSelector, sourceReader)
	}
}

// WithStorage sets the storage writer.
func WithStorage(storage protocol.OffchainStorageWriter) Option {
	return func(vc *VerificationCoordinator) {
		vc.storage = storage
	}
}

// WithConfig sets the coordinator configuration.
func WithConfig(config types.CoordinatorConfig) Option {
	return func(vc *VerificationCoordinator) {
		vc.config = config
	}
}

// WithLogger sets the logger.
func WithLogger(lggr logger.Logger) Option {
	return func(vc *VerificationCoordinator) {
		vc.lggr = lggr
	}
}

// NewVerificationCoordinator creates a new verification coordinator.
func NewVerificationCoordinator(opts ...Option) (*VerificationCoordinator, error) {
	vc := &VerificationCoordinator{
		ccvDataCh:    make(chan protocol.CCVData, 1000),
		stopCh:       make(chan struct{}),
		doneCh:       make(chan struct{}),
		sourceStates: make(map[protocol.ChainSelector]*sourceState),
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
func (vc *VerificationCoordinator) Start(ctx context.Context) error {
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

	// Start processing loop
	go vc.run(ctx)

	vc.lggr.Infow("VerificationCoordinator started",
		"coordinatorID", vc.config.VerifierID,
	)

	return nil
}

// Stop stops the verification coordinator processing.
func (vc *VerificationCoordinator) Stop() error {
	vc.mu.Lock()
	defer vc.mu.Unlock()

	if vc.stopped {
		return nil
	}

	vc.stopped = true
	vc.started = false
	close(vc.stopCh)

	// Stop all source readers and close error channels
	for chainSelector, state := range vc.sourceStates {
		if err := state.reader.Stop(); err != nil {
			vc.lggr.Errorw("Error stopping source reader", "error", err, "chainSelector", chainSelector)
		}
		// Close the per-source error channel
		close(state.verificationErrorCh)
	}

	// Wait for processing to finish
	<-vc.doneCh

	vc.lggr.Infow("VerificationCoordinator stopped")

	return nil
}

// run is the main processing loop.
func (vc *VerificationCoordinator) run(ctx context.Context) {
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
			vc.lggr.Infow("VerificationCoordinator processing stopped due to context cancellation")
			wg.Wait()
			return
		case <-vc.stopCh:
			vc.lggr.Infow("VerificationCoordinator processing stopped due to stop signal")
			wg.Wait()
			return
		case ccvData, ok := <-vc.ccvDataCh:
			if !ok {
				vc.lggr.Infow("CCVData channel closed, stopping processing")
				wg.Wait()
				return
			}

			// Write CCVData to offchain storage
			if err := vc.storage.WriteCCVData(ctx, []protocol.CCVData{ccvData}); err != nil {
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
func (vc *VerificationCoordinator) processSourceMessages(ctx context.Context, wg *sync.WaitGroup, state *sourceState) {
	defer wg.Done()
	chainSelector := state.chainSelector

	vc.lggr.Debugw("Starting source message processor", "chainSelector", chainSelector)
	defer vc.lggr.Debugw("Source message processor stopped", "chainSelector", chainSelector)

	for {
		select {
		case <-ctx.Done():
			vc.lggr.Debugw("Source message processor stopped due to context cancellation", "chainSelector", chainSelector)
			return
		case <-vc.stopCh:
			vc.lggr.Debugw("Source message processor stopped due to stop signal", "chainSelector", chainSelector)
			return
		case verificationTask, ok := <-state.verificationTaskCh:
			if !ok {
				vc.lggr.Errorw("Message channel closed for source", "chainSelector", chainSelector)
				return
			}
			// Process message event using the verifier asynchronously
			go vc.verifier.VerifyMessage(ctx, verificationTask, vc.ccvDataCh, state.verificationErrorCh)
		}
	}
}

// processSourceErrors handles error processing for a single source state.
func (vc *VerificationCoordinator) processSourceErrors(ctx context.Context, wg *sync.WaitGroup, state *sourceState) {
	defer wg.Done()
	chainSelector := state.chainSelector

	vc.lggr.Debugw("Starting source error processor", "chainSelector", chainSelector)
	defer vc.lggr.Debugw("Source error processor stopped", "chainSelector", chainSelector)

	for {
		select {
		case <-ctx.Done():
			vc.lggr.Debugw("Source error processor stopped due to context cancellation", "chainSelector", chainSelector)
			return
		case <-vc.stopCh:
			vc.lggr.Debugw("Source error processor stopped due to stop signal", "chainSelector", chainSelector)
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
func (vc *VerificationCoordinator) validate() error {
	if len(vc.sourceStates) == 0 {
		return fmt.Errorf("at least one source reader is required")
	}

	// Validate that all configured sources have corresponding readers
	for chainSelector := range vc.config.SourceConfigs {
		if _, exists := vc.sourceStates[chainSelector]; !exists {
			return fmt.Errorf("source reader not found for chain selector %d", chainSelector)
		}
	}

	if vc.verifier == nil {
		return fmt.Errorf("verifier is required")
	}

	if vc.storage == nil {
		return fmt.Errorf("storage writer is required")
	}

	if vc.lggr == nil {
		return fmt.Errorf("logger is required")
	}

	if vc.config.VerifierID == "" {
		return fmt.Errorf("coordinator ID cannot be empty")
	}

	return nil
}

// HealthCheck returns the current health status.
func (vc *VerificationCoordinator) HealthCheck(ctx context.Context) error {
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
