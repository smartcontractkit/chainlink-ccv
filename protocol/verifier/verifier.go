package verifier

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	cciptypes "github.com/smartcontractkit/chainlink-common/pkg/types/ccipocr3"

	"github.com/smartcontractkit/chainlink-ccv/protocol/common"
)

// Verifier defines the interface for message verification logic
type Verifier interface {
	// VerifyMessage performs the actual verification of a message
	VerifyMessage(ctx context.Context, task common.VerificationTask, ccvDataCh chan<- common.CCVData) error
}

// VerificationCoordinator orchestrates the verification workflow
// Reads messages from multiple SourceReaders and processes them using a Verifier
type VerificationCoordinator struct {
	// Basic operation channels
	ccvDataCh chan common.CCVData
	stopCh    chan struct{}
	doneCh    chan struct{}

	// Core components
	verifier Verifier
	// N Channels producing Any2AnyVerifierMessage
	sourceStates map[cciptypes.ChainSelector]*sourceState
	storage      common.OffchainStorageWriter

	// Configuration
	config CoordinatorConfig
	lggr   logger.Logger

	// State management
	mu      sync.RWMutex
	started bool
	stopped bool
}

// Option is the functional option type for VerificationCoordinator
type Option func(*VerificationCoordinator)

// WithVerifier sets the verifier implementation
func WithVerifier(verifier Verifier) Option {
	return func(vc *VerificationCoordinator) {
		vc.verifier = verifier
	}
}

// WithSourceReaders sets multiple source readers
func WithSourceReaders(sourceReaders map[cciptypes.ChainSelector]SourceReader) Option {
	return func(vc *VerificationCoordinator) {
		if vc.sourceStates == nil {
			vc.sourceStates = make(map[cciptypes.ChainSelector]*sourceState)
		}
		for chainSelector, reader := range sourceReaders {
			vc.sourceStates[chainSelector] = newSourceState(chainSelector, reader)
		}
	}
}

// AddSourceReader adds a single source reader to the existing map
func AddSourceReader(chainSelector cciptypes.ChainSelector, reader SourceReader) Option {
	return func(vc *VerificationCoordinator) {
		if vc.sourceStates == nil {
			vc.sourceStates = make(map[cciptypes.ChainSelector]*sourceState)
		}
		vc.sourceStates[chainSelector] = newSourceState(chainSelector, reader)
	}
}

// WithStorage sets the storage writer
func WithStorage(storage common.OffchainStorageWriter) Option {
	return func(vc *VerificationCoordinator) {
		vc.storage = storage
	}
}

// WithConfig sets the coordinator configuration
func WithConfig(config CoordinatorConfig) Option {
	return func(vc *VerificationCoordinator) {
		vc.config = config
	}
}

// WithLogger sets the logger
func WithLogger(lggr logger.Logger) Option {
	return func(vc *VerificationCoordinator) {
		vc.lggr = lggr
	}
}

// NewVerificationCoordinator creates a new verification coordinator
func NewVerificationCoordinator(opts ...Option) (*VerificationCoordinator, error) {
	//TODO: Make channel size configurable
	vc := &VerificationCoordinator{
		ccvDataCh:    make(chan common.CCVData, 1000), // Channel for CCVData results
		stopCh:       make(chan struct{}),
		doneCh:       make(chan struct{}),
		sourceStates: make(map[cciptypes.ChainSelector]*sourceState),
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

// Start begins the verification coordinator processing
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
		"coordinatorID", vc.config.CoordinatorID,
	)

	return nil
}

// Stop stops the verification coordinator processing
func (vc *VerificationCoordinator) Stop() error {
	vc.mu.Lock()
	defer vc.mu.Unlock()

	if vc.stopped {
		return nil
	}

	vc.stopped = true
	vc.started = false
	close(vc.stopCh)

	// Stop all source readers
	for chainSelector, state := range vc.sourceStates {
		if err := state.reader.Stop(); err != nil {
			vc.lggr.Errorw("Error stopping source reader", "error", err, "chainSelector", chainSelector)
		}
	}

	// Wait for processing to finish
	<-vc.doneCh

	vc.lggr.Infow("VerificationCoordinator stopped")

	return nil
}

// run is the main processing loop
func (vc *VerificationCoordinator) run(ctx context.Context) {
	defer close(vc.doneCh)

	// Start goroutines for each source state
	var wg sync.WaitGroup
	for chainSelector, state := range vc.sourceStates {
		wg.Add(1)
		go vc.processSourceMessages(ctx, &wg, chainSelector, state)
	}

	// Main loop - focus solely on ccvDataCh processing and storage
	for {
		select {
		case <-ctx.Done():
			vc.lggr.Infow("VerificationCoordinator processing stopped due to context cancellation")
			wg.Wait() // Wait for all source goroutines to finish
			return
		case <-vc.stopCh:
			vc.lggr.Infow("VerificationCoordinator processing stopped due to stop signal")
			wg.Wait() // Wait for all source goroutines to finish
			return
		case ccvData, ok := <-vc.ccvDataCh:
			if !ok {
				vc.lggr.Infow("CCVData channel closed, stopping processing")
				wg.Wait() // Wait for all source goroutines to finish
				return
			}

			// Store CCVData to offchain storage
			//TODO: handle errors/retries?
			if err := vc.storage.StoreCCVData(ctx, []common.CCVData{ccvData}); err != nil {
				vc.lggr.Errorw("Error storing CCV data",
					"error", err,
					"messageID", ccvData.MessageID,
					"sequenceNumber", ccvData.SequenceNumber,
					"sourceChain", ccvData.SourceChainSelector,
				)
			} else {
				vc.lggr.Debugw("CCV data stored successfully",
					"messageID", ccvData.MessageID,
					"sequenceNumber", ccvData.SequenceNumber,
					"sourceChain", ccvData.SourceChainSelector,
				)
			}
		}
	}
}

// processSourceMessages handles message processing for a single source state in its own goroutine
func (vc *VerificationCoordinator) processSourceMessages(ctx context.Context, wg *sync.WaitGroup, chainSelector cciptypes.ChainSelector, state *sourceState) {
	defer wg.Done()

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

			// Process message event using the verifier
			if err := vc.verifier.VerifyMessage(ctx, verificationTask, vc.ccvDataCh); err != nil {
				// Extract header for cleaner logging
				header := verificationTask.Message.Header
				vc.lggr.Errorw("Error processing message event",
					"error", err,
					"messageID", header.MessageID,
					"sequenceNumber", header.SequenceNumber,
					"sourceChain", header.SourceChainSelector,
					"chainSelector", chainSelector,
				)
			}
		}
	}
}

/*
src1 -> CCIPMessageSentEvent --processMessageEvent--->
src2 -> CCIPMessageSentEvent --processMessageEvent--->   ccvDatach --> Storage/Aggregator
src3 -> CCIPMessageSentEvent --processMessageEvent--->
*/

// CommitVerifier provides a basic verifier implementation
type CommitVerifier struct {
	config CoordinatorConfig
	signer MessageSigner
	lggr   logger.Logger
}

// NewCommitVerifier creates a new commit verifier
func NewCommitVerifier(config CoordinatorConfig, signer MessageSigner, lggr logger.Logger) *CommitVerifier {
	return &CommitVerifier{
		config: config,
		signer: signer,
		lggr:   lggr,
	}
}

// VerifyMessage implements the Verifier interface
func (cv *CommitVerifier) VerifyMessage(ctx context.Context, verificationTask common.VerificationTask, ccvDataCh chan<- common.CCVData) error {
	// Extract message and header for cleaner access
	message := verificationTask.Message
	header := message.Header

	// Basic validation
	emptyID := [32]byte{}
	if header.MessageID == emptyID {
		return fmt.Errorf("message ID is empty")
	}

	// Validate that the message comes from a configured source chain
	var sourceConfig *SourceConfig
	for _, config := range cv.config.SourceConfigs {
		if config.ChainSelector == header.SourceChainSelector {
			sourceConfig = &config
			break
		}
	}

	if sourceConfig == nil {
		return fmt.Errorf("message source chain selector %d is not configured", header.SourceChainSelector)
	}

	if header.SequenceNumber == 0 {
		return fmt.Errorf("message sequence number cannot be zero")
	}

	// The DestChainSelector and SequenceNumber are only available in Message.Header now

	cv.lggr.Debugw("Message event validation passed",
		"messageID", header.MessageID,
		"sequenceNumber", header.SequenceNumber,
		"sourceChain", header.SourceChainSelector,
		"destChain", header.DestChainSelector,
	)

	//TODO: Add finality awareness logic

	// Sign the message event
	signature, err := cv.signer.SignMessage(ctx, verificationTask)
	if err != nil {
		return fmt.Errorf("failed to sign message event: %w", err)
	}

	// Create CCV data
	ccvData := &common.CCVData{
		MessageID:             header.MessageID,
		SequenceNumber:        header.SequenceNumber,
		SourceChainSelector:   header.SourceChainSelector,
		DestChainSelector:     header.DestChainSelector,
		SourceVerifierAddress: sourceConfig.VerifierAddress,
		CCVData:               signature,
		BlobData:              []byte{},
		Timestamp:             time.Now().UnixMicro(),
		Message:               message, // Store the complete message
	}

	// Send CCVData to channel for storage
	select {
	case ccvDataCh <- *ccvData:
		cv.lggr.Debugw("CCV data sent to storage channel",
			"messageID", header.MessageID,
			"sequenceNumber", header.SequenceNumber,
			"sourceChain", header.SourceChainSelector,
			"destChain", header.DestChainSelector,
		)
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// validate checks that all required components are configured
func (vc *VerificationCoordinator) validate() error {
	if len(vc.sourceStates) == 0 {
		return fmt.Errorf("at least one source reader is required")
	}

	// Validate that all configured sources have corresponding readers
	for _, sourceConfig := range vc.config.SourceConfigs {
		if _, exists := vc.sourceStates[sourceConfig.ChainSelector]; !exists {
			return fmt.Errorf("source reader not found for chain selector %d", sourceConfig.ChainSelector)
		}
	}

	// Check for duplicate chain selectors in config
	seen := make(map[cciptypes.ChainSelector]bool)
	for _, sourceConfig := range vc.config.SourceConfigs {
		if seen[sourceConfig.ChainSelector] {
			return fmt.Errorf("duplicate chain selector %d in source configs", sourceConfig.ChainSelector)
		}
		seen[sourceConfig.ChainSelector] = true
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

	if vc.config.CoordinatorID == "" {
		return fmt.Errorf("coordinator ID cannot be empty")
	}

	// Note: verifier is now required and must be set via WithVerifier option

	return nil
}

// HealthCheck returns the current health status
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
