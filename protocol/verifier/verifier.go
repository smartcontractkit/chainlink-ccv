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

// MessageProcessor is a function type that processes messages and writes CCVData to a channel
type MessageProcessor func(ctx context.Context, message common.Any2AnyVerifierMessage, ccvDataCh chan<- common.CCVData) error

// Verifier implements a simplified message verification pipeline
// Reads messages from multiple SourceReaders and processes them using a MessageProcessor function
type Verifier struct {
	// Basic operation channels
	ccvDataCh chan common.CCVData
	stopCh    chan struct{}
	doneCh    chan struct{}

	// Core components
	processor MessageProcessor
	signer    MessageSigner
	// N Channels producing Any2AnyVerifierMessage
	sourceStates map[cciptypes.ChainSelector]*sourceState
	storage      common.OffchainStorageWriter

	// Configuration
	config VerifierConfig
	lggr   logger.Logger

	// State management
	mu      sync.RWMutex
	started bool
	stopped bool
}

// Option is the functional option type for Verifier
type Option func(*Verifier)

// WithMessageProcessor sets the message processor function
func WithMessageProcessor(processor MessageProcessor) Option {
	return func(v *Verifier) {
		v.processor = processor
	}
}

// WithSigner sets a custom signer
func WithSigner(signer MessageSigner) Option {
	return func(v *Verifier) {
		v.signer = signer
	}
}

// WithSourceReaders sets multiple source readers
func WithSourceReaders(sourceReaders map[cciptypes.ChainSelector]SourceReader) Option {
	return func(v *Verifier) {
		if v.sourceStates == nil {
			v.sourceStates = make(map[cciptypes.ChainSelector]*sourceState)
		}
		for chainSelector, reader := range sourceReaders {
			v.sourceStates[chainSelector] = newSourceState(chainSelector, reader)
		}
	}
}

// AddSourceReader adds a single source reader to the existing map
func AddSourceReader(chainSelector cciptypes.ChainSelector, reader SourceReader) Option {
	return func(v *Verifier) {
		if v.sourceStates == nil {
			v.sourceStates = make(map[cciptypes.ChainSelector]*sourceState)
		}
		v.sourceStates[chainSelector] = newSourceState(chainSelector, reader)
	}
}

// WithStorage sets the storage writer
func WithStorage(storage common.OffchainStorageWriter) Option {
	return func(v *Verifier) {
		v.storage = storage
	}
}

// WithConfig sets the verifier configuration
func WithConfig(config VerifierConfig) Option {
	return func(v *Verifier) {
		v.config = config
	}
}

// WithLogger sets the logger
func WithLogger(lggr logger.Logger) Option {
	return func(v *Verifier) {
		v.lggr = lggr
	}
}

// NewVerifier creates a new simplified verifier
func NewVerifier(opts ...Option) (*Verifier, error) {
	//TODO: Make channel size configurable
	v := &Verifier{
		ccvDataCh:    make(chan common.CCVData, 1000), // Channel for CCVData results
		stopCh:       make(chan struct{}),
		doneCh:       make(chan struct{}),
		sourceStates: make(map[cciptypes.ChainSelector]*sourceState),
	}

	// Apply all options
	for _, opt := range opts {
		opt(v)
	}

	// Validate required components
	if err := v.validate(); err != nil {
		return nil, fmt.Errorf("invalid verifier configuration: %w", err)
	}

	return v, nil
}

// Start begins the simplified verifier processing
func (v *Verifier) Start(ctx context.Context) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.started {
		return fmt.Errorf("verifier already started")
	}

	if v.stopped {
		return errors.New("verifier stopped")
	}

	// Start all source readers
	for chainSelector, state := range v.sourceStates {
		if err := state.reader.Start(ctx); err != nil {
			return fmt.Errorf("failed to start source reader for chain %d: %w", chainSelector, err)
		}
	}

	v.started = true

	// Start processing loop
	go v.run(ctx)

	v.lggr.Infow("Verifier started",
		"verifierID", v.config.VerifierID,
	)

	return nil
}

// Stop stops the simplified verifier processing
func (v *Verifier) Stop() error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.stopped {
		return nil
	}

	v.stopped = true
	v.started = false
	close(v.stopCh)

	// Stop all source readers
	for chainSelector, state := range v.sourceStates {
		if err := state.reader.Stop(); err != nil {
			v.lggr.Errorw("Error stopping source reader", "error", err, "chainSelector", chainSelector)
		}
	}

	// Wait for processing to finish
	<-v.doneCh

	v.lggr.Infow("Verifier stopped")

	return nil
}

// run is the main processing loop
func (v *Verifier) run(ctx context.Context) {
	defer close(v.doneCh)

	// Start goroutines for each source state
	var wg sync.WaitGroup
	for chainSelector, state := range v.sourceStates {
		wg.Add(1)
		go v.processSourceMessages(ctx, &wg, chainSelector, state)
	}

	// Main loop - focus solely on ccvDataCh processing and storage
	for {
		select {
		case <-ctx.Done():
			v.lggr.Infow("Verifier processing stopped due to context cancellation")
			wg.Wait() // Wait for all source goroutines to finish
			return
		case <-v.stopCh:
			v.lggr.Infow("Verifier processing stopped due to stop signal")
			wg.Wait() // Wait for all source goroutines to finish
			return
		case ccvData, ok := <-v.ccvDataCh:
			if !ok {
				v.lggr.Infow("CCVData channel closed, stopping processing")
				wg.Wait() // Wait for all source goroutines to finish
				return
			}

			// Store CCVData to offchain storage
			//TODO: handle errors/retries?
			if err := v.storage.StoreCCVData(ctx, []common.CCVData{ccvData}); err != nil {
				v.lggr.Errorw("Error storing CCV data",
					"error", err,
					"messageID", ccvData.MessageID,
					"sequenceNumber", ccvData.SequenceNumber,
					"sourceChain", ccvData.SourceChainSelector,
				)
			} else {
				v.lggr.Debugw("CCV data stored successfully",
					"messageID", ccvData.MessageID,
					"sequenceNumber", ccvData.SequenceNumber,
					"sourceChain", ccvData.SourceChainSelector,
				)
			}
		}
	}
}

// processSourceMessages handles message processing for a single source state in its own goroutine
func (v *Verifier) processSourceMessages(ctx context.Context, wg *sync.WaitGroup, chainSelector cciptypes.ChainSelector, state *sourceState) {
	defer wg.Done()

	v.lggr.Debugw("Starting source message processor", "chainSelector", chainSelector)
	defer v.lggr.Debugw("Source message processor stopped", "chainSelector", chainSelector)

	for {
		select {
		case <-ctx.Done():
			v.lggr.Debugw("Source message processor stopped due to context cancellation", "chainSelector", chainSelector)
			return
		case <-v.stopCh:
			v.lggr.Debugw("Source message processor stopped due to stop signal", "chainSelector", chainSelector)
			return
		case message, ok := <-state.messageCh:
			if !ok {
				v.lggr.Errorw("Message channel closed for source", "chainSelector", chainSelector)
				return
			}

			// Process message using the processor function
			if err := v.processor(ctx, message, v.ccvDataCh); err != nil {
				v.lggr.Errorw("Error processing message",
					"error", err,
					"messageID", message.Header.MessageID,
					"sequenceNumber", message.Header.SequenceNumber,
					"sourceChain", message.Header.SourceChainSelector,
					"chainSelector", chainSelector,
				)
			}
		}
	}
}

/*
src1 -> any2any --processMessage--->
src2 -> any2any --processMessage--->   ccvDatach --> Storage/Aggregator
src3 -> any2any --processMessage--->
*/

// DefaultMessageProcessor provides a basic message processor implementation
func (v *Verifier) DefaultMessageProcessor(ctx context.Context, message common.Any2AnyVerifierMessage, ccvDataCh chan<- common.CCVData) error {
	// Basic validation
	emptyID := [32]byte{}
	if message.Header.MessageID == emptyID {
		return fmt.Errorf("message ID is empty")
	}

	// Validate that the message comes from a configured source chain
	var sourceConfig *SourceConfig
	for _, config := range v.config.SourceConfigs {
		if config.ChainSelector == message.Header.SourceChainSelector {
			sourceConfig = &config
			break
		}
	}

	if sourceConfig == nil {
		return fmt.Errorf("message source chain selector %d is not configured", message.Header.SourceChainSelector)
	}

	if message.Header.SequenceNumber == 0 {
		return fmt.Errorf("message sequence number cannot be zero")
	}

	v.lggr.Debugw("Message validation passed",
		"messageID", message.Header.MessageID,
		"sequenceNumber", message.Header.SequenceNumber,
	)

	//TODO: Add finality awareness logic

	// Generate CCV data
	ccvData, err := v.generateCCVData(ctx, message, sourceConfig)
	if err != nil {
		return fmt.Errorf("failed to generate CCV data: %w", err)
	}

	// Send CCVData to channel for storage
	select {
	case ccvDataCh <- *ccvData:
		v.lggr.Debugw("CCV data sent to storage channel",
			"messageID", message.Header.MessageID,
			"sequenceNumber", message.Header.SequenceNumber,
		)
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// generateCCVData creates CCV data for a verified message
func (v *Verifier) generateCCVData(ctx context.Context, message common.Any2AnyVerifierMessage, sourceConfig *SourceConfig) (*common.CCVData, error) {
	// Sign the message
	signature, err := v.signer.SignMessage(ctx, message)
	if err != nil {
		return nil, fmt.Errorf("failed to sign message: %w", err)
	}

	// Determine dest verifier address (use first source config's verifier address as fallback)
	destVerifierAddress := v.config.DestVerifierAddress
	if len(destVerifierAddress) == 0 && len(v.config.SourceConfigs) > 0 {
		destVerifierAddress = v.config.SourceConfigs[0].VerifierAddress
	}

	// Create CCV data
	ccvData := &common.CCVData{
		MessageID:             message.Header.MessageID,
		SequenceNumber:        message.Header.SequenceNumber,
		SourceChainSelector:   message.Header.SourceChainSelector,
		DestChainSelector:     message.Header.DestChainSelector,
		SourceVerifierAddress: sourceConfig.VerifierAddress,
		DestVerifierAddress:   destVerifierAddress,
		CCVData:               signature,
		BlobData:              []byte{},
		Timestamp:             time.Now().UnixMicro(),
		Message:               message,
	}

	return ccvData, nil
}

// validate checks that all required components are configured
func (v *Verifier) validate() error {
	if len(v.sourceStates) == 0 {
		return fmt.Errorf("at least one source reader is required")
	}

	// Validate that all configured sources have corresponding readers
	for _, sourceConfig := range v.config.SourceConfigs {
		if _, exists := v.sourceStates[sourceConfig.ChainSelector]; !exists {
			return fmt.Errorf("source reader not found for chain selector %d", sourceConfig.ChainSelector)
		}
	}

	// Check for duplicate chain selectors in config
	seen := make(map[cciptypes.ChainSelector]bool)
	for _, sourceConfig := range v.config.SourceConfigs {
		if seen[sourceConfig.ChainSelector] {
			return fmt.Errorf("duplicate chain selector %d in source configs", sourceConfig.ChainSelector)
		}
		seen[sourceConfig.ChainSelector] = true
	}

	if v.signer == nil {
		return fmt.Errorf("signer is required")
	}

	if v.storage == nil {
		return fmt.Errorf("storage writer is required")
	}

	if v.lggr == nil {
		return fmt.Errorf("logger is required")
	}

	if v.config.VerifierID == "" {
		return fmt.Errorf("verifier ID cannot be empty")
	}

	// Set default processor if none provided
	if v.processor == nil {
		v.processor = v.DefaultMessageProcessor
	}

	return nil
}

// HealthCheck returns the current health status
func (v *Verifier) HealthCheck(ctx context.Context) error {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if v.stopped {
		return errors.New("verifier stopped")
	}

	if !v.started {
		return errors.New("verifier not started")
	}

	// Check all source readers health
	for chainSelector, state := range v.sourceStates {
		if err := state.reader.HealthCheck(ctx); err != nil {
			return fmt.Errorf("source reader unhealthy for chain %d: %w", chainSelector, err)
		}
	}

	return nil
}
