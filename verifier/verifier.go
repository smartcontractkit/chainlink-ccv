package verifier

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/batcher"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// CommitVerifier provides a basic verifier implementation using the new message format.
type CommitVerifier struct {
	signer     MessageSigner
	lggr       logger.Logger
	monitoring VerifierMonitoring
	// TODO: Use a separate config
	config CoordinatorConfig
}

// NewCommitVerifier creates a new commit verifier.
func NewCommitVerifier(config CoordinatorConfig, signer MessageSigner, lggr logger.Logger, monitoring VerifierMonitoring) (Verifier, error) {
	cv := &CommitVerifier{
		config:     config,
		signer:     signer,
		lggr:       lggr,
		monitoring: monitoring,
	}

	if err := cv.validate(); err != nil {
		return nil, fmt.Errorf("failed to create commit verifier: %w", err)
	}

	return cv, nil
}

func (cv *CommitVerifier) validate() error {
	var errs []error
	appendIfNil := func(field any, fieldName string) {
		if field == nil {
			errs = append(errs, fmt.Errorf("%s is not set", fieldName))
		}
	}
	appendIfNil(cv.config, "config")
	appendIfNil(cv.signer, "signer")
	appendIfNil(cv.lggr, "lggr")
	appendIfNil(cv.monitoring, "monitoring")

	if len(errs) > 0 {
		return fmt.Errorf("verifier is not fully initialized: %w", errors.Join(errs...))
	}

	return nil
}

// ValidateMessage validates the new message format.
func (cv *CommitVerifier) ValidateMessage(message protocol.Message) error {
	if message.Version != protocol.MessageVersion {
		return fmt.Errorf("unsupported message version: %d", message.Version)
	}

	if len(message.Sender) == 0 {
		return fmt.Errorf("sender cannot be empty")
	}

	if len(message.Receiver) == 0 {
		return fmt.Errorf("receiver cannot be empty")
	}

	return nil
}

// VerifyMessages verifies a batch of messages using the new chain-agnostic format.
// It processes tasks concurrently and adds results directly to the batcher.
// Returns a BatchResult containing any verification errors that occurred.
func (cv *CommitVerifier) VerifyMessages(ctx context.Context, tasks []VerificationTask, ccvDataBatcher *batcher.Batcher[protocol.CCVData]) batcher.BatchResult[VerificationError] {
	if len(tasks) == 0 {
		return batcher.BatchResult[VerificationError]{Items: nil, Error: nil}
	}

	cv.lggr.Infow("Starting batch verification", "batchSize", len(tasks))

	// Collect errors from concurrent verification
	var errors []VerificationError
	var errorsMu sync.Mutex

	// Process tasks concurrently
	var wg sync.WaitGroup
	for _, task := range tasks {
		wg.Add(1)
		go func(verificationTask VerificationTask) {
			defer wg.Done()
			if err := cv.verifyMessage(ctx, verificationTask, ccvDataBatcher); err != nil {
				errorsMu.Lock()
				errors = append(errors, VerificationError{
					Timestamp: time.Now(),
					Error:     err,
					Task:      verificationTask,
				})
				errorsMu.Unlock()
			}
		}(task)
	}

	wg.Wait()
	cv.lggr.Infow("Batch verification completed", "batchSize", len(tasks), "errorCount", len(errors))

	return batcher.BatchResult[VerificationError]{
		Items: errors,
		Error: nil,
	}
}

// verifyMessage verifies a single message (internal helper)
// Returns an error if verification fails, nil if successful.
func (cv *CommitVerifier) verifyMessage(ctx context.Context, verificationTask VerificationTask, ccvDataBatcher *batcher.Batcher[protocol.CCVData]) error {
	start := time.Now()
	message := verificationTask.Message

	messageID, err := message.MessageID()
	if err != nil {
		return fmt.Errorf("failed to compute message ID: %w", err)
	}

	cv.lggr.Infow("Starting message verification",
		"messageID", messageID,
		"nonce", message.Nonce,
		"sourceChain", message.SourceChainSelector,
		"destChain", message.DestChainSelector,
	)

	// 1. Validate that the message comes from a configured source chain
	sourceConfig, exists := cv.config.SourceConfigs[message.SourceChainSelector]
	if !exists {
		return fmt.Errorf("message source chain selector %d is not configured for message 0x%x", message.SourceChainSelector, messageID)
	}

	// 2. Validate message format and check verifier receipts
	if err := cv.ValidateMessage(message); err != nil {
		return fmt.Errorf("message format validation failed for message 0x%x: %w", messageID, err)
	}

	if err := ValidateMessage(&verificationTask, sourceConfig.VerifierAddress); err != nil {
		return fmt.Errorf("message validation failed for message 0x%x with verifier address %s: %w", messageID, sourceConfig.VerifierAddress.String(), err)
	}

	cv.lggr.Infow("Message validation passed",
		"messageID", messageID,
		"verifierAddress", sourceConfig.VerifierAddress.String(),
	)

	encodedSignature, err := cv.signer.SignMessage(ctx, verificationTask, sourceConfig.VerifierAddress)
	if err != nil {
		return fmt.Errorf("failed to sign message 0x%x: %w", messageID, err)
	}

	cv.lggr.Infow("Message signed successfully",
		"messageID", messageID,
		"signerAddress", cv.signer.GetSignerAddress().String(),
		"signatureLength", len(encodedSignature),
	)

	// 4. Create CCV data with all required fields
	ccvData, err := CreateCCVData(&verificationTask, encodedSignature, []byte{}, sourceConfig.VerifierAddress)
	if err != nil {
		return fmt.Errorf("failed to create CCV data for message 0x%x: %w", messageID, err)
	}

	// Add CCVData directly to batcher
	if err := ccvDataBatcher.Add(*ccvData); err != nil {
		return fmt.Errorf("failed to add CCV data to batcher for message 0x%x (nonce: %d, source chain: %d): %w", messageID, message.Nonce, message.SourceChainSelector, err)
	}

	// Record successful message processing
	cv.monitoring.Metrics().
		With("source_chain", message.SourceChainSelector.String(), "dest_chain", message.DestChainSelector.String(), "verifier_id", cv.config.VerifierID).
		IncrementMessagesProcessed(ctx)
	cv.monitoring.Metrics().
		With("source_chain", message.SourceChainSelector.String(), "verifier_id", cv.config.VerifierID).
		RecordMessageVerificationDuration(ctx, time.Since(start))

	cv.lggr.Infow("CCV data added to batcher for writing to storage",
		"messageID", messageID,
		"nonce", message.Nonce,
		"sourceChain", message.SourceChainSelector,
		"destChain", message.DestChainSelector,
		"timestamp", ccvData.Timestamp,
	)

	return nil
}
