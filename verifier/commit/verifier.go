package commit

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common/hexutil"

	committee "github.com/smartcontractkit/chainlink-ccv/committee/common"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/batcher"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// Verifier provides a basic verifier implementation using the new message format.
type Verifier struct {
	signerAddress protocol.UnknownAddress
	signer        verifier.MessageSigner
	lggr          logger.Logger
	monitoring    verifier.Monitoring
	// TODO: Use a separate config
	config verifier.CoordinatorConfig
}

// NewCommitVerifier creates a new commit verifier.
func NewCommitVerifier(config verifier.CoordinatorConfig, signerAddress protocol.UnknownAddress, signer verifier.MessageSigner, lggr logger.Logger, monitoring verifier.Monitoring) (verifier.Verifier, error) {
	cv := &Verifier{
		config:        config,
		signerAddress: signerAddress,
		signer:        signer,
		lggr:          lggr,
		monitoring:    monitoring,
	}

	if err := cv.validate(); err != nil {
		return nil, fmt.Errorf("failed to create commit verifier: %w", err)
	}

	return cv, nil
}

func (cv *Verifier) validate() error {
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
func (cv *Verifier) ValidateMessage(message protocol.Message) error {
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
func (cv *Verifier) VerifyMessages(ctx context.Context, tasks []verifier.VerificationTask, ccvDataBatcher *batcher.Batcher[protocol.VerifierNodeResult]) batcher.BatchResult[verifier.VerificationError] {
	if len(tasks) == 0 {
		return batcher.BatchResult[verifier.VerificationError]{Items: nil, Error: nil}
	}

	cv.lggr.Infow("Starting batch verification", "batchSize", len(tasks))

	// Collect errors from concurrent verification
	var errors []verifier.VerificationError
	var errorsMu sync.Mutex

	// Process tasks concurrently
	var wg sync.WaitGroup
	for _, task := range tasks {
		wg.Add(1)
		go func(verificationTask verifier.VerificationTask) {
			defer wg.Done()
			if err := cv.verifyMessage(ctx, verificationTask, ccvDataBatcher); err != nil {
				errorsMu.Lock()
				errors = append(errors, verifier.VerificationError{
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

	return batcher.BatchResult[verifier.VerificationError]{
		Items: errors,
		Error: nil,
	}
}

// verifyMessage verifies a single message (internal helper)
// Returns an error if verification fails, nil if successful.
func (cv *Verifier) verifyMessage(ctx context.Context, verificationTask verifier.VerificationTask, ccvDataBatcher *batcher.Batcher[protocol.VerifierNodeResult]) error {
	start := time.Now()
	message := verificationTask.Message

	msgIDStr := verificationTask.MessageID
	messageID, err := protocol.NewBytes32FromString(msgIDStr)
	if err != nil {
		return fmt.Errorf("failed to convert messageID to Bytes32: %w", err)
	}
	cv.lggr.Infow("Starting message verification",
		"messageID", msgIDStr,
		"nonce", message.SequenceNumber,
		"sourceChain", message.SourceChainSelector,
		"destChain", message.DestChainSelector,
	)

	// 1. Validate that the message comes from a configured source chain
	sourceConfig, exists := cv.config.SourceConfigs[message.SourceChainSelector]
	if !exists {
		return fmt.Errorf("message source chain selector %d is not configured for message %s", message.SourceChainSelector, msgIDStr)
	}

	// 2. Validate message format and check verifier receipts
	if err := cv.ValidateMessage(message); err != nil {
		return fmt.Errorf("message format validation failed for message %s: %w", msgIDStr, err)
	}

	if err := ValidateMessage(&verificationTask); err != nil {
		return fmt.Errorf(
			"message validation failed for message %s with verifier address %s and default executor address %s: %w",
			msgIDStr,
			sourceConfig.VerifierAddress.String(),
			sourceConfig.DefaultExecutorAddress.String(),
			err,
		)
	}

	cv.lggr.Infow("Message validation passed",
		"messageID", messageID,
		"verifierAddress", sourceConfig.VerifierAddress.String(),
		"defaultExecutorAddress", sourceConfig.DefaultExecutorAddress.String(),
	)

	var verifierBlob []byte
	for _, receipt := range verificationTask.ReceiptBlobs {
		if bytes.Equal(receipt.Issuer.Bytes(), sourceConfig.VerifierAddress.Bytes()) {
			verifierBlob = receipt.Blob
			break
		}
	}
	if len(verifierBlob) == 0 {
		// We didn't find a verifier blob, so look for the default executor issuer.
		var found bool
		for _, receipt := range verificationTask.ReceiptBlobs {
			if bytes.Equal(receipt.Issuer.Bytes(), sourceConfig.DefaultExecutorAddress.Bytes()) {
				found = true
				break
			}
		}
		if !found {
			issuers := make([]string, len(verificationTask.ReceiptBlobs))
			for i, receipt := range verificationTask.ReceiptBlobs {
				issuers[i] = receipt.Issuer.String()
			}
			return fmt.Errorf("neither verifier nor default executor blob found for message %s, all issuers: %v, expected issuer: %s (verifier) or %s (default executor)",
				msgIDStr,
				issuers,
				sourceConfig.VerifierAddress.String(),
				sourceConfig.DefaultExecutorAddress.String(),
			)
		}

		// Fall back to the message discovery version if the default executor is found.
		verifierBlob = protocol.MessageDiscoveryVersion
		cv.lggr.Infow("Using message discovery version for message", "messageID", messageID, "version", hexutil.Encode(verifierBlob))
	}
	hash, err := committee.NewSignableHash(messageID, verifierBlob)
	if err != nil {
		return fmt.Errorf("failed to create signable hash for message %s: %w", messageID.String(), err)
	}

	encodedSignature, err := cv.signer.Sign(hash[:])
	if err != nil {
		return fmt.Errorf("failed to sign message %s: %w", msgIDStr, err)
	}

	cv.lggr.Infow("Message signed successfully",
		"messageID", msgIDStr,
		"signer", cv.signerAddress.String(),
		"signatureLength", len(encodedSignature),
	)

	// 4. Create CCV node data with all required fields
	ccvNodeData, err := CreateVerifierNodeResult(&verificationTask, encodedSignature, verifierBlob)
	if err != nil {
		return fmt.Errorf("failed to create CCV node data for message %s: %w", msgIDStr, err)
	}

	if err := ccvDataBatcher.Add(*ccvNodeData); err != nil {
		return fmt.Errorf("failed to add CCV node data to batcher for message %s (sequence number: %d, source chain: %d): %w", messageID.String(), message.SequenceNumber, message.SourceChainSelector, err)
	}

	// Record successful message processing
	cv.monitoring.Metrics().
		With("source_chain", message.SourceChainSelector.Name(), "dest_chain", message.DestChainSelector.Name(), "verifier_id", cv.config.VerifierID).
		IncrementMessagesProcessed(ctx)
	cv.monitoring.Metrics().
		With("source_chain", message.SourceChainSelector.Name(), "verifier_id", cv.config.VerifierID).
		RecordMessageVerificationDuration(ctx, time.Since(start))

	cv.lggr.Infow("CCV data added to batcher for writing to storage",
		"messageID", msgIDStr,
		"nonce", message.SequenceNumber,
		"sourceChain", message.SourceChainSelector,
		"destChain", message.DestChainSelector,
	)

	return nil
}
