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
// It processes tasks concurrently and returns all results (both successes and errors).
// The caller is responsible for handling results (e.g., adding successes to a batcher).
func (cv *Verifier) VerifyMessages(ctx context.Context, tasks []verifier.VerificationTask) []verifier.VerificationResult {
	if len(tasks) == 0 {
		return nil
	}

	cv.lggr.Infow("Starting batch verification", "batchSize", len(tasks))

	// Collect results from concurrent verification
	results := make([]verifier.VerificationResult, len(tasks))
	var wg sync.WaitGroup

	// Process tasks concurrently
	for i, task := range tasks {
		wg.Add(1)
		go func(index int, verificationTask verifier.VerificationTask) {
			defer wg.Done()
			result, err := cv.verifyMessage(ctx, verificationTask)
			if err != nil {
				verificationError := verifier.VerificationError{
					Timestamp: time.Now(),
					Error:     err,
					Task:      verificationTask,
				}
				results[index] = verifier.VerificationResult{
					Error: &verificationError,
				}
			} else {
				results[index] = verifier.VerificationResult{
					Result: result,
				}
			}
		}(i, task)
	}

	wg.Wait()

	successCount := 0
	errorCount := 0
	for _, result := range results {
		if result.Error != nil {
			errorCount++
		} else {
			successCount++
		}
	}

	cv.lggr.Infow("Batch verification completed",
		"batchSize", len(tasks),
		"successCount", successCount,
		"errorCount", errorCount)

	return results
}

// verifyMessage verifies a single message (internal helper)
// Returns the VerifierNodeResult if successful, or an error if verification fails.
func (cv *Verifier) verifyMessage(ctx context.Context, verificationTask verifier.VerificationTask) (*protocol.VerifierNodeResult, error) {
	start := time.Now()
	message := verificationTask.Message

	msgIDStr := verificationTask.MessageID
	messageID, err := protocol.NewBytes32FromString(msgIDStr)
	if err != nil {
		return nil, fmt.Errorf("failed to convert messageID to Bytes32: %w", err)
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
		return nil, fmt.Errorf("message source chain selector %d is not configured for message %s", message.SourceChainSelector, msgIDStr)
	}

	// 2. Validate message format and check verifier receipts
	if err := cv.ValidateMessage(message); err != nil {
		return nil, fmt.Errorf("message format validation failed for message %s: %w", msgIDStr, err)
	}

	if err := ValidateMessage(&verificationTask); err != nil {
		return nil, fmt.Errorf(
			"message validation failed for message %s with verifier address %s and default executor address %s: %w",
			msgIDStr,
			sourceConfig.VerifierAddress.String(),
			sourceConfig.DefaultExecutorAddress.String(),
			err,
		)
	}

	cv.lggr.Infow("Message validation passed",
		"messageID", messageID,
		"verifierAddress", sourceConfig.VerifierAddress,
		"defaultExecutorAddress", sourceConfig.DefaultExecutorAddress,
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
			return nil, fmt.Errorf("neither verifier nor default executor blob found for message %s, all issuers: %v, expected issuer: %s (verifier) or %s (default executor)",
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
		return nil, fmt.Errorf("failed to create signable hash for message %s: %w", messageID.String(), err)
	}

	encodedSignature, err := cv.signer.Sign(hash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign message %s: %w", msgIDStr, err)
	}

	cv.lggr.Infow("Message signed successfully",
		"messageID", msgIDStr,
		"signer", cv.signerAddress,
		"signatureLength", len(encodedSignature),
	)

	// 4. Create CCV node data with all required fields
	ccvNodeData, err := CreateVerifierNodeResult(&verificationTask, encodedSignature, verifierBlob)
	if err != nil {
		return nil, fmt.Errorf("failed to create CCV node data for message %s: %w", msgIDStr, err)
	}

	// Record successful message processing
	cv.monitoring.Metrics().
		With("source_chain", message.SourceChainSelector.String(), "dest_chain", message.DestChainSelector.String(), "verifier_id", cv.config.VerifierID).
		IncrementMessagesProcessed(ctx)
	cv.monitoring.Metrics().
		With("source_chain", message.SourceChainSelector.String(), "verifier_id", cv.config.VerifierID).
		RecordMessageVerificationDuration(ctx, time.Since(start))

	cv.lggr.Infow("Message verification completed successfully",
		"messageID", msgIDStr,
		"nonce", message.SequenceNumber,
		"sourceChain", message.SourceChainSelector,
		"destChain", message.DestChainSelector,
	)

	return ccvNodeData, nil
}
