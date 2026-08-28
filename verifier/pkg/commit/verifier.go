package commit

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common/hexutil"

	"github.com/smartcontractkit/chainlink-ccv/common/committee"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	verifier "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vtypes"
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

// VerifyMessages verifies a batch of messages using the new chain-agnostic format.
// It processes tasks concurrently and returns all results (both successes and errors).
// The caller is responsible for handling results (e.g., adding successes to a batcher).
func (cv *Verifier) VerifyMessages(ctx context.Context, tasks []verifier.VerificationTask) []verifier.VerificationResult {
	if len(tasks) == 0 {
		return nil
	}

	cv.lggr.Debugw("Starting batch verification", "batchSize", len(tasks))

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

	cv.lggr.Debugw("Batch verification completed",
		"batchSize", len(tasks),
		"successCount", successCount,
		"errorCount", errorCount)

	return results
}

// signablePayload is what verification resolves before it signs: the message ID in binary form,
// the configuration of the message's source chain, and the receipt blob the signature commits to.
type signablePayload struct {
	messageID    protocol.Bytes32
	sourceConfig verifier.SourceConfig
	blob         []byte
	// usedDiscoveryVersion records that the task carried no verifier-issued receipt and the blob
	// fell back to the message discovery version.
	usedDiscoveryVersion bool
}

// resolveSignablePayload runs every check verification makes before it signs, and returns what
// signing needs. ValidateTask and verifyMessage both go through this one function deliberately.
// A caller uses ValidateTask to decide which tasks are worth further work, so a second copy of
// these checks that drifted from this one would start letting through tasks that verification
// then goes on to sign. Keep them one implementation.
func (cv *Verifier) resolveSignablePayload(verificationTask *verifier.VerificationTask) (signablePayload, error) {
	msgIDStr := verificationTask.MessageID
	messageID, err := protocol.NewBytes32FromString(msgIDStr)
	if err != nil {
		return signablePayload{}, fmt.Errorf("failed to convert messageID to Bytes32: %w", err)
	}

	// 1. Validate that the message comes from a configured source chain
	sourceConfig, exists := cv.config.SourceConfigs[verificationTask.Message.SourceChainSelector]
	if !exists {
		return signablePayload{}, fmt.Errorf("message source chain selector %d is not configured for message %s", verificationTask.Message.SourceChainSelector, msgIDStr)
	}

	// 2. Validate message format and check verifier receipts
	if err := ValidateVerificationTask(verificationTask); err != nil {
		return signablePayload{}, fmt.Errorf(
			"task validation failed for message %s with verifier address %s and default executor address %s: %w",
			msgIDStr,
			sourceConfig.VerifierAddress.String(),
			sourceConfig.DefaultExecutorAddress.String(),
			err,
		)
	}

	// 3. Resolve the blob the signature commits to, preferring this verifier's own receipt.
	var verifierBlob []byte
	for _, receipt := range verificationTask.ReceiptBlobs {
		if bytes.Equal(receipt.Issuer.Bytes(), sourceConfig.VerifierAddress.Bytes()) {
			verifierBlob = receipt.Blob
			break
		}
	}
	if len(verifierBlob) > 0 {
		return signablePayload{messageID: messageID, sourceConfig: sourceConfig, blob: verifierBlob}, nil
	}

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
		return signablePayload{}, fmt.Errorf("neither verifier nor default executor blob found for message %s, all issuers: %v, expected issuer: %s (verifier) or %s (default executor)",
			msgIDStr,
			issuers,
			sourceConfig.VerifierAddress.String(),
			sourceConfig.DefaultExecutorAddress.String(),
		)
	}

	// Fall back to the message discovery version if the default executor is found.
	return signablePayload{
		messageID:            messageID,
		sourceConfig:         sourceConfig,
		blob:                 protocol.MessageDiscoveryVersion,
		usedDiscoveryVersion: true,
	}, nil
}

// ValidateTask reports whether verification would reject this task before it ever signs. A
// non-nil error is the error VerifyMessages would attach to the task's result, so a caller that
// diverts the task on a non-nil error changes nothing about where the task ends up.
//
// The policy gate uses this to keep the operator's endpoint out of the path of a message this
// verifier is going to reject anyway. See resolveSignablePayload for why the two paths have to
// stay a single implementation.
func (cv *Verifier) ValidateTask(verificationTask *verifier.VerificationTask) error {
	_, err := cv.resolveSignablePayload(verificationTask)
	return err
}

var _ verifier.TaskValidator = (*Verifier)(nil)

// verifyMessage verifies a single message (internal helper)
// Returns the VerifierNodeResult if successful, or an error if verification fails.
func (cv *Verifier) verifyMessage(_ context.Context, verificationTask verifier.VerificationTask) (*protocol.VerifierNodeResult, error) {
	message := verificationTask.Message
	msgIDStr := verificationTask.MessageID

	cv.lggr.Debugw("Starting message verification",
		protocol.LogKeyMessageID, msgIDStr,
		protocol.LogKeyNonce, message.SequenceNumber,
		protocol.LogKeySourceChain, message.SourceChainSelector,
		protocol.LogKeyDestChain, message.DestChainSelector,
	)

	payload, err := cv.resolveSignablePayload(&verificationTask)
	if err != nil {
		return nil, err
	}

	cv.lggr.Debugw("Message validation passed",
		protocol.LogKeyMessageID, payload.messageID,
		"verifierAddress", payload.sourceConfig.VerifierAddress,
		"defaultExecutorAddress", payload.sourceConfig.DefaultExecutorAddress,
	)
	if payload.usedDiscoveryVersion {
		cv.lggr.Debugw("Using message discovery version for message",
			protocol.LogKeyMessageID, payload.messageID,
			"version", hexutil.Encode(payload.blob),
		)
	}

	hash, err := committee.NewSignableHash(payload.messageID, payload.blob)
	if err != nil {
		return nil, fmt.Errorf("failed to create signable hash for message %s: %w", payload.messageID.String(), err)
	}

	encodedSignature, err := cv.signer.Sign(hash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign message %s: %w", msgIDStr, err)
	}

	cv.lggr.Debugw("Message signed successfully",
		protocol.LogKeyMessageID, msgIDStr,
		"signer", cv.signerAddress,
		"signatureLength", len(encodedSignature),
	)

	// 4. Create CCV node data with all required fields
	ccvNodeData, err := CreateVerifierNodeResult(&verificationTask, encodedSignature, payload.blob)
	if err != nil {
		return nil, fmt.Errorf("failed to create CCV node data for message %s: %w", msgIDStr, err)
	}

	// PER-MESSAGE LOG (status): signing complete; storage write is the terminal success.
	cv.lggr.Infow("Message verification completed successfully",
		protocol.LogTypeKey, protocol.LogTypeMessageStatus,
		protocol.LogKeyMessageID, msgIDStr,
		protocol.LogKeyNonce, message.SequenceNumber,
		protocol.LogKeySourceChain, message.SourceChainSelector,
		protocol.LogKeyDestChain, message.DestChainSelector,
	)

	return ccvNodeData, nil
}
