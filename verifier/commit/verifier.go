package commit

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/batcher"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
	"github.com/smartcontractkit/chainlink-ccv/verifier/internal/utils"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/common"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// Verifier provides a basic verifier implementation using the new message format.
type Verifier struct {
	signer     verifier.MessageSigner
	lggr       logger.Logger
	monitoring common.VerifierMonitoring
	// TODO: Use a separate config
	config verifier.CoordinatorConfig
}

// NewCommitVerifier creates a new commit verifier.
func NewCommitVerifier(config verifier.CoordinatorConfig, signer verifier.MessageSigner, lggr logger.Logger, monitoring common.VerifierMonitoring) (verifier.Verifier, error) {
	cv := &Verifier{
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
func (cv *Verifier) VerifyMessages(ctx context.Context, tasks []verifier.VerificationTask, ccvDataBatcher *batcher.Batcher[protocol.CCVData], verificationErrorCh chan<- verifier.VerificationError) {
	if len(tasks) == 0 {
		return
	}

	cv.lggr.Debugw("Starting batch verification", "batchSize", len(tasks))

	// Process tasks concurrently
	var wg sync.WaitGroup
	for _, task := range tasks {
		wg.Add(1)
		go func(verificationTask verifier.VerificationTask) {
			defer wg.Done()
			cv.verifyMessage(ctx, verificationTask, ccvDataBatcher, verificationErrorCh)
		}(task)
	}

	wg.Wait()
	cv.lggr.Debugw("Batch verification completed", "batchSize", len(tasks))
}

// verifyMessage verifies a single message (internal helper)
func (cv *Verifier) verifyMessage(ctx context.Context, verificationTask verifier.VerificationTask, ccvDataBatcher *batcher.Batcher[protocol.CCVData], verificationErrorCh chan<- verifier.VerificationError) {
	start := time.Now()
	message := verificationTask.Message

	messageID, err := message.MessageID()
	if err != nil {
		utils.SendVerificationError(ctx, verificationTask, fmt.Errorf("failed to compute message ID: %w", err), verificationErrorCh, cv.lggr)
		return
	}

	cv.lggr.Debugw("Starting message verification",
		"messageID", messageID,
		"nonce", message.Nonce,
		"sourceChain", message.SourceChainSelector,
		"destChain", message.DestChainSelector,
	)

	// 1. Validate that the message comes from a configured source chain
	sourceConfig, exists := cv.config.SourceConfigs[message.SourceChainSelector]
	if !exists {
		utils.SendVerificationError(ctx, verificationTask, fmt.Errorf("message source chain selector %d is not configured", message.SourceChainSelector), verificationErrorCh, cv.lggr)
		return
	}

	// 2. Validate message format and check verifier receipts
	if err := cv.ValidateMessage(message); err != nil {
		utils.SendVerificationError(ctx, verificationTask, fmt.Errorf("message format validation failed: %w", err), verificationErrorCh, cv.lggr)
		return
	}

	if err := ValidateMessage(&verificationTask, sourceConfig.VerifierAddress); err != nil {
		utils.SendVerificationError(ctx, verificationTask, fmt.Errorf("message validation failed: %w", err), verificationErrorCh, cv.lggr)
		return
	}

	cv.lggr.Infow("Message validation passed",
		"messageID", messageID,
		"verifierAddress", sourceConfig.VerifierAddress.String(),
	)

	encodedSignature, err := cv.signer.SignMessage(ctx, verificationTask, sourceConfig.VerifierAddress)
	if err != nil {
		utils.SendVerificationError(ctx, verificationTask, fmt.Errorf("failed to sign message event: %w", err), verificationErrorCh, cv.lggr)
		return
	}

	cv.lggr.Infow("Message signed successfully",
		"messageID", messageID,
		"signerAddress", cv.signer.GetSignerAddress().String(),
		"signatureLength", len(encodedSignature),
	)

	// 4. Create CCV data with all required fields
	ccvData, err := CreateCCVData(&verificationTask, encodedSignature, []byte{}, sourceConfig.VerifierAddress)
	if err != nil {
		utils.SendVerificationError(ctx, verificationTask, fmt.Errorf("failed to create CCV data: %w", err), verificationErrorCh, cv.lggr)
		return
	}

	// Add CCVData directly to batcher
	if err := ccvDataBatcher.Add(*ccvData); err != nil {
		cv.lggr.Errorw("Error adding CCV data to batcher",
			"error", err,
			"messageID", messageID,
			"nonce", message.Nonce,
			"sourceChain", message.SourceChainSelector,
		)
		return
	}

	// Record successful message processing
	cv.monitoring.Metrics().
		With("source_chain", message.SourceChainSelector.String(), "dest_chain", message.DestChainSelector.String(), "verifier_id", cv.config.VerifierID).
		IncrementMessagesProcessed(ctx)
	cv.monitoring.Metrics().
		With("source_chain", message.SourceChainSelector.String(), "verifier_id", cv.config.VerifierID).
		RecordMessageVerificationDuration(ctx, time.Since(start))

	cv.lggr.Infow("CCV data added to batcher",
		"messageID", messageID,
		"nonce", message.Nonce,
		"sourceChain", message.SourceChainSelector,
		"destChain", message.DestChainSelector,
		"timestamp", ccvData.Timestamp,
	)
}
