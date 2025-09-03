package commit

import (
	"context"
	"fmt"

	"github.com/smartcontractkit/chainlink-ccv/protocol/common"
	"github.com/smartcontractkit/chainlink-ccv/verifier/types"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// MessageSigner defines the interface for message signers
type MessageSigner interface {
	SignMessage(ctx context.Context, verificationTask types.VerificationTask, sourceVerifierAddress common.UnknownAddress) ([]byte, []byte, error)
	GetSignerAddress() common.UnknownAddress
}

// CommitVerifier provides a basic verifier implementation using the new message format
type CommitVerifier struct {
	config types.CoordinatorConfig
	signer MessageSigner
	lggr   logger.Logger
}

// NewCommitVerifier creates a new commit verifier
func NewCommitVerifier(config types.CoordinatorConfig, signer MessageSigner, lggr logger.Logger) *CommitVerifier {
	return &CommitVerifier{
		config: config,
		signer: signer,
		lggr:   lggr,
	}
}

// ValidateMessage validates the new message format
func (cv *CommitVerifier) ValidateMessage(message common.Message) error {
	if message.Version != common.MessageVersion {
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

// VerifyMessage verifies a message using the new chain-agnostic format
func (cv *CommitVerifier) VerifyMessage(ctx context.Context, verificationTask types.VerificationTask, ccvDataCh chan<- common.CCVData) error {
	message := verificationTask.Message

	messageID, err := message.MessageID()
	if err != nil {
		return fmt.Errorf("failed to compute message ID: %w", err)
	}

	cv.lggr.Debugw("Starting message verification",
		"messageID", messageID,
		"sequenceNumber", message.SequenceNumber,
		"sourceChain", message.SourceChainSelector,
		"destChain", message.DestChainSelector,
	)

	// 1. Validate that the message comes from a configured source chain
	sourceConfig, exists := cv.config.SourceConfigs[message.SourceChainSelector]
	if !exists {
		return fmt.Errorf("message source chain selector %d is not configured", message.SourceChainSelector)
	}

	// 2. Validate message format and check verifier receipts
	if err := cv.ValidateMessage(message); err != nil {
		return fmt.Errorf("message format validation failed: %w", err)
	}

	if err := ValidateMessage(&verificationTask, sourceConfig.VerifierAddress); err != nil {
		return fmt.Errorf("message validation failed: %w", err)
	}

	cv.lggr.Debugw("Message validation passed",
		"messageID", messageID,
		"verifierAddress", sourceConfig.VerifierAddress.String(),
	)

	// 3. Sign the message event using the new chain-agnostic method
	signature, verifierBlob, err := cv.signer.SignMessage(ctx, verificationTask, sourceConfig.VerifierAddress)
	if err != nil {
		return fmt.Errorf("failed to sign message event: %w", err)
	}

	cv.lggr.Infow("Message signed successfully",
		"messageID", messageID,
		"signerAddress", cv.signer.GetSignerAddress().String(),
		"signatureLength", len(signature),
		"blobLength", len(verifierBlob),
	)

	// 4. Create CCV data with all required fields
	ccvData, err := CreateCCVData(&verificationTask, signature, verifierBlob, sourceConfig.VerifierAddress)
	if err != nil {
		return fmt.Errorf("failed to create CCV data: %w", err)
	}

	// Send CCVData to channel for storage
	select {
	case ccvDataCh <- *ccvData:
		cv.lggr.Infow("CCV data sent to storage channel",
			"messageID", messageID,
			"sequenceNumber", message.SequenceNumber,
			"sourceChain", message.SourceChainSelector,
			"destChain", message.DestChainSelector,
			"timestamp", ccvData.Timestamp,
		)
	case <-ctx.Done():
		cv.lggr.Debugw("Context cancelled while sending CCV data",
			"messageID", messageID,
			"sequenceNumber", message.SequenceNumber,
			"sourceChain", message.SourceChainSelector,
		)
	}

	return nil
}
