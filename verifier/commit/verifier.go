package commit

import (
	"context"
	"fmt"

	"github.com/smartcontractkit/chainlink-ccv/verifier"
	"github.com/smartcontractkit/chainlink-ccv/verifier/internal/utils"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	protocol "github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
)

// Verifier provides a basic verifier implementation using the new message format.
type Verifier struct {
	signer verifier.MessageSigner
	lggr   logger.Logger
	// TODO: Use a separate config
	config verifier.CoordinatorConfig
}

// NewCommitVerifier creates a new commit verifier.
func NewCommitVerifier(config verifier.CoordinatorConfig, signer verifier.MessageSigner, lggr logger.Logger) verifier.Verifier {
	return &Verifier{
		config: config,
		signer: signer,
		lggr:   lggr,
	}
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

// VerifyMessage verifies a message using the new chain-agnostic format.
func (cv *Verifier) VerifyMessage(ctx context.Context, verificationTask verifier.VerificationTask, ccvDataCh chan<- protocol.CCVData, verificationErrorCh chan<- verifier.VerificationError) {
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

	// 3. Sign the message event using the new chain-agnostic method
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

	// Send CCVData to channel for storage
	select {
	case ccvDataCh <- *ccvData:
		cv.lggr.Infow("CCV data sent to storage channel",
			"messageID", messageID,
			"nonce", message.Nonce,
			"sourceChain", message.SourceChainSelector,
			"destChain", message.DestChainSelector,
			"timestamp", ccvData.Timestamp,
		)
	case <-ctx.Done():
		cv.lggr.Debugw("Context cancelled while sending CCV data",
			"messageID", messageID,
			"nonce", message.Nonce,
			"sourceChain", message.SourceChainSelector,
		)
	}
}
