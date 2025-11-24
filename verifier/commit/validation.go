package commit

import (
	"bytes"
	"fmt"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
)

// ValidateMessage validates a verification task message using the new format.
func ValidateMessage(
	verificationTask *verifier.VerificationTask,
	verifierOnRampAddress protocol.UnknownAddress,
	defaultExecutorOnRampAddress protocol.UnknownAddress,
) error {
	if verificationTask == nil {
		return fmt.Errorf("verification task is nil")
	}

	message := verificationTask.Message
	// TODO: this check seems redundant - its already done in Verifier.ValidateMessage.
	if message.Version != protocol.MessageVersion {
		return fmt.Errorf("unsupported message version: %d", message.Version)
	}

	messageID, err := message.MessageID()
	if err != nil {
		return fmt.Errorf("failed to compute message ID: %w", err)
	}
	if bytes.Equal(messageID[:], make([]byte, 32)) {
		return fmt.Errorf("message ID is empty")
	}

	// Receipt blobs list must not be empty
	if len(verificationTask.ReceiptBlobs) == 0 {
		return fmt.Errorf("receipt blobs list is empty, at least one receipt blob is required")
	}

	// Check if the verifier onramp address or the default executor onramp address is found as issuer in any receipt blob
	found := false
	for _, receipt := range verificationTask.ReceiptBlobs {
		isVerifierOnRamp := bytes.Equal(receipt.Issuer.Bytes(), verifierOnRampAddress.Bytes())
		isDefaultExecutorOnRamp := bytes.Equal(receipt.Issuer.Bytes(), defaultExecutorOnRampAddress.Bytes())
		if isVerifierOnRamp || isDefaultExecutorOnRamp {
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf(
			"verifier onramp address %s or default executor onramp address %s not found as issuer in any receipt blob",
			verifierOnRampAddress.String(),
			defaultExecutorOnRampAddress.String(),
		)
	}

	// Validate that ccvAndExecutorHash is not zero - it's required
	if message.CcvAndExecutorHash == (protocol.Bytes32{}) {
		return fmt.Errorf(
			"ccvAndExecutorHash is required and cannot be zero",
		)
	}

	// Validate ccvAndExecutorHash
	if err := validateCCVAndExecutorHash(verificationTask); err != nil {
		return fmt.Errorf("ccvAndExecutorHash validation failed: %w", err)
	}

	return nil
}

// validateCCVAndExecutorHash validates that the message's ccvAndExecutorHash matches
// the hash computed from CCV addresses and executor address extracted from receipt blobs.
func validateCCVAndExecutorHash(verificationTask *verifier.VerificationTask) error {
	message := verificationTask.Message

	if len(verificationTask.ReceiptBlobs) == 0 {
		return fmt.Errorf("no receipt blobs to extract CCV and executor addresses from")
	}

	// Calculate number of token transfers and CCV receipts
	numTokenTransfers := 0
	if message.TokenTransferLength != 0 {
		numTokenTransfers = 1
	}
	numCCVBlobs := len(verificationTask.ReceiptBlobs) - numTokenTransfers - 1

	if numCCVBlobs < 0 {
		return fmt.Errorf("invalid receipt structure: insufficient receipts (got %d, need at least %d for tokens + executor)",
			len(verificationTask.ReceiptBlobs), numTokenTransfers+1)
	}

	// Parse receipt structure
	receiptStructure, err := protocol.ParseReceiptStructure(
		verificationTask.ReceiptBlobs,
		numCCVBlobs,
		numTokenTransfers,
	)
	if err != nil {
		return fmt.Errorf("failed to parse receipt structure: %w", err)
	}

	return message.ValidateCCVAndExecutorHash(receiptStructure.CCVAddresses, receiptStructure.ExecutorAddress)
}
