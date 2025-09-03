package commit

import (
	"bytes"
	"fmt"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol/common"
	"github.com/smartcontractkit/chainlink-ccv/verifier/types"
	"github.com/smartcontractkit/chainlink-ccv/verifier/utils"
)

// ValidateMessage validates a verification task message using the new format
func ValidateMessage(verificationTask *types.VerificationTask, verifierOnRampAddress common.UnknownAddress) error {
	if verificationTask == nil {
		return fmt.Errorf("verification task is nil")
	}

	message := verificationTask.Message
	if message.Version != common.MessageVersion {
		return fmt.Errorf("unsupported message version: %d", message.Version)
	}

	messageID, err := message.MessageID()
	if err != nil {
		return fmt.Errorf("failed to compute message ID: %w", err)
	}
	if bytes.Equal(messageID[:], make([]byte, 32)) {
		return fmt.Errorf("message ID is empty")
	}

	// Check if the verifier onramp address is found as issuer in any receipt blob
	found := false
	for _, receipt := range verificationTask.ReceiptBlobs {
		if bytes.Equal(receipt.Issuer.Bytes(), verifierOnRampAddress.Bytes()) {
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("verifier onramp address %s not found as issuer in any receipt blob", verifierOnRampAddress.String())
	}

	return nil
}

// CreateCCVData creates CCVData from verification task, signature, and blob using the new format
func CreateCCVData(verificationTask *types.VerificationTask, signature []byte, verifierBlob []byte, sourceVerifierAddress common.UnknownAddress) (*common.CCVData, error) {
	message := verificationTask.Message
	messageID, err := message.MessageID()
	if err != nil {
		return nil, fmt.Errorf("failed to compute message ID: %w", err)
	}
	// Find the receipt blob that corresponds to our source verifier address
	verifierIndex, err := utils.FindVerifierIndexBySourceAddress(verificationTask, sourceVerifierAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to find verifier index: %w", err)
	}

	// Get the receipt blob at the verifier index
	if verifierIndex >= len(verificationTask.ReceiptBlobs) {
		return nil, fmt.Errorf("verifier index %d is out of bounds for receipt blobs (length: %d)", verifierIndex, len(verificationTask.ReceiptBlobs))
	}
	receiptBlob := verificationTask.ReceiptBlobs[verifierIndex]

	return &common.CCVData{
		MessageID:             messageID,
		SequenceNumber:        message.SequenceNumber,
		SourceChainSelector:   message.SourceChainSelector,
		DestChainSelector:     message.DestChainSelector,
		SourceVerifierAddress: sourceVerifierAddress,
		DestVerifierAddress:   common.UnknownAddress{}, // Will be set by the caller if needed
		CCVData:               signature,
		Timestamp:             time.Now().UnixMicro(), // Unix timestamp in microseconds
		Message:               message,
		ReceiptBlob:           receiptBlob,
	}, nil
}
