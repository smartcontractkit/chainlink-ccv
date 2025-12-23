package commit

import (
	"fmt"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
)

// CreateVerifierNodeResult creates CCVNodeData from verification task and signature.
func CreateVerifierNodeResult(verificationTask *verifier.VerificationTask, signature, verifierBlob []byte) (*protocol.VerifierNodeResult, error) {
	message := verificationTask.Message

	messageID, err := protocol.NewBytes32FromString(verificationTask.MessageID)
	if err != nil {
		return nil, fmt.Errorf("failed to convert messageID to Bytes32: %w", err)
	}

	// Calculate number of CCV receipts from the receipt structure.
	// Structure: [CCVs...] + [Token at length-2 (if exists)] + [Executor at length-2] + [Network fee at length-1]
	// Therefore: numCCVs = totalReceipts - numTokens - 2 (executor + network fee)
	// OnRamp allows 0 or 1 token. Check if TokenTransferLength indicates actual token data.
	// Empty token transfer is MinSizeRequiredMsgTokenFields (39 bytes), actual token is larger.
	numTokenTransfers := 0
	if message.TokenTransferLength != 0 {
		numTokenTransfers = 1
	}
	numCCVBlobs := len(verificationTask.ReceiptBlobs) - numTokenTransfers - 2

	if numCCVBlobs < 0 {
		return nil, fmt.Errorf("invalid receipt structure: insufficient receipts (got %d, need at least %d for tokens + executor)",
			len(verificationTask.ReceiptBlobs), numTokenTransfers+2)
	}

	// Parse receipt structure using the helper function
	receiptStructure, err := protocol.ParseReceiptStructure(
		verificationTask.ReceiptBlobs,
		numCCVBlobs,
		numTokenTransfers,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to parse receipt structure: %w", err)
	}

	return &protocol.VerifierNodeResult{
		MessageID:       messageID,
		Message:         message,
		CCVVersion:      verifierBlob,
		CCVAddresses:    receiptStructure.CCVAddresses,
		ExecutorAddress: receiptStructure.ExecutorAddress,
		Signature:       signature,
	}, nil
}
