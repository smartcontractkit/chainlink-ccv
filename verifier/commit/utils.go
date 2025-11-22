package commit

import (
	"fmt"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
)

// CreateCCVNodeData creates CCVNodeData from verification task and signature.
func CreateCCVNodeData(verificationTask *verifier.VerificationTask, signature, verifierBlob []byte) (*protocol.CCVNodeData, error) {
	message := verificationTask.Message

	messageID, err := message.MessageID()
	if err != nil {
		return nil, fmt.Errorf("failed to compute message ID: %w", err)
	}

	// Calculate number of CCV receipts from the receipt structure.
	// Structure: [CCVs...] + [Token at length-2 (if exists)] + [Executor at length-1]
	// Therefore: numCCVs = totalReceipts - numTokens - 1 (executor)
	// OnRamp allows 0 or 1 token. Check if TokenTransferLength indicates actual token data.
	// Empty token transfer is MinSizeRequiredMsgTokenFields (39 bytes), actual token is larger.
	numTokenTransfers := 0
	if message.TokenTransferLength > protocol.MinSizeRequiredMsgTokenFields {
		numTokenTransfers = 1
	}
	numCCVBlobs := len(verificationTask.ReceiptBlobs) - numTokenTransfers - 1

	if numCCVBlobs < 0 {
		return nil, fmt.Errorf("invalid receipt structure: insufficient receipts (got %d, need at least %d for tokens + executor)",
			len(verificationTask.ReceiptBlobs), numTokenTransfers+1)
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

	return &protocol.CCVNodeData{
		MessageID:       messageID,
		Message:         message,
		CCVVersion:      verifierBlob,
		CCVAddresses:    receiptStructure.CCVAddresses,
		ExecutorAddress: receiptStructure.ExecutorAddress,
		Signature:       signature,
	}, nil
}
