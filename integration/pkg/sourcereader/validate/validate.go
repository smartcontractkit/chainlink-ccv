package validate

import (
	"fmt"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// CCVAndExecutorHash validates that the message's ccvAndExecutorHash matches
// the hash computed from CCV addresses and executor address extracted from receipt blobs.
func CCVAndExecutorHash(message protocol.Message, receiptBlobs []protocol.ReceiptWithBlob) error {
	if len(receiptBlobs) == 0 {
		return fmt.Errorf("no receipt blobs to extract CCV and executor addresses from")
	}

	// Calculate number of token transfers and CCV receipts
	numTokenTransfers := 0
	if message.TokenTransferLength != 0 {
		numTokenTransfers = 1
	}
	numCCVBlobs := len(receiptBlobs) - numTokenTransfers - 2 // Executor + network fee

	if numCCVBlobs < 0 {
		return fmt.Errorf("invalid receipt structure: insufficient receipts (got %d, need at least %d for tokens + executor + network fee)",
			len(receiptBlobs), numTokenTransfers+2)
	}

	// Parse receipt structure
	receiptStructure, err := protocol.ParseReceiptStructure(
		receiptBlobs,
		numCCVBlobs,
		numTokenTransfers,
	)
	if err != nil {
		return fmt.Errorf("failed to parse receipt structure: %w", err)
	}

	return message.ValidateCCVAndExecutorHash(receiptStructure.CCVAddresses, receiptStructure.ExecutorAddress)
}
