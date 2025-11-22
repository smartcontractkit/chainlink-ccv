package protocol

import (
	"fmt"
)

// ReceiptStructure represents the parsed structure of receipts from an OnRamp event.
// Receipt structure from OnRamp.sol _getReceipts():
// - Array size: ccvs.length + tokenAmounts.length + 1
// - CCVs: indices [0 .. ccvs.length-1]
// - Executor: index [length-1] (always last)
// - Token: index [length-2] (second-to-last, if tokenAmounts.length > 0)
// Example with 2 CCVs, 1 token: [CCV0, CCV1, Token, Executor]
// Example with 2 CCVs, 0 tokens: [CCV0, CCV1, Executor].
type ReceiptStructure struct {
	CCVReceipts     []ReceiptWithBlob
	TokenReceipts   []ReceiptWithBlob
	ExecutorReceipt ReceiptWithBlob
	CCVAddresses    []UnknownAddress
	ExecutorAddress UnknownAddress
}

// ParseReceiptStructure parses receipts according to CCIP OnRamp structure.
// It validates that receipts match the expected structure and extracts:
// - CCV receipts (first numCCVBlobs receipts, each with a corresponding blob)
// - Executor receipt (always at index length-1)
// - Token receipts (at index length-2 if numTokenTransfers > 0).
func ParseReceiptStructure(receipts []ReceiptWithBlob, numCCVBlobs, numTokenTransfers int) (*ReceiptStructure, error) {
	if len(receipts) == 0 {
		return nil, fmt.Errorf("no receipts provided")
	}

	// Validate structure: CCVs + Tokens + 1 Executor = Total
	expectedReceipts := numCCVBlobs + numTokenTransfers + 1
	if len(receipts) != expectedReceipts {
		return nil, fmt.Errorf("unexpected receipt count: got %d, expected %d (CCVs=%d + Tokens=%d + Executor=1)",
			len(receipts), expectedReceipts, numCCVBlobs, numTokenTransfers)
	}

	result := &ReceiptStructure{
		CCVReceipts:   make([]ReceiptWithBlob, 0, numCCVBlobs),
		TokenReceipts: make([]ReceiptWithBlob, 0, numTokenTransfers),
		CCVAddresses:  make([]UnknownAddress, 0, numCCVBlobs),
	}

	// Extract CCV receipts (first numCCVBlobs)
	for i := 0; i < numCCVBlobs; i++ {
		result.CCVReceipts = append(result.CCVReceipts, receipts[i])
		result.CCVAddresses = append(result.CCVAddresses, receipts[i].Issuer)
	}

	// Extract executor receipt (always last at index length-1)
	result.ExecutorReceipt = receipts[len(receipts)-1]
	result.ExecutorAddress = result.ExecutorReceipt.Issuer

	// Extract token receipt (at index length-2 if present)
	if numTokenTransfers > 0 {
		result.TokenReceipts = append(result.TokenReceipts, receipts[len(receipts)-2])
	}

	return result, nil
}
