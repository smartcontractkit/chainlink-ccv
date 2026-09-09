package chainaccess

import (
	"math/big"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// NewMessageDetails builds the shared reader view from already-decoded event data, without
// RPCs or API-specific types. Readers surface it alongside the original message, whose bytes
// remain unchanged. It is also usable when reading older persisted events or tasks.
func NewMessageDetails(message protocol.Message, receipts []protocol.ReceiptWithBlob, feeToken protocol.UnknownAddress) *protocol.MessageDetails {
	details := &protocol.MessageDetails{
		OnRampAddress:  normalizeAddress(message.OnRampAddress),
		OffRampAddress: normalizeAddress(message.OffRampAddress),
		Sender:         normalizeAddress(message.Sender),
		Receiver:       normalizeAddress(message.Receiver),
		FeeToken:       normalizeAddress(feeToken),
		FeeTokenAmount: totalFeeTokenAmount(receipts),
		Finality:       message.Finality.Requirement(),
	}
	if transfer := message.TokenTransfer; transfer != nil {
		details.SourcePoolAddress = normalizeAddress(transfer.SourcePoolAddress)
		details.SourceTokenAddress = normalizeAddress(transfer.SourceTokenAddress)
		details.DestTokenAddress = normalizeAddress(transfer.DestTokenAddress)
		details.TokenReceiver = normalizeAddress(transfer.TokenReceiver)
	}
	return details
}

// normalizeAddress uses one chain-independent representation: at least 32 bytes, padded
// on the left. It preserves longer addresses and all their leading zeros. Every non-empty
// result owns its bytes so consumers cannot mutate the original message through this view.
func normalizeAddress(address []byte) protocol.UnknownAddress {
	if len(address) == 0 {
		return nil
	}
	normalized := make(protocol.UnknownAddress, max(32, len(address)))
	copy(normalized[len(normalized)-len(address):], address)
	return normalized
}

// totalFeeTokenAmount includes every receipt, including token, executor and network fees.
// Missing receipts or amounts mean unknown; a known zero fee remains a non-nil zero value.
func totalFeeTokenAmount(receipts []protocol.ReceiptWithBlob) *big.Int {
	if len(receipts) == 0 {
		return nil
	}
	total := new(big.Int)
	for _, receipt := range receipts {
		if receipt.FeeTokenAmount == nil {
			return nil
		}
		total.Add(total, receipt.FeeTokenAmount)
	}
	return total
}
