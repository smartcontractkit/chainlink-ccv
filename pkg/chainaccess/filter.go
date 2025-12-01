package chainaccess

import "github.com/smartcontractkit/chainlink-ccv/protocol"

// ReceiptIssuerFilter filters protocol.MessageSentEvent to only include those
// that have at least one of issuerAddresses present in their receipts.
type ReceiptIssuerFilter struct {
	issuerAddresses map[string]struct{}
}

func NewReceiptIssuerFilter(
	issuerAddress ...protocol.UnknownAddress,
) MessageFilter {
	issuerAddresses := make(map[string]struct{})
	for _, addr := range issuerAddress {
		issuerAddresses[addr.String()] = struct{}{}
	}
	return &ReceiptIssuerFilter{
		issuerAddresses: issuerAddresses,
	}
}

func (v *ReceiptIssuerFilter) Filter(msg protocol.MessageSentEvent) bool {
	for _, receipt := range msg.Receipts {
		if _, exists := v.issuerAddresses[receipt.Issuer.String()]; exists {
			return true
		}
	}
	return false
}
