package chainaccess

import "github.com/smartcontractkit/chainlink-ccv/protocol"

// ReceiptIssuerFilter filters protocol.MessageSentEvent to only include those
// that have at all issuerAddresses present in their receipts.
type ReceiptIssuerFilter struct {
	issuerAddresses []protocol.UnknownAddress
}

func NewReceiptIssuerFilter(
	issuerAddress ...protocol.UnknownAddress,
) MessageFilter {
	return &ReceiptIssuerFilter{
		issuerAddresses: issuerAddress,
	}
}

func (v *ReceiptIssuerFilter) Filter(msg protocol.MessageSentEvent) bool {
	receipts := make(map[string]struct{})
	for _, receipt := range msg.Receipts {
		receipts[receipt.Issuer.String()] = struct{}{}
	}
	for _, addr := range v.issuerAddresses {
		if _, exists := receipts[addr.String()]; !exists {
			return false
		}
	}
	return true
}
