package chainaccess

import "github.com/smartcontractkit/chainlink-ccv/protocol"

// VerifierIssuerFilter filters protocol.MessageSentEvent to only include those
// that have at least one receipt issued by the specified verifier issuer address.
type VerifierIssuerFilter struct {
	issuerAddress protocol.UnknownAddress
}

func NewVerifierIssuerFilter(
	issuerAddress protocol.UnknownAddress,
) MessageFilter {
	return &VerifierIssuerFilter{
		issuerAddress: issuerAddress,
	}
}

func (v *VerifierIssuerFilter) Filter(msg protocol.MessageSentEvent) bool {
	for _, receipt := range msg.Receipts {
		if v.issuerAddress.Equal(receipt.Issuer) {
			return true
		}
	}
	return false
}

// CompositeMessageFilter combines multiple MessageFilters using logical AND.
// Works as allow-all if no filters are provided.
type CompositeMessageFilter struct {
	filters []MessageFilter
}

func NewCompositeMessageFilter(filters ...MessageFilter) MessageFilter {
	return &CompositeMessageFilter{
		filters: filters,
	}
}

func (c *CompositeMessageFilter) Filter(msg protocol.MessageSentEvent) bool {
	for _, filter := range c.filters {
		if !filter.Filter(msg) {
			return false
		}
	}
	return true
}
