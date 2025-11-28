package chainaccess

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

func TestVerifierIssuerFilter_Filter(t *testing.T) {
	targetIssuer := protocol.UnknownAddress("0x1234567890abcdef")
	otherIssuer1 := protocol.UnknownAddress("0xabcdef1234567890")
	otherIssuer2 := protocol.UnknownAddress("0xfedcba0987654321")

	tests := []struct {
		name     string
		issuer   protocol.UnknownAddress
		msg      protocol.MessageSentEvent
		expected bool
	}{
		{
			name:   "no receipts - should return false",
			issuer: targetIssuer,
			msg: protocol.MessageSentEvent{
				Receipts: []protocol.ReceiptWithBlob{},
			},
			expected: false,
		},
		{
			name:   "single receipt with matching issuer - should return true",
			issuer: targetIssuer,
			msg: protocol.MessageSentEvent{
				Receipts: []protocol.ReceiptWithBlob{
					{Issuer: targetIssuer},
				},
			},
			expected: true,
		},
		{
			name:   "single receipt with non-matching issuer - should return false",
			issuer: targetIssuer,
			msg: protocol.MessageSentEvent{
				Receipts: []protocol.ReceiptWithBlob{
					{Issuer: otherIssuer1},
				},
			},
			expected: false,
		},
		{
			name:   "multiple receipts with matching issuer as first - should return true",
			issuer: targetIssuer,
			msg: protocol.MessageSentEvent{
				Receipts: []protocol.ReceiptWithBlob{
					{Issuer: targetIssuer},
					{Issuer: otherIssuer1},
					{Issuer: otherIssuer2},
				},
			},
			expected: true,
		},
		{
			name:   "multiple receipts with matching issuer in middle - should return true",
			issuer: targetIssuer,
			msg: protocol.MessageSentEvent{
				Receipts: []protocol.ReceiptWithBlob{
					{Issuer: otherIssuer1},
					{Issuer: targetIssuer},
					{Issuer: otherIssuer2},
				},
			},
			expected: true,
		},
		{
			name:   "multiple receipts with matching issuer as last - should return true",
			issuer: targetIssuer,
			msg: protocol.MessageSentEvent{
				Receipts: []protocol.ReceiptWithBlob{
					{Issuer: otherIssuer1},
					{Issuer: otherIssuer2},
					{Issuer: targetIssuer},
				},
			},
			expected: true,
		},
		{
			name:   "multiple receipts with no matching issuer - should return false",
			issuer: targetIssuer,
			msg: protocol.MessageSentEvent{
				Receipts: []protocol.ReceiptWithBlob{
					{Issuer: otherIssuer1},
					{Issuer: otherIssuer2},
				},
			},
			expected: false,
		},
		{
			name:   "multiple receipts with duplicate matching issuers - should return true",
			issuer: targetIssuer,
			msg: protocol.MessageSentEvent{
				Receipts: []protocol.ReceiptWithBlob{
					{Issuer: targetIssuer},
					{Issuer: otherIssuer1},
					{Issuer: targetIssuer},
				},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter := NewVerifierIssuerFilter(tt.issuer)
			result := filter.Filter(tt.msg)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCompositeMessageFilter_Filter(t *testing.T) {
	issuer1 := protocol.UnknownAddress("0x1111111111111111")
	issuer2 := protocol.UnknownAddress("0x2222222222222222")
	issuer3 := protocol.UnknownAddress("0x3333333333333333")

	tests := []struct {
		name     string
		filters  []MessageFilter
		msg      protocol.MessageSentEvent
		expected bool
	}{
		{
			name:    "no filters - should return true",
			filters: []MessageFilter{},
			msg: protocol.MessageSentEvent{
				Receipts: []protocol.ReceiptWithBlob{},
			},
			expected: true,
		},
		{
			name: "single filter matches - should return true",
			filters: []MessageFilter{
				NewVerifierIssuerFilter(issuer1),
			},
			msg: protocol.MessageSentEvent{
				Receipts: []protocol.ReceiptWithBlob{
					{Issuer: issuer1},
				},
			},
			expected: true,
		},
		{
			name: "single filter does not match - should return false",
			filters: []MessageFilter{
				NewVerifierIssuerFilter(issuer1),
			},
			msg: protocol.MessageSentEvent{
				Receipts: []protocol.ReceiptWithBlob{
					{Issuer: issuer2},
				},
			},
			expected: false,
		},
		{
			name: "multiple filters all match - should return true",
			filters: []MessageFilter{
				NewVerifierIssuerFilter(issuer1),
				NewVerifierIssuerFilter(issuer2),
			},
			msg: protocol.MessageSentEvent{
				Receipts: []protocol.ReceiptWithBlob{
					{Issuer: issuer1},
					{Issuer: issuer2},
				},
			},
			expected: true,
		},
		{
			name: "multiple filters first does not match - should return false",
			filters: []MessageFilter{
				NewVerifierIssuerFilter(issuer1),
				NewVerifierIssuerFilter(issuer2),
			},
			msg: protocol.MessageSentEvent{
				Receipts: []protocol.ReceiptWithBlob{
					{Issuer: issuer2},
				},
			},
			expected: false,
		},
		{
			name: "multiple filters second does not match - should return false",
			filters: []MessageFilter{
				NewVerifierIssuerFilter(issuer1),
				NewVerifierIssuerFilter(issuer2),
			},
			msg: protocol.MessageSentEvent{
				Receipts: []protocol.ReceiptWithBlob{
					{Issuer: issuer1},
				},
			},
			expected: false,
		},
		{
			name: "multiple filters none match - should return false",
			filters: []MessageFilter{
				NewVerifierIssuerFilter(issuer1),
				NewVerifierIssuerFilter(issuer2),
			},
			msg: protocol.MessageSentEvent{
				Receipts: []protocol.ReceiptWithBlob{
					{Issuer: issuer3},
				},
			},
			expected: false,
		},
		{
			name: "three filters all match - should return true",
			filters: []MessageFilter{
				NewVerifierIssuerFilter(issuer1),
				NewVerifierIssuerFilter(issuer2),
				NewVerifierIssuerFilter(issuer3),
			},
			msg: protocol.MessageSentEvent{
				Receipts: []protocol.ReceiptWithBlob{
					{Issuer: issuer1},
					{Issuer: issuer2},
					{Issuer: issuer3},
				},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter := NewCompositeMessageFilter(tt.filters...)
			result := filter.Filter(tt.msg)
			assert.Equal(t, tt.expected, result)
		})
	}
}
