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
	otherIssuer3 := protocol.UnknownAddress("0x1111111111111111")

	tests := []struct {
		name     string
		issuers  []protocol.UnknownAddress
		msg      protocol.MessageSentEvent
		expected bool
	}{
		{
			name:    "single issuer - no receipts - should return false",
			issuers: []protocol.UnknownAddress{targetIssuer},
			msg: protocol.MessageSentEvent{
				Receipts: []protocol.ReceiptWithBlob{},
			},
			expected: false,
		},
		{
			name:    "single issuer - single receipt with matching issuer - should return true",
			issuers: []protocol.UnknownAddress{targetIssuer},
			msg: protocol.MessageSentEvent{
				Receipts: []protocol.ReceiptWithBlob{
					{Issuer: targetIssuer},
				},
			},
			expected: true,
		},
		{
			name:    "single issuer - single receipt with non-matching issuer - should return false",
			issuers: []protocol.UnknownAddress{targetIssuer},
			msg: protocol.MessageSentEvent{
				Receipts: []protocol.ReceiptWithBlob{
					{Issuer: otherIssuer1},
				},
			},
			expected: false,
		},
		{
			name:    "single issuer - multiple receipts with matching issuer as first - should return true",
			issuers: []protocol.UnknownAddress{targetIssuer},
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
			name:    "single issuer - multiple receipts with matching issuer in middle - should return true",
			issuers: []protocol.UnknownAddress{targetIssuer},
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
			name:    "single issuer - multiple receipts with matching issuer as last - should return true",
			issuers: []protocol.UnknownAddress{targetIssuer},
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
			name:    "single issuer - multiple receipts with no matching issuer - should return false",
			issuers: []protocol.UnknownAddress{targetIssuer},
			msg: protocol.MessageSentEvent{
				Receipts: []protocol.ReceiptWithBlob{
					{Issuer: otherIssuer1},
					{Issuer: otherIssuer2},
				},
			},
			expected: false,
		},
		{
			name:    "single issuer - multiple receipts with duplicate matching issuers - should return true",
			issuers: []protocol.UnknownAddress{targetIssuer},
			msg: protocol.MessageSentEvent{
				Receipts: []protocol.ReceiptWithBlob{
					{Issuer: targetIssuer},
					{Issuer: otherIssuer1},
					{Issuer: targetIssuer},
				},
			},
			expected: true,
		},

		{
			name:    "multiple issuers - no receipts - should return false",
			issuers: []protocol.UnknownAddress{targetIssuer, otherIssuer1},
			msg: protocol.MessageSentEvent{
				Receipts: []protocol.ReceiptWithBlob{},
			},
			expected: false,
		},
		{
			name:    "multiple issuers - all issuers present in receipts - should return true",
			issuers: []protocol.UnknownAddress{targetIssuer, otherIssuer1},
			msg: protocol.MessageSentEvent{
				Receipts: []protocol.ReceiptWithBlob{
					{Issuer: targetIssuer},
					{Issuer: otherIssuer1},
				},
			},
			expected: true,
		},
		{
			name:    "multiple issuers - all issuers present with extras - should return true",
			issuers: []protocol.UnknownAddress{targetIssuer, otherIssuer1},
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
			name:    "multiple issuers - only first issuer present - should return false",
			issuers: []protocol.UnknownAddress{targetIssuer, otherIssuer1},
			msg: protocol.MessageSentEvent{
				Receipts: []protocol.ReceiptWithBlob{
					{Issuer: targetIssuer},
					{Issuer: otherIssuer2},
				},
			},
			expected: false,
		},
		{
			name:    "multiple issuers - only second issuer present - should return false",
			issuers: []protocol.UnknownAddress{targetIssuer, otherIssuer1},
			msg: protocol.MessageSentEvent{
				Receipts: []protocol.ReceiptWithBlob{
					{Issuer: otherIssuer1},
					{Issuer: otherIssuer2},
				},
			},
			expected: false,
		},
		{
			name:    "multiple issuers - none of the required issuers present - should return false",
			issuers: []protocol.UnknownAddress{targetIssuer, otherIssuer1},
			msg: protocol.MessageSentEvent{
				Receipts: []protocol.ReceiptWithBlob{
					{Issuer: otherIssuer2},
					{Issuer: otherIssuer3},
				},
			},
			expected: false,
		},
		{
			name:    "multiple issuers - all issuers present in different order - should return true",
			issuers: []protocol.UnknownAddress{targetIssuer, otherIssuer1},
			msg: protocol.MessageSentEvent{
				Receipts: []protocol.ReceiptWithBlob{
					{Issuer: otherIssuer1},
					{Issuer: targetIssuer},
				},
			},
			expected: true,
		},
		{
			name:    "three issuers - all present - should return true",
			issuers: []protocol.UnknownAddress{targetIssuer, otherIssuer1, otherIssuer2},
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
			name:    "three issuers - one missing - should return false",
			issuers: []protocol.UnknownAddress{targetIssuer, otherIssuer1, otherIssuer2},
			msg: protocol.MessageSentEvent{
				Receipts: []protocol.ReceiptWithBlob{
					{Issuer: targetIssuer},
					{Issuer: otherIssuer1},
					{Issuer: otherIssuer3},
				},
			},
			expected: false,
		},
		{
			name:    "three issuers - all present with duplicates - should return true",
			issuers: []protocol.UnknownAddress{targetIssuer, otherIssuer1, otherIssuer2},
			msg: protocol.MessageSentEvent{
				Receipts: []protocol.ReceiptWithBlob{
					{Issuer: targetIssuer},
					{Issuer: otherIssuer1},
					{Issuer: targetIssuer}, // duplicate
					{Issuer: otherIssuer2},
				},
			},
			expected: true,
		},
		{
			name:    "no issuers required - no receipts - should return true",
			issuers: []protocol.UnknownAddress{},
			msg: protocol.MessageSentEvent{
				Receipts: []protocol.ReceiptWithBlob{},
			},
			expected: true,
		},
		{
			name:    "no issuers required - with receipts - should return true",
			issuers: []protocol.UnknownAddress{},
			msg: protocol.MessageSentEvent{
				Receipts: []protocol.ReceiptWithBlob{
					{Issuer: targetIssuer},
				},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter := NewReceiptIssuerFilter(tt.issuers...)
			result := filter.Filter(tt.msg)
			assert.Equal(t, tt.expected, result)
		})
	}
}
