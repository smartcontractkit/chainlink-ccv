package lbtc

import (
	"context"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

type AttestationService interface {
	// Fetch retrieves the attestations for a given message batch.
	Fetch(ctx context.Context, message []protocol.Message) ([]protocol.ByteSlice, error)
}

type HTTPAttestationService struct{}

func (h HTTPAttestationService) Fetch(
	ctx context.Context,
	message []protocol.Message,
) ([]protocol.ByteSlice, error) {
	// Build Lombard requests by grabbing ExtraData from each message's TokenTransfer
	requests := make([]protocol.ByteSlice, 0, len(message))
	for _, msg := range message {
		requests = append(requests, msg.TokenTransfer.ExtraData)
	}
	// Cal Lombard Batch API
	return requests, nil
}
