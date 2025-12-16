package lbtc

import (
	"context"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

type AttestationService interface {
	// Fetch retrieves the attestations for a given message batch.
	Fetch(ctx context.Context, message []protocol.Message) (map[string]protocol.ByteSlice, error)
}

type HTTPAttestationService struct {
	api       string
	timeout   time.Duration
	interval  time.Duration
	batchSize int
}

func NewAttestationService(config LBTCConfig) AttestationService {
	return HTTPAttestationService{
		api:       config.AttestationAPI,
		timeout:   config.AttestationAPITimeout,
		interval:  config.AttestationAPIInterval,
		batchSize: config.AttestationAPIBatchSize,
	}
}

func (h HTTPAttestationService) Fetch(
	ctx context.Context,
	message []protocol.Message,
) (map[string]protocol.ByteSlice, error) {
	// Build Lombard requests by grabbing ExtraData from each message's TokenTransfer
	requests := make(map[string]protocol.ByteSlice, len(message))
	for _, msg := range message {
		requests[msg.MustMessageID().String()] = msg.TokenTransfer.ExtraData
	}
	// Cal Lombard Batch API
	return requests, nil
}
