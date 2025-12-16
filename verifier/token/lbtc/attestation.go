package lbtc

import (
	"context"
	"slices"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type AttestationService interface {
	// Fetch retrieves the attestations for a given message batch.
	Fetch(ctx context.Context, message []protocol.Message) (map[string]Attestation, error)
}

type HTTPAttestationService struct {
	lggr      logger.Logger
	client    HTTPClient
	batchSize int
}

func NewAttestationService(
	lggr logger.Logger,
	config LBTCConfig,
) (AttestationService, error) {
	client, err := NewHTTPClient(lggr, config)
	if err != nil {
		return nil, err
	}
	return &HTTPAttestationService{
		lggr:      lggr,
		client:    client,
		batchSize: config.AttestationAPIBatchSize,
	}, nil
}

func (h *HTTPAttestationService) Fetch(
	ctx context.Context,
	messages []protocol.Message,
) (map[string]Attestation, error) {
	requests := make([]protocol.ByteSlice, 0, len(messages))
	for _, msg := range messages {
		requests = append(requests, msg.TokenTransfer.ExtraData)
	}

	attestations := make([]Attestation, 0, len(requests))
	batches := splitSlice(requests, h.batchSize)
	for _, batch := range batches {
		response, err := h.client.GetMessages(ctx, batch)
		if err != nil {
			return nil, err
		}
		attestations = append(attestations, response...)
	}

	result := make(map[string]Attestation)
	for _, msg := range messages {
		id, err := msg.MessageID()
		if err != nil {
			return nil, err
		}
		extraData := msg.TokenTransfer.ExtraData

		idx := slices.IndexFunc(attestations, func(attestation Attestation) bool {
			return attestation.MessageHash == extraData.String()
		})
		if idx != -1 {
			result[id.String()] = attestations[idx]
		} else {
			result[id.String()] = Attestation{
				MessageHash: extraData.String(),
				Status:      attestationStatusUnspecified,
			}
		}
	}
	return result, nil
}

func splitSlice[T any](s []T, chunkSize int) [][]T {
	if chunkSize <= 0 {
		return nil
	}

	var result [][]T

	for i := 0; i < len(s); i += chunkSize {
		end := i + chunkSize
		if end > len(s) {
			end = len(s)
		}
		result = append(result, s[i:end])
	}

	return result
}
