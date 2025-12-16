package lbtc

import (
	"context"
	"fmt"
	"slices"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type AttestationService interface {
	// Fetch retrieves the attestations for a given message batch. It should slice batch into smaller
	// requests if number of messages exceeds allowed limit.
	Fetch(ctx context.Context, message []protocol.Message) (map[string]Attestation, error)
}

type HTTPAttestationService struct {
	lggr   logger.Logger
	client HTTPClient
	// batchSize defines maximum number of messages to request in a single API call.
	// 0 or negative value means no limit.
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
		// TODO: Implement running that in parallel if needed.
		// For now, it's not a big deal, because batch limit is quite high (20)
		// considering the number of messages that be passed into this function at once.
		response, err := h.client.GetMessages(ctx, batch)
		if err != nil {
			return nil, fmt.Errorf("fetch attestations failed: %w", err)
		}
		attestations = append(attestations, response...)
	}

	// Map attestations back to messageIDs
	result := make(map[string]Attestation)
	for _, msg := range messages {
		id, err := msg.MessageID()
		if err != nil {
			return nil, fmt.Errorf("message ID extraction failed: %w", err)
		}
		extraData := msg.TokenTransfer.ExtraData.String()

		idx := slices.IndexFunc(attestations, func(attestation Attestation) bool {
			return attestation.MessageHash == extraData
		})
		if idx != -1 {
			result[id.String()] = attestations[idx]
		} else {
			h.lggr.Errorw("Failed to find attestation for message in the response", "id", id)
			result[id.String()] = Attestation{
				MessageHash: extraData,
				Status:      attestationStatusUnspecified,
			}
		}
	}
	return result, nil
}

func splitSlice[T any](s []T, chunkSize int) [][]T {
	var result [][]T

	// if chunkSize is not defined then don't slice it and return as it is
	if chunkSize <= 0 {
		result = append(result, s)
		return result
	}

	for i := 0; i < len(s); i += chunkSize {
		end := i + chunkSize
		if end > len(s) {
			end = len(s)
		}
		result = append(result, s[i:end])
	}

	return result
}
