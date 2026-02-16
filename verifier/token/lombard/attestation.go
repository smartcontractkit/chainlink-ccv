package lombard

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

// Attestation represents a Lombard attestation along with related data
// allowing creating proper payload for the verifier on the destination chain.
// Please see ToVerifierFormat for more details on the format.
type Attestation struct {
	verifierVersion protocol.ByteSlice
	attestation     string
	status          AttestationStatus
}

func NewAttestation(
	ccvVerifierVersion protocol.ByteSlice,
	resp AttestationResponse,
) Attestation {
	return Attestation{
		verifierVersion: ccvVerifierVersion,
		attestation:     resp.Data,
		status:          resp.Status,
	}
}

func NewMissingAttestation(
	ccvVerifierVersion protocol.ByteSlice,
) Attestation {
	return Attestation{
		verifierVersion: ccvVerifierVersion,
		status:          AttestationStatusUnspecified,
	}
}

// ToVerifierFormat converts the attestation into format expected by the verifier on the dest:
// <4 byte verifier version><lombard attestation>
// <lombard attestation> := abi.encode(payload, proof) as per Lombard spec, but offchain doesn't need to know the details.
func (a *Attestation) ToVerifierFormat() (protocol.ByteSlice, error) {
	if !a.IsReady() {
		return nil, fmt.Errorf("attestation is not ready, status: %s", a.status)
	}

	attestationBytes, err := protocol.NewByteSliceFromHex(a.attestation)
	if err != nil {
		return nil, fmt.Errorf("failed to decode attestation hex: %w", err)
	}

	var output protocol.ByteSlice
	output = append(output, a.verifierVersion...)
	output = append(output, attestationBytes...)
	return output, nil
}

func (a *Attestation) IsReady() bool {
	return a.status == AttestationStatusApproved
}

type HTTPAttestationService struct {
	lggr            logger.Logger
	client          HTTPClient
	verifierVersion protocol.ByteSlice
	// batchSize defines maximum number of messages to request in a single API call.
	// 0 or negative value means no limit.
	batchSize int
}

func NewAttestationService(
	lggr logger.Logger,
	config LombardConfig,
) (AttestationService, error) {
	client, err := NewHTTPClient(lggr, config)
	if err != nil {
		return nil, err
	}

	return &HTTPAttestationService{
		lggr:            lggr,
		client:          client,
		verifierVersion: config.VerifierVersion,
		batchSize:       config.AttestationAPIBatchSize,
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

	attestations := make([]AttestationResponse, 0, len(requests))
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

		idx := slices.IndexFunc(attestations, func(attestation AttestationResponse) bool {
			return attestation.MessageHash == extraData
		})
		if idx != -1 {
			result[id.String()] = NewAttestation(h.verifierVersion, attestations[idx])
		} else {
			h.lggr.Errorw("Failed to find attestation for message in the response", "id", id)
			result[id.String()] = NewMissingAttestation(h.verifierVersion)
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
		end := min(i+chunkSize, len(s))
		result = append(result, s[i:end])
	}

	return result
}
