package lombard

import (
	"context"
	"fmt"
	"slices"

	"github.com/ethereum/go-ethereum/accounts/abi"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	verifier "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vtypes"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// lengthPrefixBytes is the wire-format size of a uint16 big-endian length prefix.
const lengthPrefixBytes = 2

type AttestationService interface {
	// Fetch retrieves the attestations for a given verification task batch. It should slice batch into smaller
	// requests if number of tasks exceeds allowed limit.
	Fetch(ctx context.Context, tasks []verifier.VerificationTask) (map[string]Attestation, error)
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

// decodeABIAttestation decodes the ABI-encoded attestation to extract payload and proof.
// The attestation is expected to be encoded as abi.encode(bytes, bytes).
func decodeABIAttestation(attestationBytes []byte) (rawPayload, proof []byte, err error) {
	// Create ABI types for abi.decode(bytes, bytes)
	bytesType, err := abi.NewType("bytes", "", nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create bytes ABI type: %w", err)
	}

	args := abi.Arguments{
		{Type: bytesType},
		{Type: bytesType},
	}

	// Decode the attestation
	unpacked, err := args.Unpack(attestationBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to ABI decode attestation: %w", err)
	}

	if len(unpacked) != 2 {
		return nil, nil, fmt.Errorf("expected 2 values from ABI decode, got %d", len(unpacked))
	}

	rawPayload, ok := unpacked[0].([]byte)
	if !ok {
		return nil, nil, fmt.Errorf("first decoded value is not bytes")
	}

	proof, ok = unpacked[1].([]byte)
	if !ok {
		return nil, nil, fmt.Errorf("second decoded value is not bytes")
	}

	return rawPayload, proof, nil
}

// ToVerifierFormat converts the attestation into format expected by the verifier on the dest:
// [versionTag (4 bytes)][rawPayloadLength (2 bytes)][rawPayload (variable)][proofLength (2 bytes)][proof (variable)]
//
// The attestation from Lombard API is ABI-encoded as abi.encode(bytes, bytes) where:
// - First bytes: rawPayload
// - Second bytes: proof
//
// So we need to:
// 1. ABI decode the attestation to extract rawPayload and proof
// 2. Construct the verifier format with 4-byte version tag and 2-byte length prefixes.
func (a *Attestation) ToVerifierFormat() (protocol.ByteSlice, error) {
	if !a.IsReady() {
		return nil, fmt.Errorf("attestation is not ready, status: %s", a.status)
	}

	attestationBytes, err := protocol.NewByteSliceFromHex(a.attestation)
	if err != nil {
		return nil, fmt.Errorf("failed to decode attestation hex: %w", err)
	}

	rawPayload, proof, err := decodeABIAttestation(attestationBytes)
	if err != nil {
		return nil, err
	}

	// Check for overflow before casting to uint16
	if len(rawPayload) > 0xFFFF {
		return nil, fmt.Errorf("rawPayload too large: %d bytes (max 65535)", len(rawPayload))
	}
	if len(proof) > 0xFFFF {
		return nil, fmt.Errorf("proof too large: %d bytes (max 65535)", len(proof))
	}

	// Build output: [versionTag (4)][rawPayloadLength (2)][rawPayload][proofLength (2)][proof]
	// #nosec G115 -- overflow checked above, safe to cast to uint16
	rawPayloadLength := uint16(len(rawPayload))
	// #nosec G115 -- overflow checked above, safe to cast to uint16
	proofLength := uint16(len(proof))

	output := make(protocol.ByteSlice, 0, len(a.verifierVersion)+lengthPrefixBytes+len(rawPayload)+lengthPrefixBytes+len(proof))
	// Add version tag (4 bytes)
	output = append(output, a.verifierVersion...)
	// Add rawPayloadLength (2 bytes, big-endian)
	//nolint:gosec // G115: byte truncation is the intended big-endian encoding
	output = append(output, byte(rawPayloadLength>>8), byte(rawPayloadLength))
	// Add rawPayload
	output = append(output, rawPayload...)
	// Add proofLength (2 bytes, big-endian)
	//nolint:gosec // G115: byte truncation is the intended big-endian encoding
	output = append(output, byte(proofLength>>8), byte(proofLength))
	// Add proof
	output = append(output, proof...)

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
	batchSize         int
	verifierResolvers map[protocol.ChainSelector]protocol.UnknownAddress
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
		lggr:              lggr,
		client:            client,
		verifierVersion:   config.VerifierVersion,
		batchSize:         config.AttestationAPIBatchSize,
		verifierResolvers: config.ParsedVerifierResolvers,
	}, nil
}

func (h *HTTPAttestationService) Fetch(
	ctx context.Context,
	tasks []verifier.VerificationTask,
) (map[string]Attestation, error) {
	requests := make([]protocol.ByteSlice, 0, len(tasks))
	for _, task := range tasks {
		// Find the blob issued by one of the verifier resolvers
		var blob protocol.ByteSlice
		sourceChain := task.Message.SourceChainSelector
		expectedIssuer, ok := h.verifierResolvers[sourceChain]
		if !ok {
			h.lggr.Warnw("No verifier resolver configured for source chain, skipping task",
				"messageID", task.MessageID,
				"sourceChain", sourceChain)
			continue
		}

		for _, receipt := range task.ReceiptBlobs {
			if receipt.Issuer.Equal(expectedIssuer) {
				blob = receipt.Blob
				break
			}
		}

		if len(blob) == 0 {
			h.lggr.Warnw("No matching blob found for task in ReceiptBlobs",
				"messageID", task.MessageID,
				"expectedIssuer", expectedIssuer.String(),
				"sourceChain", sourceChain)
			continue
		}

		requests = append(requests, blob)
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
	for _, task := range tasks {
		// Find the blob for this task
		var blob protocol.ByteSlice
		sourceChain := task.Message.SourceChainSelector
		expectedIssuer, ok := h.verifierResolvers[sourceChain]
		if !ok {
			h.lggr.Errorw("No verifier resolver configured for source chain; marking attestation as missing",
				"messageID", task.MessageID,
				"sourceChain", sourceChain)
			result[task.MessageID] = NewMissingAttestation(h.verifierVersion)
			continue
		}

		for _, receipt := range task.ReceiptBlobs {
			if receipt.Issuer.Equal(expectedIssuer) {
				blob = receipt.Blob
				break
			}
		}

		if len(blob) == 0 {
			h.lggr.Errorw("No matching blob found for task; marking attestation as missing",
				"messageID", task.MessageID,
				"expectedIssuer", expectedIssuer.String())
			result[task.MessageID] = NewMissingAttestation(h.verifierVersion)
			continue
		}

		blobStr := blob.String()

		// Prefer APPROVED status if multiple entries exist for the same hash
		idx := slices.IndexFunc(attestations, func(attestation AttestationResponse) bool {
			return attestation.MessageHash == blobStr && attestation.Status == AttestationStatusApproved
		})
		if idx == -1 {
			idx = slices.IndexFunc(attestations, func(attestation AttestationResponse) bool {
				return attestation.MessageHash == blobStr
			})
		}
		if idx != -1 {
			result[task.MessageID] = NewAttestation(h.verifierVersion, attestations[idx])
		} else {
			h.lggr.Errorw("Failed to find attestation for task in the response",
				"messageID", task.MessageID)
			result[task.MessageID] = NewMissingAttestation(h.verifierVersion)
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
