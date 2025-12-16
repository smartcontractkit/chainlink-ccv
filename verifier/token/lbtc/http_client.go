package lbtc

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	httputil "github.com/smartcontractkit/chainlink-ccv/verifier/token/http"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type AttestationStatus string

const (
	apiVersion      = "v1"
	attestationPath = "deposits/getByHash"

	attestationStatusUnspecified AttestationStatus = "NOTARIZATION_STATUS_UNSPECIFIED"
	attestationStatusFailed      AttestationStatus = "NOTARIZATION_STATUS_FAILED"
	attestationStatusPending     AttestationStatus = "NOTARIZATION_STATUS_PENDING"
	attestationStatusSubmitted   AttestationStatus = "NOTARIZATION_STATUS_SUBMITTED"
	attestationStatusApproved    AttestationStatus = "NOTARIZATION_STATUS_SESSION_APPROVED"
)

type HTTPClient interface {
	// GetMessages fetches Lombard attestations for the given message hashes. It uses Batch API.
	GetMessages(
		ctx context.Context, messageHashes []protocol.ByteSlice,
	) ([]Attestation, error)
}

type HTTPClientImpl struct {
	lggr   logger.Logger
	client httputil.Client
}

// NewHTTPClient creates a new HTTP-based Lombard attestation client.
func NewHTTPClient(
	lggr logger.Logger,
	config LBTCConfig,
) (*HTTPClientImpl, error) {
	client, err := httputil.GetHTTPClient(
		lggr,
		config.AttestationAPI,
		config.AttestationAPIInterval,
		config.AttestationAPITimeout,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("create HTTP client: %w", err)
	}
	return &HTTPClientImpl{
		lggr:   lggr,
		client: client,
	}, nil
}

func (h *HTTPClientImpl) GetMessages(
	ctx context.Context,
	messageHashes []protocol.ByteSlice,
) ([]Attestation, error) {
	encodedRequest, err := json.Marshal(NewAttestationRequest(messageHashes))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal attestation request: %w", err)
	}

	respRaw, _, err := h.client.Post(ctx, fmt.Sprintf("bridge/%s/%s", apiVersion, attestationPath), encodedRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to post attestation request: %w", err)
	}

	var attestationResp AttestationResponse
	err = json.Unmarshal(respRaw, &attestationResp)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal attestation response: %w", err)
	}

	if attestationResp.Code != 0 {
		return nil, fmt.Errorf("attestation request failed: %s", attestationResp.Message)
	}
	return attestationResp.Attestations, nil
}

type AttestationRequest struct {
	PayloadHashes []string `json:"messageHash"`
}

func NewAttestationRequest(
	messageHashes []protocol.ByteSlice,
) AttestationRequest {
	payloadHashes := make([]string, 0, len(messageHashes))
	for _, msgHash := range messageHashes {
		payloadHashes = append(payloadHashes, msgHash.String())
	}
	return AttestationRequest{PayloadHashes: payloadHashes}
}

type AttestationResponse struct {
	Attestations []Attestation `json:"attestations"`
	// fields in case of error
	Code    int    `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}

type Attestation struct {
	MessageHash string            `json:"message_hash"`
	Status      AttestationStatus `json:"status"`
	// Data is represented by abi.encode(payload, proof)
	Data string `json:"attestation,omitempty"`
}

func (a *Attestation) IsReady() bool {
	return a.Status == attestationStatusApproved
}
