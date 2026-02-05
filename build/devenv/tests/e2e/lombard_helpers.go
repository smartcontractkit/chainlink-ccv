package e2e

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// registerLombardAttestation registers a Lombard attestation response with the fake service.
func registerLombardAttestation(
	t *testing.T,
	httpUrl string,
	messageHash protocol.ByteSlice,
	attestation string,
	status string,
) {
	reqBody := map[string]string{
		"messageHash": messageHash.String(),
		"attestation": attestation,
		"status":      status,
	}

	reqJSON, err := json.Marshal(reqBody)
	require.NoError(t, err)

	resp, err := http.Post(
		httpUrl+"/lombard/v1/attestations",
		"application/json",
		bytes.NewBuffer(reqJSON),
	)
	require.NoError(t, err)
	defer func() {
		_ = resp.Body.Close()
	}()

	require.Equal(t, http.StatusOK, resp.StatusCode, "Failed to register Lombard attestation")
}

// buildLombardAttestation constructs a Lombard attestation payload.
// The attestation format is: abi.encode(payload, proof)
// For testing purposes, we can use a dummy attestation
func buildLombardAttestation() string {
	// Return a hex-encoded dummy attestation
	// In real scenario, this would be abi.encode(payload, proof) from Lombard
	// For testing, we'll use a simple dummy value
	dummyAttestation := make([]byte, 100)
	for i := range dummyAttestation {
		dummyAttestation[i] = byte(i % 256)
	}
	return "0x" + hex.EncodeToString(dummyAttestation)
}
