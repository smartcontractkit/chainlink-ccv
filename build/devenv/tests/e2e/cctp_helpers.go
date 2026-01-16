package e2e

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// registerCCTPAttestation registers a CCTP attestation response with the fake service.
func registerCCTPAttestation(t *testing.T, messageID [32]byte, status string) {
	// Convert messageID to hex string
	messageIDHex := "0x" + hex.EncodeToString(messageID[:])

	reqBody := map[string]string{
		"sourceDomain": "100",
		"messageID":    messageIDHex,
		"status":       status,
	}
	reqJSON, err := json.Marshal(reqBody)
	require.NoError(t, err)

	// The fake service runs on port 9111
	resp, err := http.Post(
		"http://localhost:9111/cctp/v2/attestations",
		"application/json",
		bytes.NewBuffer(reqJSON),
	)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode, "Failed to register CCTP attestation")
}
