package e2e

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"maps"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// registerCCTPAttestation registers a CCTP attestation response with the fake service.
func registerCCTPAttestation(
	t *testing.T,
	httpUrl string,
	messageID [32]byte,
	messageSender protocol.UnknownAddress,
	status string,
	optionalFields ...map[string]string,
) {
	messageIDHex := "0x" + hex.EncodeToString(messageID[:])

	reqBody := map[string]string{
		"sourceDomain":  "100",
		"messageID":     messageIDHex,
		"status":        status,
		"messageSender": messageSender.String(), // "0x2609ac236def92d0992ff8bbcf810a59a9301bca", // Default messageSender
	}

	// Add optional fields if provided (message, attestation, messageSender can be overridden)
	if len(optionalFields) > 0 {
		maps.Copy(reqBody, optionalFields[0])
	}

	reqJSON, err := json.Marshal(reqBody)
	require.NoError(t, err)

	resp, err := http.Post(
		httpUrl+"/cctp/v2/attestations",
		"application/json",
		bytes.NewBuffer(reqJSON),
	)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode, "Failed to register CCTP attestation")
}
