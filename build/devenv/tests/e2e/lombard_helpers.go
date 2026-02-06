package e2e

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/token/lombard"
)

// Lombard Attestation Flow:
//
// 1. The test calls buildLombardAttestation(messageID) which creates the attestation:
//    Format: [rawPayloadLength (2 bytes)][rawPayload (36 bytes)][proofLength (2 bytes)][proof (0 bytes)]
//    Where rawPayload = versionTag (0xf0f3a135) + messageId (32 bytes)
//
// 2. This attestation is registered with the fake HTTP service via registerLombardAttestation()
//
// 3. The Go verifier (verifier/token/lombard/verifier.go) fetches the attestation from the API
//
// 4. The Go verifier calls attestation.ToVerifierFormat() which prepends the 4-byte version tag:
//    Final ccvData: [versionTag (4 bytes)][rawPayloadLength (2 bytes)][rawPayload (36 bytes)][proofLength (2 bytes)][proof (0 bytes)]
//
// 5. This ccvData is sent to LombardVerifier.sol's verifyMessage() function
//
// 6. The Solidity contract extracts rawPayload and proof, then calls:
//    IMailbox.deliverAndHandle(rawPayload, proof)
//
// 7. The mock mailbox returns the rawPayload as the bridgedMessage (for testing purposes)
//
// 8. The contract validates that bridgedMessage is exactly 36 bytes and contains:
//    - versionTag (4 bytes): 0xf0f3a135
//    - messageId (32 bytes): matches the expected message ID

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

// buildLombardAttestation constructs a Lombard attestation payload for the mock API.
// The Go verifier (lombard/verifier.go) will prepend the 4-byte version tag to this attestation.
// So this function returns: [rawPayloadLength (2 bytes)][rawPayload][proofLength (2 bytes)][proof]
//
// The final ccvData that reaches LombardVerifier.sol will be:
// [versionTag (4 bytes)][rawPayloadLength (2 bytes)][rawPayload][proofLength (2 bytes)][proof]
//
// The rawPayload is what gets passed to deliverAndHandle() on the mock mailbox.
// The mock mailbox should return a "bridged message" that is exactly 36 bytes:
// - VERSION_TAG_V1_7_0 (4 bytes): 0xf0f3a135
// - messageId (32 bytes).
func buildLombardAttestation(messageID protocol.Bytes32) string {
	// Version tag for LombardVerifier 1.7.0
	versionTag := lombard.VerifierVersion

	// Build the bridged message that will be returned by the mock mailbox
	// This is what deliverAndHandle() returns: VERSION_TAG_V1_7_0 + messageId
	bridgedMessage := append(versionTag, messageID[:]...)

	// For the mock, we'll use the bridged message as the payload
	// In a real scenario, this would be more complex data from Lombard
	rawPayload := bridgedMessage

	// Dummy proof (empty for mock)
	proof := []byte{}

	// Build the attestation (WITHOUT the version tag - that's added by Go verifier):
	// [rawPayloadLength (2 bytes)][rawPayload][proofLength (2 bytes)][proof]
	var attestation []byte

	// Add rawPayload length as uint16 big-endian (2 bytes)
	rawPayloadLength := uint16(len(rawPayload))
	attestation = append(attestation, byte(rawPayloadLength>>8), byte(rawPayloadLength))

	// Add rawPayload
	attestation = append(attestation, rawPayload...)

	// Add proof length as uint16 big-endian (2 bytes)
	proofLength := uint16(len(proof))
	attestation = append(attestation, byte(proofLength>>8), byte(proofLength))

	// Add proof
	attestation = append(attestation, proof...)

	return "0x" + hex.EncodeToString(attestation)
}
