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

// registerCCTPAttestation registers a CCTP attestation response with the fake service.
func registerCCTPAttestation(
	t *testing.T,
	httpUrl string,
	messageID [32]byte,
	messageSender protocol.UnknownAddress,
	receiver protocol.UnknownAddress,
	status string,
) {
	messageIDHex := "0x" + hex.EncodeToString(messageID[:])

	// Build CCTP message (412 bytes total)
	// Verifier version (4 bytes) + CCTP message header (148 bytes) + message body (228 bytes) + hook data (36 bytes)
	message := buildCCTPMessage(messageID, messageSender, receiver)

	// Build attestation (65 bytes minimum - ECDSA signature with recovery byte)
	// For testing purposes, we can use a dummy signature
	attestation := buildCCTPAttestation()

	reqBody := map[string]string{
		"sourceDomain":  "100",
		"messageID":     messageIDHex,
		"status":        status,
		"messageSender": messageSender.String(),
		"message":       message,
		"attestation":   attestation,
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

// buildCCTPMessage constructs a 412-byte CCTP message according to the Solidity spec.
// Message format:
//   - version (4 bytes): uint32
//   - sourceDomain (4 bytes): uint32
//   - destinationDomain (4 bytes): uint32
//   - nonce (32 bytes): bytes32
//   - sender (32 bytes): bytes32
//   - recipient (32 bytes): bytes32
//   - destinationCaller (32 bytes): bytes32
//   - minFinalityThreshold (4 bytes): uint32
//   - finalityThresholdExecuted (4 bytes): uint32
//   - messageBody (228 bytes):
//   - version (4 bytes): uint32
//   - burnToken (32 bytes): bytes32
//   - mintRecipient (32 bytes): bytes32
//   - amount (32 bytes): uint256
//   - messageSender (32 bytes): bytes32
//   - maxFee (32 bytes): uint256
//   - feeExecuted (32 bytes): uint256
//   - expirationBlock (32 bytes): uint256
//   - hookData (36 bytes):
//   - verifierVersion (4 bytes): 0x8e1d1a9d
//   - messageId (32 bytes): bytes32
func buildCCTPMessage(messageID [32]byte, messageSender, receiver protocol.UnknownAddress) string {
	message := make([]byte, 412)

	// Most fields filled with zeros for testing
	// We only set the required fields according to the spec

	// Fill mintRecipient field (offset 148 + 36, left-padded to 32 bytes)
	// Solidity extraction: address(bytes20(message[148 + 36 + 12:148 + 36 + 12 + 20]))
	// This corresponds to mintRecipient in the message body, offset by 12 bytes for left-padding
	receiverBytes := receiver.Bytes()
	if len(receiverBytes) == 20 {
		// Left-pad the 20-byte address to 32 bytes (offset 148 + 36 + 12 = 196)
		copy(message[196:216], receiverBytes[:])
	} else {
		// For non-standard address lengths, copy as-is
		copy(message[184:216], receiverBytes[:])
	}

	// Verifier version at the start (4 bytes) - NOT part of the 412 bytes, but part of verifier results
	// So we start with the CCTP message header

	// Message body starts at byte 148
	// messageSender is at offset 148 + 100 = 248
	// In Solidity, addresses are left-padded to 32 bytes (12 zeros + 20 address bytes)
	messageSenderBytes := messageSender.Bytes()
	if len(messageSenderBytes) == 20 {
		// Left-pad the 20-byte address to 32 bytes
		copy(message[248+12:248+32], messageSenderBytes[:])
	} else {
		// For non-standard address lengths, copy as-is
		copy(message[248:248+32], messageSenderBytes[:])
	}

	// Hook data starts at byte 148 + 228 = 376
	// verifierVersion (4 bytes) at offset 376
	verifierVersion := []byte{0x8e, 0x1d, 0x1a, 0x9d}
	copy(message[376:380], verifierVersion)

	// messageID (32 bytes) at offset 380
	copy(message[380:412], messageID[:])

	return "0x" + hex.EncodeToString(message)
}

// buildCCTPAttestation constructs a dummy 65-byte ECDSA signature with recovery byte.
// For testing purposes, this can be filled with zeros or a dummy signature.
func buildCCTPAttestation() string {
	attestation := make([]byte, 65)
	// Fill with zeros for testing - real implementation would have actual signature
	return "0x" + hex.EncodeToString(attestation)
}
