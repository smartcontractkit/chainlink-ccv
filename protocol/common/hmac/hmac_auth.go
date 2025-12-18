// Package hmac provides HMAC-SHA256 authentication utilities for gRPC requests
// following the Chainlink Data Streams authentication pattern.
//
// This package is shared between:
// - Aggregator server: for validating incoming request signatures
// - Client applications: for generating signatures when making requests
package hmac

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"

	"google.golang.org/protobuf/proto"
)

// HMAC authentication metadata header keys for gRPC.
const (
	// HeaderAuthorization contains the API key (UUID format).
	HeaderAuthorization = "authorization"
	// HeaderTimestamp contains the current timestamp in milliseconds since Unix epoch.
	HeaderTimestamp = "x-authorization-timestamp"
	// HeaderSignature contains the HMAC-SHA256 signature (hex-encoded).
	HeaderSignature = "x-authorization-signature-sha256"
	// HTTPMethodPost is the HTTP method used for all gRPC requests.
	HTTPMethodPost = "POST"

	// DefaultTimeWindow is the default acceptable time window for request timestamps.
	DefaultTimeWindow = 15 * time.Second
)

// SerializeRequestBody marshals a protobuf message to bytes.
func SerializeRequestBody(req any) ([]byte, error) {
	protoMsg, ok := req.(proto.Message)
	if !ok {
		return nil, fmt.Errorf("request is not a proto.Message")
	}
	return proto.Marshal(protoMsg)
}

// ComputeBodyHash computes the SHA256 hash of the request body and returns it as a hex-encoded string.
func ComputeBodyHash(body []byte) string {
	hash := sha256.Sum256(body)
	return hex.EncodeToString(hash[:])
}

// GenerateStringToSign creates the string that should be signed according to Data Streams pattern.
// Format: "METHOD FULL_PATH BODY_HASH API_KEY TIMESTAMP"
//
// Example:
//
//	stringToSign := GenerateStringToSign("POST", "/Aggregator/ReadChainStatus", "abc123...", "api-key-uuid", "1234567890")
func GenerateStringToSign(method, fullPath, bodyHash, apiKey, timestamp string) string {
	return fmt.Sprintf("%s %s %s %s %s", method, fullPath, bodyHash, apiKey, timestamp)
}

// ComputeHMAC computes the HMAC-SHA256 signature and returns it as a hex-encoded string.
func ComputeHMAC(secret, stringToSign string) string {
	h := hmac.New(sha256.New, []byte(secret))
	_, _ = h.Write([]byte(stringToSign)) // hash.Hash.Write never returns an error
	return hex.EncodeToString(h.Sum(nil))
}

// ValidateTimestamp checks if the timestamp is within acceptable window (±15 seconds).
func ValidateTimestamp(timestampStr string) error {
	timestampMs, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid timestamp format: %w", err)
	}

	now := time.Now().UnixMilli()
	diff := now - timestampMs

	if diff > DefaultTimeWindow.Milliseconds() || diff < -DefaultTimeWindow.Milliseconds() {
		return fmt.Errorf("timestamp outside acceptable window: %d ms difference", diff)
	}

	return nil
}

// ValidateSignature checks if the provided signature matches any of the client's secrets.
// Uses constant-time comparison to prevent timing attacks.
// Returns true if signature is valid with any of the secrets.
//
// This function is primarily used by the server to validate incoming requests.
func ValidateSignature(stringToSign, providedSig string, secrets map[string]string) bool {
	for _, secret := range secrets {
		expectedSig := ComputeHMAC(secret, stringToSign)

		// Use constant-time comparison to prevent timing attacks
		if subtle.ConstantTimeCompare([]byte(expectedSig), []byte(providedSig)) == 1 {
			return true
		}
	}
	return false
}

// GenerateSignature is a convenience function that generates a complete HMAC signature
// for a gRPC request. This is typically used by clients.
//
// Parameters:
//   - secret: The HMAC secret key
//   - method: The gRPC method name (e.g., "/Aggregator/ReadChainStatus")
//   - req: The protobuf request message
//   - apiKey: The API key
//   - timestampMs: The timestamp in milliseconds since Unix epoch
//
// Returns:
//   - The hex-encoded HMAC-SHA256 signature
//   - An error if serialization fails
func GenerateSignature(secret, method string, req proto.Message, apiKey string, timestampMs int64) (string, error) {
	// 1. Serialize request body
	body, err := SerializeRequestBody(req)
	if err != nil {
		return "", fmt.Errorf("failed to serialize request: %w", err)
	}

	// 2. Compute body hash
	bodyHash := ComputeBodyHash(body)

	// 3. Generate string to sign
	timestamp := strconv.FormatInt(timestampMs, 10)
	stringToSign := GenerateStringToSign(HTTPMethodPost, method, bodyHash, apiKey, timestamp)

	// 4. Compute HMAC signature
	signature := ComputeHMAC(secret, stringToSign)

	return signature, nil
}
