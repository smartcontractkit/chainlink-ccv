// Package hmac provides HMAC-SHA256 authentication utilities for gRPC requests
// following the Chainlink Data Streams authentication pattern.
//
// This package is shared between:
// - Aggregator server: for validating incoming request signatures
// - Client applications: for generating signatures when making requests
// - Devenv services: for generating HMAC credentials
// - Tests: for consistent test credentials
package hmac

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"
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

	// DefaultSecretBytes is the default number of bytes for generated HMAC secrets.
	// 32 bytes = 256 bits of entropy, resulting in a 64-character hex string.
	DefaultSecretBytes = 32

	// MinSecretBytes is the minimum required length for HMAC secrets.
	// Secrets must be at least 32 bytes (256 bits) for adequate security.
	MinSecretBytes = 32
)

// Credentials holds an API key and its associated HMAC secret.
type Credentials struct {
	APIKey string
	Secret string
}

// GenerateSecret generates a cryptographically secure random secret.
// The secret is returned as a hex-encoded string.
// numBytes specifies the number of random bytes (e.g., 32 bytes = 64 hex chars).
func GenerateSecret(numBytes int) (string, error) {
	secret := make([]byte, numBytes)
	if _, err := rand.Read(secret); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return hex.EncodeToString(secret), nil
}

// GenerateCredentials generates a new API key (UUID) and HMAC secret pair.
func GenerateCredentials() (Credentials, error) {
	secret, err := GenerateSecret(DefaultSecretBytes)
	if err != nil {
		return Credentials{}, fmt.Errorf("failed to generate HMAC secret: %w", err)
	}
	return Credentials{
		APIKey: uuid.New().String(),
		Secret: secret,
	}, nil
}

// MustGenerateCredentials generates a new API key (UUID) and HMAC secret pair and panics if an error occurs.
func MustGenerateCredentials() Credentials {
	creds, err := GenerateCredentials()
	if err != nil {
		panic(err)
	}
	return creds
}

// ValidateAPIKey validates that the API key is a valid UUID.
func ValidateAPIKey(apiKey string) error {
	if _, err := uuid.Parse(apiKey); err != nil {
		return fmt.Errorf("API key must be a valid UUID, got %q", apiKey)
	}
	return nil
}

// ValidateSecret validates that the secret is hex-encoded and at least MinSecretBytes long.
func ValidateSecret(secret string) error {
	decoded, err := hex.DecodeString(secret)
	if err != nil {
		return fmt.Errorf("secret must be hex-encoded: %w", err)
	}
	if len(decoded) < MinSecretBytes {
		return fmt.Errorf("secret must be at least %d bytes (%d hex chars), got %d bytes",
			MinSecretBytes, MinSecretBytes*2, len(decoded))
	}
	return nil
}

// SerializeRequestBody marshals a protobuf message to bytes.
func SerializeRequestBody(req any) ([]byte, error) {
	protoMsg, ok := req.(proto.Message)
	if !ok {
		return nil, fmt.Errorf("request is not a proto.Message")
	}
	return proto.MarshalOptions{Deterministic: true}.Marshal(protoMsg)
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
// The secret must be a hex-encoded string which will be decoded before use as the HMAC key.
func ComputeHMAC(secret, stringToSign string) (string, error) {
	secretBytes, err := hex.DecodeString(secret)
	if err != nil {
		return "", fmt.Errorf("HMAC secret must be hex-encoded: %w", err)
	}
	h := hmac.New(sha256.New, secretBytes)
	_, _ = h.Write([]byte(stringToSign)) // hash.Hash.Write never returns an error
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ValidateTimestamp checks if the timestamp is within acceptable window.
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

// ValidateSignature checks if the provided signature matches the client's secret.
// Returns true if signature is valid, false if invalid or if there's an error computing the signature.
//
// This function is primarily used by the server to validate incoming requests.
func ValidateSignature(stringToSign, providedSig, secret string) bool {
	expectedSig, err := ComputeHMAC(secret, stringToSign)
	if err != nil {
		return false
	}
	return hmac.Equal([]byte(expectedSig), []byte(providedSig))
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
	signature, err := ComputeHMAC(secret, stringToSign)
	if err != nil {
		return "", fmt.Errorf("failed to compute HMAC: %w", err)
	}

	return signature, nil
}
