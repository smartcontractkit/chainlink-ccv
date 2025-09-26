package pagination

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

// OpaquePaginationTokenPayload represents the internal structure of a pagination token.
type OpaquePaginationTokenPayload struct {
	LastSeqNum  int64  `json:"seq_num"`
	Timestamp   int64  `json:"ts"`
	CommitteeID string `json:"cid"`
}

// SecurePaginationToken represents the secure, signed pagination token.
type SecurePaginationToken struct {
	Payload   string `json:"p"`
	Signature string `json:"s"`
}

// Paginator handles secure pagination token generation and validation.
type Paginator struct {
	secret []byte
}

// NewPaginationTokenManager creates a new Paginator with the provided secret.
func NewPaginationTokenManager(secret []byte) *Paginator {
	return &Paginator{
		secret: secret,
	}
}

// GenerateRandomSecret generates a cryptographically secure random secret for token signing.
func GenerateRandomSecret() ([]byte, error) {
	secret := make([]byte, 32) // 256-bit secret
	_, err := rand.Read(secret)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random secret: %w", err)
	}
	return secret, nil
}

// GenerateToken creates a secure, signed pagination token.
func (tm *Paginator) GenerateToken(lastSeqNum int64, committeeID string) (string, error) {
	payload := OpaquePaginationTokenPayload{
		LastSeqNum:  lastSeqNum,
		Timestamp:   time.Now().Unix(),
		CommitteeID: committeeID,
	}

	// Serialize payload to JSON
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Base64 encode payload
	payloadB64 := base64.StdEncoding.EncodeToString(payloadBytes)

	// Generate HMAC signature for payload
	signature := tm.generateSignature(payloadB64, committeeID)

	// Create secure token structure
	token := SecurePaginationToken{
		Payload:   payloadB64,
		Signature: base64.StdEncoding.EncodeToString(signature),
	}

	// Serialize and encode final token
	tokenBytes, err := json.Marshal(token)
	if err != nil {
		return "", fmt.Errorf("failed to marshal token: %w", err)
	}

	return base64.StdEncoding.EncodeToString(tokenBytes), nil
}

// ValidateToken validates and extracts the payload from a secure pagination token.
func (tm *Paginator) ValidateToken(tokenStr, committeeID string) (*OpaquePaginationTokenPayload, error) {
	if tokenStr == "" {
		return nil, fmt.Errorf("empty token")
	}

	// Decode base64 token
	tokenBytes, err := base64.StdEncoding.DecodeString(tokenStr)
	if err != nil {
		return nil, fmt.Errorf("invalid token encoding: %w", err)
	}

	// Unmarshal token structure
	var token SecurePaginationToken
	if err := json.Unmarshal(tokenBytes, &token); err != nil {
		return nil, fmt.Errorf("invalid token structure: %w", err)
	}

	// Decode payload first to check committee ID
	payloadBytes, err := base64.StdEncoding.DecodeString(token.Payload)
	if err != nil {
		return nil, fmt.Errorf("invalid payload encoding: %w", err)
	}

	var payload OpaquePaginationTokenPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, fmt.Errorf("invalid payload structure: %w", err)
	}

	// Validate committee binding before signature verification
	if payload.CommitteeID != committeeID {
		return nil, fmt.Errorf("committee mismatch")
	}

	// Verify signature
	expectedSignature := tm.generateSignature(token.Payload, committeeID)
	providedSignature, err := base64.StdEncoding.DecodeString(token.Signature)
	if err != nil {
		return nil, fmt.Errorf("invalid signature encoding: %w", err)
	}

	if !hmac.Equal(expectedSignature, providedSignature) {
		return nil, fmt.Errorf("invalid token signature")
	}

	return &payload, nil
}

// generateSignature creates an HMAC-SHA256 signature for the given payload and committee.
func (tm *Paginator) generateSignature(payload, committeeID string) []byte {
	h := hmac.New(sha256.New, tm.secret)
	h.Write([]byte(payload))
	h.Write([]byte(committeeID))
	return h.Sum(nil)
}
