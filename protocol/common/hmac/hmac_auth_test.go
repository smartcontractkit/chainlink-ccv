package hmac

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/emptypb"
)

func TestGenerateSignature(t *testing.T) {
	secret := "test-secret-key"
	method := "/Aggregator/ReadBlockCheckpoint"
	apiKey := "test-api-key"
	timestampMs := time.Now().UnixMilli()

	// Use an empty proto message for testing
	req := &emptypb.Empty{}

	// Generate signature
	signature, err := GenerateSignature(secret, method, req, apiKey, timestampMs)
	require.NoError(t, err, "Should generate signature without error")
	require.NotEmpty(t, signature, "Signature should not be empty")
	require.Len(t, signature, 64, "HMAC-SHA256 hex signature should be 64 characters")
}

func TestSerializeRequestBody(t *testing.T) {
	req := &emptypb.Empty{}

	body, err := SerializeRequestBody(req)
	require.NoError(t, err, "Should serialize proto message")
	require.NotNil(t, body, "Body should not be nil")
}

func TestSerializeRequestBody_NotProtoMessage(t *testing.T) {
	notProto := "not a proto message"

	_, err := SerializeRequestBody(notProto)
	require.Error(t, err, "Should error on non-proto message")
	require.Contains(t, err.Error(), "not a proto.Message")
}

func TestComputeBodyHash(t *testing.T) {
	body := []byte("test body content")

	hash := ComputeBodyHash(body)
	require.NotEmpty(t, hash, "Hash should not be empty")
	require.Len(t, hash, 64, "SHA256 hex hash should be 64 characters")

	// Same body should produce same hash
	hash2 := ComputeBodyHash(body)
	require.Equal(t, hash, hash2, "Same body should produce same hash")
}

func TestGenerateStringToSign(t *testing.T) {
	method := "POST"
	fullPath := "/Aggregator/ReadBlockCheckpoint"
	bodyHash := "abc123"
	apiKey := "api-key-uuid"
	timestamp := "1234567890"

	stringToSign := GenerateStringToSign(method, fullPath, bodyHash, apiKey, timestamp)

	expected := "POST /Aggregator/ReadBlockCheckpoint abc123 api-key-uuid 1234567890"
	require.Equal(t, expected, stringToSign, "String to sign should match expected format")
}

func TestComputeHMAC(t *testing.T) {
	secret := "test-secret"
	stringToSign := "POST /path body-hash api-key timestamp"

	signature := ComputeHMAC(secret, stringToSign)
	require.NotEmpty(t, signature, "HMAC should not be empty")
	require.Len(t, signature, 64, "HMAC-SHA256 hex should be 64 characters")

	// Same inputs should produce same signature
	signature2 := ComputeHMAC(secret, stringToSign)
	require.Equal(t, signature, signature2, "Same inputs should produce same HMAC")

	// Different secret should produce different signature
	differentSignature := ComputeHMAC("different-secret", stringToSign)
	require.NotEqual(t, signature, differentSignature, "Different secret should produce different HMAC")
}

func TestValidateTimestamp(t *testing.T) {
	t.Run("valid current timestamp", func(t *testing.T) {
		now := time.Now().UnixMilli()
		err := ValidateTimestamp(toString(now))
		require.NoError(t, err, "Current timestamp should be valid")
	})

	t.Run("valid timestamp within 5 seconds", func(t *testing.T) {
		fourSecondsAgo := time.Now().Add(-4 * time.Second).UnixMilli()
		err := ValidateTimestamp(toString(fourSecondsAgo))
		require.NoError(t, err, "Timestamp 4 seconds ago should be valid")
	})

	t.Run("invalid timestamp too old", func(t *testing.T) {
		sixSecondsAgo := time.Now().Add(-16 * time.Second).UnixMilli()
		err := ValidateTimestamp(toString(sixSecondsAgo))
		require.Error(t, err, "Timestamp 16 seconds ago should be invalid")
		require.Contains(t, err.Error(), "outside acceptable window")
	})

	t.Run("invalid timestamp too far in future", func(t *testing.T) {
		sixSecondsAhead := time.Now().Add(16 * time.Second).UnixMilli()
		err := ValidateTimestamp(toString(sixSecondsAhead))
		require.Error(t, err, "Timestamp 16 seconds ahead should be invalid")
		require.Contains(t, err.Error(), "outside acceptable window")
	})

	t.Run("invalid timestamp format", func(t *testing.T) {
		err := ValidateTimestamp("not-a-number")
		require.Error(t, err, "Non-numeric timestamp should be invalid")
		require.Contains(t, err.Error(), "invalid timestamp format")
	})
}

func TestValidateSignature(t *testing.T) {
	secret := "test-secret"
	stringToSign := "POST /path body-hash api-key timestamp"
	validSignature := ComputeHMAC(secret, stringToSign)

	t.Run("valid signature with single secret", func(t *testing.T) {
		secrets := map[string]string{
			"current": secret,
		}

		isValid := ValidateSignature(stringToSign, validSignature, secrets)
		require.True(t, isValid, "Valid signature should be accepted")
	})

	t.Run("valid signature with multiple secrets", func(t *testing.T) {
		secrets := map[string]string{
			"current":  secret,
			"previous": "old-secret",
		}

		isValid := ValidateSignature(stringToSign, validSignature, secrets)
		require.True(t, isValid, "Valid signature should be accepted with multiple secrets")
	})

	t.Run("valid with rotated secret", func(t *testing.T) {
		// Signature made with "old-secret"
		oldSecret := "old-secret"
		oldSignature := ComputeHMAC(oldSecret, stringToSign)

		secrets := map[string]string{
			"current":  secret,
			"previous": oldSecret,
		}

		isValid := ValidateSignature(stringToSign, oldSignature, secrets)
		require.True(t, isValid, "Signature with old secret should still be valid")
	})

	t.Run("invalid signature", func(t *testing.T) {
		secrets := map[string]string{
			"current": secret,
		}

		isValid := ValidateSignature(stringToSign, "invalid-signature", secrets)
		require.False(t, isValid, "Invalid signature should be rejected")
	})

	t.Run("signature with wrong secret", func(t *testing.T) {
		wrongSignature := ComputeHMAC("wrong-secret", stringToSign)

		secrets := map[string]string{
			"current": secret,
		}

		isValid := ValidateSignature(stringToSign, wrongSignature, secrets)
		require.False(t, isValid, "Signature with wrong secret should be rejected")
	})
}

func TestConstants(t *testing.T) {
	require.Equal(t, "authorization", HeaderAuthorization)
	require.Equal(t, "x-authorization-timestamp", HeaderTimestamp)
	require.Equal(t, "x-authorization-signature-sha256", HeaderSignature)
	require.Equal(t, "POST", HTTPMethodPost)
}

// Helper function to convert int64 to string.
func toString(i int64) string {
	return fmt.Sprintf("%d", i)
}
