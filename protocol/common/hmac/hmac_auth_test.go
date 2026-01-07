package hmac

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/emptypb"
)

const (
	testHexSecret    = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	testHexSecretAlt = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	testAPIKey       = "00000000-0000-0000-0000-000000000001"
)

func TestGenerateSignature(t *testing.T) {
	secret := testHexSecret
	method := "/Aggregator/ReadChainStatus"
	apiKey := testAPIKey
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
	fullPath := "/Aggregator/ReadChainStatus"
	bodyHash := "abc123"
	apiKey := "api-key-uuid"
	timestamp := "1234567890"

	stringToSign := GenerateStringToSign(method, fullPath, bodyHash, apiKey, timestamp)

	expected := "POST /Aggregator/ReadChainStatus abc123 api-key-uuid 1234567890"
	require.Equal(t, expected, stringToSign, "String to sign should match expected format")
}

func TestComputeHMAC(t *testing.T) {
	stringToSign := "POST /path body-hash api-key timestamp"

	t.Run("hex-encoded secret is decoded before use", func(t *testing.T) {
		signature, err := ComputeHMAC(testHexSecret, stringToSign)
		require.NoError(t, err)
		require.NotEmpty(t, signature, "HMAC should not be empty")
		require.Len(t, signature, 64, "HMAC-SHA256 hex should be 64 characters")

		// Same inputs should produce same signature
		signature2, err := ComputeHMAC(testHexSecret, stringToSign)
		require.NoError(t, err)
		require.Equal(t, signature, signature2, "Same inputs should produce same HMAC")

		// Different secret should produce different signature
		differentSignature, err := ComputeHMAC(testHexSecretAlt, stringToSign)
		require.NoError(t, err)
		require.NotEqual(t, signature, differentSignature, "Different secret should produce different HMAC")
	})

	t.Run("non-hex secret returns error", func(t *testing.T) {
		_, err := ComputeHMAC("not-valid-hex", stringToSign)
		require.Error(t, err)
		require.Contains(t, err.Error(), "HMAC secret must be hex-encoded")
	})

	t.Run("different hex secrets produce different signatures", func(t *testing.T) {
		hexSecret1 := "0a0b0c0d0e0f0a0b0c0d0e0f0a0b0c0d0a0b0c0d0e0f0a0b0c0d0e0f0a0b0c0d"
		hexSecret2 := "1a1b1c1d1e1f1a1b1c1d1e1f1a1b1c1d1a1b1c1d1e1f1a1b1c1d1e1f1a1b1c1d"

		sig1, err := ComputeHMAC(hexSecret1, stringToSign)
		require.NoError(t, err)
		sig2, err := ComputeHMAC(hexSecret2, stringToSign)
		require.NoError(t, err)

		require.NotEqual(t, sig1, sig2, "Different secrets should produce different signatures")
	})
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
	stringToSign := "POST /path body-hash api-key timestamp"
	validSignature, err := ComputeHMAC(testHexSecret, stringToSign)
	require.NoError(t, err)

	t.Run("valid signature", func(t *testing.T) {
		isValid := ValidateSignature(stringToSign, validSignature, testHexSecret)
		require.True(t, isValid, "Valid signature should be accepted")
	})

	t.Run("invalid signature", func(t *testing.T) {
		isValid := ValidateSignature(stringToSign, "invalid-signature", testHexSecret)
		require.False(t, isValid, "Invalid signature should be rejected")
	})

	t.Run("signature with wrong secret", func(t *testing.T) {
		wrongSignature, err := ComputeHMAC(testHexSecretAlt, stringToSign)
		require.NoError(t, err)
		isValid := ValidateSignature(stringToSign, wrongSignature, testHexSecret)
		require.False(t, isValid, "Signature with wrong secret should be rejected")
	})

	t.Run("invalid hex secret returns false", func(t *testing.T) {
		isValid := ValidateSignature(stringToSign, validSignature, "not-hex")
		require.False(t, isValid, "Invalid hex secret should return false")
	})
}

func TestConstants(t *testing.T) {
	require.Equal(t, "authorization", HeaderAuthorization)
	require.Equal(t, "x-authorization-timestamp", HeaderTimestamp)
	require.Equal(t, "x-authorization-signature-sha256", HeaderSignature)
	require.Equal(t, "POST", HTTPMethodPost)
}

func TestGenerateSecret(t *testing.T) {
	t.Run("generates hex-encoded secret of correct length", func(t *testing.T) {
		secret, err := GenerateSecret(32)
		require.NoError(t, err)
		require.Len(t, secret, 64, "32 bytes should produce 64 hex characters")
	})

	t.Run("generates unique secrets", func(t *testing.T) {
		secret1, err := GenerateSecret(32)
		require.NoError(t, err)
		secret2, err := GenerateSecret(32)
		require.NoError(t, err)
		require.NotEqual(t, secret1, secret2, "consecutive secrets should be unique")
	})

	t.Run("generates valid hex-encoded output", func(t *testing.T) {
		secret, err := GenerateSecret(32)
		require.NoError(t, err)
		require.Len(t, secret, 64, "32 bytes should produce 64 hex characters")
		require.NoError(t, ValidateSecret(secret), "generated secret should pass validation")
	})
}

func TestGenerateCredentials(t *testing.T) {
	t.Run("generates valid credentials", func(t *testing.T) {
		creds, err := GenerateCredentials()
		require.NoError(t, err)
		require.NotEmpty(t, creds.APIKey)
		require.NotEmpty(t, creds.Secret)
	})

	t.Run("API key is valid UUID", func(t *testing.T) {
		creds, err := GenerateCredentials()
		require.NoError(t, err)
		require.NoError(t, ValidateAPIKey(creds.APIKey))
	})

	t.Run("secret is valid hex with correct length", func(t *testing.T) {
		creds, err := GenerateCredentials()
		require.NoError(t, err)
		require.Len(t, creds.Secret, DefaultSecretBytes*2, "secret should be 64 hex chars (32 bytes)")
		require.NoError(t, ValidateSecret(creds.Secret))
	})

	t.Run("generates unique credentials", func(t *testing.T) {
		creds1, err := GenerateCredentials()
		require.NoError(t, err)
		creds2, err := GenerateCredentials()
		require.NoError(t, err)
		require.NotEqual(t, creds1.APIKey, creds2.APIKey)
		require.NotEqual(t, creds1.Secret, creds2.Secret)
	})
}

func TestMustGenerateCredentials(t *testing.T) {
	t.Run("returns valid credentials without panic", func(t *testing.T) {
		require.NotPanics(t, func() {
			creds := MustGenerateCredentials()
			require.NotEmpty(t, creds.APIKey)
			require.NotEmpty(t, creds.Secret)
		})
	})

	t.Run("credentials pass validation", func(t *testing.T) {
		creds := MustGenerateCredentials()
		require.NoError(t, ValidateAPIKey(creds.APIKey))
		require.NoError(t, ValidateSecret(creds.Secret))
	})
}

func TestValidateAPIKey(t *testing.T) {
	tests := []struct {
		name    string
		apiKey  string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid UUID",
			apiKey:  "550e8400-e29b-41d4-a716-446655440000",
			wantErr: false,
		},
		{
			name:    "valid UUID v4",
			apiKey:  testAPIKey,
			wantErr: false,
		},
		{
			name:    "empty string returns error",
			apiKey:  "",
			wantErr: true,
			errMsg:  "must be a valid UUID",
		},
		{
			name:    "invalid format returns error",
			apiKey:  "not-a-uuid",
			wantErr: true,
			errMsg:  "must be a valid UUID",
		},
		{
			name:    "malformed UUID returns error",
			apiKey:  "550e8400-e29b-41d4-a716",
			wantErr: true,
			errMsg:  "must be a valid UUID",
		},
		{
			name:    "UUID with invalid characters returns error",
			apiKey:  "550e8400-e29b-41d4-a716-44665544000g",
			wantErr: true,
			errMsg:  "must be a valid UUID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAPIKey(tt.apiKey)
			if tt.wantErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateSecret(t *testing.T) {
	tests := []struct {
		name    string
		secret  string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid 32-byte hex secret",
			secret:  testHexSecret,
			wantErr: false,
		},
		{
			name:    "valid 64-byte hex secret",
			secret:  testHexSecret + testHexSecret,
			wantErr: false,
		},
		{
			name:    "empty string returns error",
			secret:  "",
			wantErr: true,
			errMsg:  "must be at least",
		},
		{
			name:    "non-hex string returns error",
			secret:  "not-valid-hex-string-at-all!!!!",
			wantErr: true,
			errMsg:  "must be hex-encoded",
		},
		{
			name:    "hex secret too short returns error",
			secret:  "0123456789abcdef",
			wantErr: true,
			errMsg:  "must be at least 32 bytes",
		},
		{
			name:    "31 bytes (62 hex chars) returns error",
			secret:  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd",
			wantErr: true,
			errMsg:  "must be at least 32 bytes",
		},
		{
			name:    "exactly 32 bytes (64 hex chars) is valid",
			secret:  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSecret(tt.secret)
			if tt.wantErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// Helper function to convert int64 to string.
func toString(i int64) string {
	return fmt.Sprintf("%d", i)
}
