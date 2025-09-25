package pagination

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTokenManager(t *testing.T) {
	secret := []byte("test-secret-key-for-hmac-sign32x")
	require.Len(t, secret, 32, "Test secret should be 32 bytes")

	tm := NewPaginationTokenManager(secret)
	committeeID := "test-committee-123"
	lastSeqNum := int64(42)

	t.Run("Generate and validate token", func(t *testing.T) {
		// Generate token
		token, err := tm.GenerateToken(lastSeqNum, committeeID)
		require.NoError(t, err)
		require.NotEmpty(t, token)

		// Validate token
		payload, err := tm.ValidateToken(token, committeeID)
		require.NoError(t, err)
		require.NotNil(t, payload)
		require.Equal(t, lastSeqNum, payload.LastSeqNum)
		require.Equal(t, committeeID, payload.CommitteeID)
		require.Greater(t, payload.Timestamp, int64(0))
	})

	t.Run("Invalid committee ID should fail", func(t *testing.T) {
		token, err := tm.GenerateToken(lastSeqNum, committeeID)
		require.NoError(t, err)

		// Try to validate with different committee ID
		_, err = tm.ValidateToken(token, "wrong-committee")
		require.Error(t, err)
		require.Contains(t, err.Error(), "committee mismatch")
	})

	t.Run("Tampered token should fail", func(t *testing.T) {
		token, err := tm.GenerateToken(lastSeqNum, committeeID)
		require.NoError(t, err)

		// Tamper with token by changing last character
		tamperedToken := token[:len(token)-1] + "X"

		_, err = tm.ValidateToken(tamperedToken, committeeID)
		require.Error(t, err)
	})

	t.Run("Empty token should fail", func(t *testing.T) {
		_, err := tm.ValidateToken("", committeeID)
		require.Error(t, err)
		require.Contains(t, err.Error(), "empty token")
	})

	t.Run("Invalid base64 token should fail", func(t *testing.T) {
		_, err := tm.ValidateToken("invalid-base64!", committeeID)
		require.Error(t, err)
	})
}

func TestGenerateRandomSecret(t *testing.T) {
	secret1, err := GenerateRandomSecret()
	require.NoError(t, err)
	require.Len(t, secret1, 32)

	secret2, err := GenerateRandomSecret()
	require.NoError(t, err)
	require.Len(t, secret2, 32)

	// Secrets should be different
	require.NotEqual(t, secret1, secret2)
}
