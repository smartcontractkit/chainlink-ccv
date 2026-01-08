package model

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

func TestCommitVerificationRecordIdentifier_ToIdentifier(t *testing.T) {
	t.Run("formats message ID and address properly", func(t *testing.T) {
		identifier := CommitVerificationRecordIdentifier{
			MessageID: []byte{0x01, 0x02, 0x03},
			Address:   protocol.ByteSlice{0xaa, 0xbb, 0xcc},
		}

		result := identifier.ToIdentifier()

		assert.Contains(t, result, "010203:aabbcc")
	})

	t.Run("handles empty values", func(t *testing.T) {
		identifier := CommitVerificationRecordIdentifier{
			MessageID: []byte{},
			Address:   protocol.ByteSlice{},
		}

		result := identifier.ToIdentifier()
		assert.Contains(t, result, ":")
	})
}

func TestCommitVerificationRecord_GetID(t *testing.T) {
	t.Run("returns identifier for valid record", func(t *testing.T) {
		record := &CommitVerificationRecord{
			MessageID: []byte{0x01, 0x02, 0x03},
			SignerIdentifier: &SignerIdentifier{
				Identifier: protocol.ByteSlice{0xaa, 0xbb, 0xcc},
			},
		}

		result, err := record.GetID()
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, record.MessageID, result.MessageID)
		assert.Equal(t, record.SignerIdentifier.Identifier, result.Address)
	})

	t.Run("returns error for empty signer identifier", func(t *testing.T) {
		record := &CommitVerificationRecord{
			MessageID: []byte{0x01, 0x02, 0x03},
			SignerIdentifier: &SignerIdentifier{
				Identifier: protocol.ByteSlice{},
			},
		}

		result, err := record.GetID()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "identifier is nil or empty")
		assert.Nil(t, result)
	})

	t.Run("returns error for empty message ID", func(t *testing.T) {
		record := &CommitVerificationRecord{
			MessageID: []byte{},
			SignerIdentifier: &SignerIdentifier{
				Identifier: protocol.ByteSlice{0xaa, 0xbb, 0xcc},
			},
		}

		result, err := record.GetID()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "message ID is nil or empty")
		assert.Nil(t, result)
	})

	t.Run("returns error for nil message ID", func(t *testing.T) {
		record := &CommitVerificationRecord{
			MessageID: nil,
			SignerIdentifier: &SignerIdentifier{
				Identifier: protocol.ByteSlice{0xaa, 0xbb, 0xcc},
			},
		}

		result, err := record.GetID()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "message ID is nil or empty")
		assert.Nil(t, result)
	})
}

func TestCommitVerificationRecord_GetTimestamp(t *testing.T) {
	t.Run("returns stored timestamp", func(t *testing.T) {
		expectedTime := time.Date(2024, 6, 15, 12, 30, 45, 0, time.UTC)
		record := &CommitVerificationRecord{createdAt: expectedTime}

		result := record.GetTimestamp()
		assert.Equal(t, expectedTime, result)
	})

	t.Run("returns zero time for unset timestamp", func(t *testing.T) {
		record := &CommitVerificationRecord{}

		result := record.GetTimestamp()
		assert.True(t, result.IsZero())
	})
}

func TestCommitVerificationRecord_TimestampRoundTrip(t *testing.T) {
	originalMs := int64(1704067200123) // 2024-01-01 00:00:00.123 UTC

	record := &CommitVerificationRecord{}
	record.SetTimestampFromMillis(originalMs)

	resultMs := record.GetTimestamp().UnixMilli()
	assert.Equal(t, originalMs, resultMs)
}
