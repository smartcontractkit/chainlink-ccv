package common

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/verifier/testutil"
)

func TestFilterEncodableMessages_AllValid_ReturnsAllAsEncodableAndNoSkipped(t *testing.T) {
	msg := testutil.CreateTestMessage(t, 1, 1, 100, 10, 200000)
	messages := []MessageWithMetadata{
		{Message: msg, Metadata: MessageMetadata{Status: MessageProcessing, IngestionTimestamp: time.Now()}},
	}
	encodable, skipped := FilterEncodableMessages(messages)
	assert.Len(t, encodable, 1)
	assert.Empty(t, skipped)
	assert.Equal(t, messages[0], encodable[0])
}

func TestFilterEncodableMessages_MessageFailsMessageID_ThatMessageSkippedRestEncodable(t *testing.T) {
	validMsg := testutil.CreateTestMessage(t, 1, 1, 100, 10, 200000)
	invalidMsg := validMsg
	invalidMsg.SenderLength = 99
	messages := []MessageWithMetadata{
		{Message: validMsg, Metadata: MessageMetadata{Status: MessageProcessing, IngestionTimestamp: time.Now()}},
		{Message: invalidMsg, Metadata: MessageMetadata{Status: MessageProcessing, IngestionTimestamp: time.Now()}},
		{Message: validMsg, Metadata: MessageMetadata{Status: MessageProcessing, IngestionTimestamp: time.Now()}},
	}
	encodable, skipped := FilterEncodableMessages(messages)
	require.Len(t, encodable, 2)
	assert.Equal(t, messages[0], encodable[0])
	assert.Equal(t, messages[2], encodable[1])
	require.Len(t, skipped, 1)
	assert.Equal(t, 1, skipped[0].Index)
	assert.Contains(t, skipped[0].Reason, "SenderLength mismatch")
}

func TestFilterEncodableMessages_AllInvalid_ReturnsEmptyEncodableAndAllSkipped(t *testing.T) {
	validMsg := testutil.CreateTestMessage(t, 1, 1, 100, 10, 200000)
	invalidMsg := validMsg
	invalidMsg.SenderLength = 99
	messages := []MessageWithMetadata{
		{Message: invalidMsg, Metadata: MessageMetadata{Status: MessageProcessing, IngestionTimestamp: time.Now()}},
		{Message: invalidMsg, Metadata: MessageMetadata{Status: MessageProcessing, IngestionTimestamp: time.Now()}},
	}
	encodable, skipped := FilterEncodableMessages(messages)
	assert.Empty(t, encodable)
	require.Len(t, skipped, 2)
	assert.Equal(t, 0, skipped[0].Index)
	assert.Equal(t, 1, skipped[1].Index)
}

func TestFilterEncodableMessages_EmptyInput_ReturnsEmptySlices(t *testing.T) {
	encodable, skipped := FilterEncodableMessages(nil)
	assert.Empty(t, encodable)
	assert.Empty(t, skipped)

	encodable, skipped = FilterEncodableMessages([]MessageWithMetadata{})
	assert.Empty(t, encodable)
	assert.Empty(t, skipped)
}
