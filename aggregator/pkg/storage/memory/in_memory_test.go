package memory

import (
	"context"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
)

func TestInMemoryStorage_GetBatchCCVData(t *testing.T) {
	storage := NewInMemoryStorage()
	ctx := context.Background()

	// Create test data
	messageID1 := []byte("message1")
	messageID2 := []byte("message2")
	messageID3 := []byte("message3") // This one won't have data

	report1 := &model.CommitAggregatedReport{
		MessageID: messageID1,
		Sequence:  1,
	}
	report2 := &model.CommitAggregatedReport{
		MessageID: messageID2,
		Sequence:  2,
	}

	// Store test data
	err := storage.SubmitReport(ctx, report1)
	require.NoError(t, err)
	err = storage.SubmitReport(ctx, report2)
	require.NoError(t, err)

	// Test batch retrieval
	messageIDs := []model.MessageID{messageID1, messageID2, messageID3}
	results, err := storage.GetBatchCCVData(ctx, messageIDs)
	require.NoError(t, err)

	// Verify results
	assert.Len(t, results, 2, "Should return 2 results (excluding messageID3)")

	messageID1Hex := hex.EncodeToString(messageID1)
	messageID2Hex := hex.EncodeToString(messageID2)
	messageID3Hex := hex.EncodeToString(messageID3)

	assert.Contains(t, results, messageID1Hex)
	assert.Contains(t, results, messageID2Hex)
	assert.NotContains(t, results, messageID3Hex)

	assert.Equal(t, report1, results[messageID1Hex])
	assert.Equal(t, report2, results[messageID2Hex])
}

func TestInMemoryStorage_GetBatchCCVData_EmptyMessageIDs(t *testing.T) {
	storage := NewInMemoryStorage()
	ctx := context.Background()

	// Test with empty message IDs
	results, err := storage.GetBatchCCVData(ctx, []model.MessageID{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestInMemoryStorage_GetBatchCCVData_NoMatchingData(t *testing.T) {
	storage := NewInMemoryStorage()
	ctx := context.Background()

	// Test with message IDs that don't exist
	messageIDs := []model.MessageID{[]byte("nonexistent1"), []byte("nonexistent2")}
	results, err := storage.GetBatchCCVData(ctx, messageIDs)
	require.NoError(t, err)
	assert.Empty(t, results)
}
