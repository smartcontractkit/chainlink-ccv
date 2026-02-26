package storageaccess

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"google.golang.org/protobuf/proto"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	committeepb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/committee-verifier/v1"
)

func TestAggregatorWriter_MessageSizeChecking(t *testing.T) {
	lggr := logger.Test(t)

	t.Run("splitIntoBatches respects byte size limits", func(t *testing.T) {
		writer := &AggregatorWriter{
			lggr:           lggr,
			maxMessageSize: 10 * 1024, // 10KB limit
		}

		// Create test requests with known sizes
		requests := []requestWithSize{
			{size: 2000, origIdx: 0}, // 2KB
			{size: 3000, origIdx: 1}, // 3KB
			{size: 4000, origIdx: 2}, // 4KB
			{size: 5000, origIdx: 3}, // 5KB
			{size: 1000, origIdx: 4}, // 1KB
			{size: 6000, origIdx: 5}, // 6KB
		}

		batches := writer.splitIntoBatches(requests)

		// Verify batches respect size limits
		for i, batch := range batches {
			totalSize := ProtoBatchOverhead
			for _, req := range batch {
				totalSize += req.size
			}
			assert.LessOrEqual(t, totalSize, writer.maxMessageSize,
				"batch %d exceeds max size: %d > %d", i, totalSize, writer.maxMessageSize)
		}

		// Verify all requests are included
		var allIndices []int
		for _, batch := range batches {
			for _, req := range batch {
				allIndices = append(allIndices, req.origIdx)
			}
		}
		assert.Equal(t, []int{0, 1, 2, 3, 4, 5}, allIndices)
	})

	t.Run("WriteCCVNodeData rejects oversized individual messages", func(t *testing.T) {
		ctx := context.Background()
		writer := &AggregatorWriter{
			lggr:           lggr,
			maxMessageSize: 1000, // Very small limit for testing
		}

		// Create a large message that will exceed the limit
		largeMessage := protocol.Message{
			SourceChainSelector: protocol.ChainSelector(1),
			// Add enough data to make the proto message > 1000 bytes
			Data: make([]byte, 2000),
		}

		messageID, err := largeMessage.MessageID()
		require.NoError(t, err)

		testData := []protocol.VerifierNodeResult{
			{
				Message:   largeMessage,
				MessageID: messageID,
			},
		}

		results, err := writer.WriteCCVNodeData(ctx, testData)

		require.NoError(t, err)
		require.Len(t, results, 1)

		// The oversized message should be marked as failed and non-retryable
		assert.Equal(t, protocol.WriteFailure, results[0].Status)
		assert.NotNil(t, results[0].Error)
		assert.False(t, results[0].Retryable, "oversized messages should not be retryable")
		assert.Contains(t, results[0].Error.Error(), "exceeds max message size")
	})

	t.Run("splitIntoBatches handles empty requests", func(t *testing.T) {
		writer := &AggregatorWriter{
			lggr:           lggr,
			maxMessageSize: 10 * 1024,
		}

		batches := writer.splitIntoBatches(nil)
		assert.Nil(t, batches)

		batches = writer.splitIntoBatches([]requestWithSize{})
		assert.Nil(t, batches)
	})

	t.Run("splitIntoBatches creates single batch when all fit", func(t *testing.T) {
		writer := &AggregatorWriter{
			lggr:           lggr,
			maxMessageSize: 20 * 1024, // 20KB limit
		}

		requests := []requestWithSize{
			{size: 1000, origIdx: 0},
			{size: 2000, origIdx: 1},
			{size: 1500, origIdx: 2},
		}

		batches := writer.splitIntoBatches(requests)

		require.Len(t, batches, 1)
		assert.Len(t, batches[0], 3)
	})

	t.Run("splitIntoBatches creates multiple batches when needed", func(t *testing.T) {
		writer := &AggregatorWriter{
			lggr:           lggr,
			maxMessageSize: 3 * 1024, // 3KB limit
		}

		// Each request is ~2KB, plus overhead means max 1 per batch
		requests := []requestWithSize{
			{size: 2000, origIdx: 0},
			{size: 2000, origIdx: 1},
			{size: 2000, origIdx: 2},
		}

		batches := writer.splitIntoBatches(requests)

		// With 1KB overhead and 2KB messages, only 1 message fits per batch at 3KB limit
		assert.GreaterOrEqual(t, len(batches), 2, "should create multiple batches")

		// Verify order is preserved
		idx := 0
		for _, batch := range batches {
			for _, req := range batch {
				assert.Equal(t, idx, req.origIdx)
				idx++
			}
		}
	})
}

func TestProtoMessageSizeCalculation(t *testing.T) {
	t.Run("proto.Size returns reasonable values for actual messages", func(t *testing.T) {
		// Create a realistic CCV message
		message := protocol.Message{
			SourceChainSelector: protocol.ChainSelector(1),
			SequenceNumber:      100,
			Data:                make([]byte, 1000), // 1KB of data
		}

		messageID, err := message.MessageID()
		require.NoError(t, err)

		ccvAddr, err := protocol.NewUnknownAddressFromHex("0x1234567890123456789012345678901234567890")
		require.NoError(t, err)

		ccvData := protocol.VerifierNodeResult{
			Message:    message,
			MessageID:  messageID,
			CCVVersion: []byte{1},
			CCVAddresses: []protocol.UnknownAddress{
				ccvAddr,
			},
			ExecutorAddress: ccvAddr,
			Signature:       []byte{0x01, 0x02, 0x03},
		}

		// Convert to proto
		protoReq, err := mapCCVDataToCCVNodeDataProto(ccvData)
		require.NoError(t, err)

		// Calculate size
		size := proto.Size(protoReq)

		// Size should be reasonable (not zero, not huge)
		assert.Greater(t, size, 0, "proto size should be positive")
		assert.Less(t, size, 10*1024, "proto size should be less than 10KB for this test message")

		t.Logf("Proto message size: %d bytes", size)
	})

	t.Run("proto.Size scales with data size", func(t *testing.T) {
		smallData := createTestMessage(100)  // 100 bytes
		largeData := createTestMessage(5000) // 5KB

		smallProto, err := mapCCVDataToCCVNodeDataProto(smallData)
		require.NoError(t, err)
		largeProto, err := mapCCVDataToCCVNodeDataProto(largeData)
		require.NoError(t, err)

		smallSize := proto.Size(smallProto)
		largeSize := proto.Size(largeProto)

		assert.Less(t, smallSize, largeSize, "larger data should result in larger proto size")

		t.Logf("Small message: %d bytes, Large message: %d bytes", smallSize, largeSize)
	})
}

func TestBatchOverheadEstimate(t *testing.T) {
	t.Run("ProtoBatchOverhead is reasonable", func(t *testing.T) {
		// Create a batch request with a few messages
		requests := []*committeepb.WriteCommitteeVerifierNodeResultRequest{
			{CommitteeVerifierNodeResult: &committeepb.CommitteeVerifierNodeResult{}},
			{CommitteeVerifierNodeResult: &committeepb.CommitteeVerifierNodeResult{}},
		}

		batchReq := &committeepb.BatchWriteCommitteeVerifierNodeResultRequest{
			Requests: requests,
		}

		// Calculate the overhead
		batchSize := proto.Size(batchReq)
		individualSizes := 0
		for _, req := range requests {
			individualSizes += proto.Size(req)
		}

		overhead := batchSize - individualSizes

		t.Logf("Batch overhead: %d bytes (batch: %d, individuals: %d)", overhead, batchSize, individualSizes)

		// Our constant should be reasonable - not too small to cause issues, not unnecessarily large
		assert.Less(t, overhead, ProtoBatchOverhead,
			"actual overhead (%d) should be less than our safety margin (%d)", overhead, ProtoBatchOverhead)
	})
}

// Helper function to create test messages with specific data sizes.
func createTestMessage(dataSize int) protocol.VerifierNodeResult {
	message := protocol.Message{
		SourceChainSelector: protocol.ChainSelector(1),
		SequenceNumber:      100,
		Data:                make([]byte, dataSize),
	}

	messageID, _ := message.MessageID()

	ccvAddr, _ := protocol.NewUnknownAddressFromHex("0x1234567890123456789012345678901234567890")

	return protocol.VerifierNodeResult{
		Message:    message,
		MessageID:  messageID,
		CCVVersion: []byte{1},
		CCVAddresses: []protocol.UnknownAddress{
			ccvAddr,
		},
		ExecutorAddress: ccvAddr,
		Signature:       []byte{0x01, 0x02, 0x03},
	}
}
