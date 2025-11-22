package message_heap

import (
	"container/heap"
	"reflect"
	"testing"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

func createTestMessage(nonce, sourceChain, destChain uint64) *protocol.Message {
	return &protocol.Message{
		SequenceNumber:      protocol.SequenceNumber(nonce),
		SourceChainSelector: protocol.ChainSelector(sourceChain),
		DestChainSelector:   protocol.ChainSelector(destChain),
		Version:             1,
	}
}

func createMessageWithTimestamp(readyTime int64, nonce uint64) *MessageWithTimestamps {
	msg := createTestMessage(nonce, 1, 2)
	msgID, err := msg.MessageID()
	if err != nil {
		return nil
	}
	return &MessageWithTimestamps{
		ReadyTime:     readyTime,
		Message:       msg,
		MessageID:     msgID,
		RetryInterval: 0,
	}
}

func TestMessageHeap_PeekTime(t *testing.T) {
	tests := []struct {
		name     string
		messages []*MessageWithTimestamps
		expected int64
	}{
		{
			name: "single element heap",
			messages: []*MessageWithTimestamps{
				createMessageWithTimestamp(100, 1),
			},
			expected: 100,
		},
		{
			name: "multi-element heap - should return earliest",
			messages: []*MessageWithTimestamps{
				createMessageWithTimestamp(300, 3),
				createMessageWithTimestamp(100, 1),
				createMessageWithTimestamp(200, 2),
			},
			expected: 100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Initialize heap to maintain heap property
			mh := NewMessageHeap()

			for _, msg := range tt.messages {
				mh.Push(*msg)
			}

			if got := mh.Peek().ReadyTime; got != tt.expected {
				t.Errorf("MessageHeap.PeekTime() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestMessageHeap_PopAllReady(t *testing.T) {
	tests := []struct {
		name           string
		messages       []*MessageWithTimestamps
		expectedNonces []uint64
		timestamp      int64
		expectedCount  int
		remainingCount int
	}{
		{
			name:           "empty heap",
			messages:       []*MessageWithTimestamps{},
			timestamp:      100,
			expectedCount:  0,
			expectedNonces: []uint64{},
			remainingCount: 0,
		},
		{
			name: "no messages ready",
			messages: []*MessageWithTimestamps{
				createMessageWithTimestamp(300, 2),
				createMessageWithTimestamp(200, 1),
			},
			timestamp:      100,
			expectedCount:  0,
			expectedNonces: []uint64{},
			remainingCount: 2,
		},
		{
			name: "some messages ready",
			messages: []*MessageWithTimestamps{
				createMessageWithTimestamp(300, 4),
				createMessageWithTimestamp(200, 3),
				createMessageWithTimestamp(50, 1),
				createMessageWithTimestamp(100, 2),
			},
			timestamp:      150,
			expectedCount:  2,
			expectedNonces: []uint64{1, 2},
			remainingCount: 2,
		},
		{
			name: "all messages ready",
			messages: []*MessageWithTimestamps{
				createMessageWithTimestamp(150, 3),
				createMessageWithTimestamp(50, 1),
				createMessageWithTimestamp(100, 2),
			},
			timestamp:      200,
			expectedCount:  3,
			expectedNonces: []uint64{1, 2, 3},
			remainingCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Initialize heap to maintain heap property
			mh := NewMessageHeap()
			for _, msg := range tt.messages {
				mh.Push(*msg)
			}

			result := mh.PopAllReady(tt.timestamp)

			if len(result) != tt.expectedCount {
				t.Errorf("PopAllReady() returned %v messages, want %v", len(result), tt.expectedCount)
			}

			if mh.Len() != tt.remainingCount {
				t.Errorf("After PopAllReady(), heap has %v messages, want %v", mh.Len(), tt.remainingCount)
			}

			// Check that returned messages have expected nonces
			var actualNonces []uint64
			for _, payload := range result {
				actualNonces = append(actualNonces, uint64(payload.Message.SequenceNumber))
			}

			if !reflect.DeepEqual(actualNonces, tt.expectedNonces) {
				if len(actualNonces) == 0 && len(tt.expectedNonces) == 0 {
					return
				}
				t.Errorf("PopAllReady() returned nonces %v, want %v", actualNonces, tt.expectedNonces)
			}
		})
	}
}

func TestMessageHeap_InternalHeapIntegration(t *testing.T) {
	mh := &ReadyTimestampHeap{}
	heap.Init(mh)

	// Test that heap is initially empty
	if mh.Len() != 0 {
		t.Errorf("New heap should be empty")
	}

	// Push some messages out of order
	messages := []*MessageWithTimestamps{
		createMessageWithTimestamp(50, 0),
		createMessageWithTimestamp(300, 3),
		createMessageWithTimestamp(100, 1),
		createMessageWithTimestamp(200, 2),
	}

	for _, msg := range messages {
		heap.Push(mh, MessageHeapEntry{
			ReadyTime: msg.ReadyTime,
			MessageID: msg.MessageID,
		})
		// Verify heap property - should always return earliest time
		if mh.Peek().ReadyTime != 50 {
			t.Errorf("peekTime() = %v, want 50", mh.Peek().ReadyTime)
		}
	}

	// Pop all messages and verify they come out in timestamp order
	expectedOrder := []int{0, 2, 3, 1}

	for i := 0; i < len(expectedOrder); i++ {
		if mh.Len() == 0 {
			t.Errorf("Heap is empty at iteration %v", i)
			break
		}
		expectedMessage := messages[expectedOrder[i]]

		if mh.Peek().ReadyTime != expectedMessage.ReadyTime {
			t.Errorf("peekTime() at iteration %v = %v, want %v", i, mh.Peek().ReadyTime, expectedMessage.ReadyTime)
		}

		msg, ok := heap.Pop(mh).(MessageHeapEntry)
		if !ok {
			t.Errorf("Pop() returned wrong type: %T", msg)
			continue
		}

		if msg.MessageID != expectedMessage.MessageID {
			t.Errorf("Pop() at iteration %v returned message ID %v, want %v", i, msg.MessageID, expectedMessage.MessageID)
		}
	}

	// Verify heap is empty
	if mh.Len() != 0 {
		t.Errorf("Heap should be empty after popping all elements")
	}
}
