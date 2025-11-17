package message_heap

import (
	"container/heap"
	"reflect"
	"testing"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

func createTestMessage(nonce, sourceChain, destChain uint64) *protocol.Message {
	return &protocol.Message{
		Nonce:               protocol.Nonce(nonce),
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
				heap.Push(&mh, msg)
			}

			if got := mh.peekTime(); got != tt.expected {
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
				heap.Push(&mh, msg)
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
				actualNonces = append(actualNonces, uint64(payload.Message.Nonce))
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

func TestMessageHeap_Integration(t *testing.T) {
	mh := NewMessageHeap()

	// Test that heap is initially empty
	if !mh.IsEmpty() {
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
		heap.Push(&mh, msg)
		// Verify heap property - should always return earliest time
		if mh.peekTime() != 50 {
			t.Errorf("peekTime() = %v, want 50", mh.peekTime())
		}
	}

	// Pop all messages and verify they come out in timestamp order
	expectedOrder := []int64{50, 100, 200, 300}
	expectedNonces := []uint64{0, 1, 2, 3}

	for i := 0; i < len(expectedOrder); i++ {
		if mh.IsEmpty() {
			t.Errorf("Heap is empty at iteration %v", i)
			break
		}

		if mh.peekTime() != expectedOrder[i] {
			t.Errorf("peekTime() at iteration %v = %v, want %v", i, mh.peekTime(), expectedOrder[i])
		}

		result := heap.Pop(&mh)
		msg, ok := result.(*MessageWithTimestamps)
		if !ok {
			t.Errorf("Pop() returned wrong type: %T", result)
			continue
		}

		if uint64(msg.Message.Nonce) != expectedNonces[i] {
			t.Errorf("Pop() at iteration %v returned nonce %v, want %v", i, msg.Message.Nonce, expectedNonces[i])
		}
	}

	// Verify heap is empty
	if !mh.IsEmpty() {
		t.Errorf("Heap should be empty after popping all elements")
	}
}
