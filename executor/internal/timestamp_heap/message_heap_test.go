package timestamp_heap

import (
	"container/heap"
	"reflect"
	"testing"

	"github.com/smartcontractkit/chainlink-ccv/executor/types"

	protocoltypes "github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
)

func createTestMessage(nonce, sourceChain, destChain uint64) *types.MessageWithCCVData {
	return &types.MessageWithCCVData{
		CCVData: []protocoltypes.CCVData{},
		Message: protocoltypes.Message{
			Nonce:               protocoltypes.Nonce(nonce),
			SourceChainSelector: protocoltypes.ChainSelector(sourceChain),
			DestChainSelector:   protocoltypes.ChainSelector(destChain),
			Version:             1,
		},
		VerifiedTimestamp: 0,
	}
}

func createMessageWithTimestamp(readyTime int64, nonce uint64) *MessageWithTimestamp {
	return &MessageWithTimestamp{
		ReadyTime: readyTime,
		Payload:   createTestMessage(nonce, 1, 2),
	}
}

func TestMessageHeap_PeekTime(t *testing.T) {
	tests := []struct {
		name     string
		heap     MessageHeap
		expected int64
	}{
		{
			name: "single element heap",
			heap: MessageHeap{
				createMessageWithTimestamp(100, 1),
			},
			expected: 100,
		},
		{
			name: "multi-element heap - should return earliest",
			heap: MessageHeap{
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
			heap.Init(&tt.heap)

			if got := tt.heap.PeekTime(); got != tt.expected {
				t.Errorf("MessageHeap.PeekTime() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestMessageHeap_PopAllReady(t *testing.T) {
	tests := []struct {
		name           string
		heap           MessageHeap
		expectedNonces []uint64
		timestamp      int64
		expectedCount  int
		remainingCount int
	}{
		{
			name:           "empty heap",
			heap:           MessageHeap{},
			timestamp:      100,
			expectedCount:  0,
			expectedNonces: []uint64{},
			remainingCount: 0,
		},
		{
			name: "no messages ready",
			heap: MessageHeap{
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
			heap: MessageHeap{
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
			heap: MessageHeap{
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
			heap.Init(&tt.heap)

			result := tt.heap.PopAllReady(tt.timestamp)

			if len(result) != tt.expectedCount {
				t.Errorf("PopAllReady() returned %v messages, want %v", len(result), tt.expectedCount)
			}

			if tt.heap.Len() != tt.remainingCount {
				t.Errorf("After PopAllReady(), heap has %v messages, want %v", tt.heap.Len(), tt.remainingCount)
			}

			// Check that returned messages have expected nonces
			var actualNonces []uint64
			for _, msg := range result {
				actualNonces = append(actualNonces, uint64(msg.Message.Nonce))
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
	var mh MessageHeap
	heap.Init(&mh)

	// Test that heap is initially empty
	if !mh.IsEmpty() {
		t.Errorf("New heap should be empty")
	}

	// Push some messages out of order
	messages := []*MessageWithTimestamp{
		createMessageWithTimestamp(50, 0),
		createMessageWithTimestamp(300, 3),
		createMessageWithTimestamp(100, 1),
		createMessageWithTimestamp(200, 2),
	}

	for _, msg := range messages {
		heap.Push(&mh, msg)
		// Verify heap property - should always return earliest time
		if mh.PeekTime() != 50 {
			t.Errorf("PeekTime() = %v, want 50", mh.PeekTime())
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

		if mh.PeekTime() != expectedOrder[i] {
			t.Errorf("PeekTime() at iteration %v = %v, want %v", i, mh.PeekTime(), expectedOrder[i])
		}

		result := heap.Pop(&mh)
		msg, ok := result.(*MessageWithTimestamp)
		if !ok {
			t.Errorf("Pop() returned wrong type: %T", result)
			continue
		}

		if uint64(msg.Payload.Message.Nonce) != expectedNonces[i] {
			t.Errorf("Pop() at iteration %v returned nonce %v, want %v", i, msg.Payload.Message.Nonce, expectedNonces[i])
		}
	}

	// Verify heap is empty
	if !mh.IsEmpty() {
		t.Errorf("Heap should be empty after popping all elements")
	}
}
