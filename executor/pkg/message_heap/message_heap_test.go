package message_heap

import (
	"container/heap"
	"reflect"
	"testing"
	"time"

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

func createMessageWithTimestamp(readyTime time.Time, nonce uint64) *MessageWithTimestamps {
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
	t1 := time.Unix(100, 0)
	t2 := time.Unix(200, 0)
	t3 := time.Unix(300, 0)
	tests := []struct {
		name     string
		messages []*MessageWithTimestamps
		expected time.Time
	}{
		{
			name: "single element heap",
			messages: []*MessageWithTimestamps{
				createMessageWithTimestamp(t1, 1),
			},
			expected: t1,
		},
		{
			name: "multi-element heap - should return earliest",
			messages: []*MessageWithTimestamps{
				createMessageWithTimestamp(t3, 3),
				createMessageWithTimestamp(t1, 1),
				createMessageWithTimestamp(t2, 2),
			},
			expected: t1,
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
	t05 := time.Unix(50, 0)
	t1 := time.Unix(100, 0)
	t15 := time.Unix(150, 0)
	t2 := time.Unix(200, 0)
	t3 := time.Unix(300, 0)
	tests := []struct {
		name           string
		messages       []*MessageWithTimestamps
		expectedNonces []uint64
		timestamp      time.Time
		expectedCount  int
		remainingCount int
	}{
		{
			name:           "empty heap",
			messages:       []*MessageWithTimestamps{},
			timestamp:      t1,
			expectedCount:  0,
			expectedNonces: []uint64{},
			remainingCount: 0,
		},
		{
			name: "no messages ready",
			messages: []*MessageWithTimestamps{
				createMessageWithTimestamp(t3, 2),
				createMessageWithTimestamp(t2, 1),
			},
			timestamp:      t1,
			expectedCount:  0,
			expectedNonces: []uint64{},
			remainingCount: 2,
		},
		{
			name: "some messages ready",
			messages: []*MessageWithTimestamps{
				createMessageWithTimestamp(t3, 4),
				createMessageWithTimestamp(t2, 3),
				createMessageWithTimestamp(t05, 1),
				createMessageWithTimestamp(t1, 2),
			},
			timestamp:      t15,
			expectedCount:  2,
			expectedNonces: []uint64{1, 2},
			remainingCount: 2,
		},
		{
			name: "all messages ready",
			messages: []*MessageWithTimestamps{
				createMessageWithTimestamp(t2, 3),
				createMessageWithTimestamp(t05, 1),
				createMessageWithTimestamp(t1, 2),
			},
			timestamp:      t2,
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
	t0_5 := time.Unix(50, 0)
	t1 := time.Unix(100, 0)
	t2 := time.Unix(200, 0)
	t3 := time.Unix(300, 0)
	mh := &ReadyTimestampHeap{}
	heap.Init(mh)

	// Test that heap is initially empty
	if mh.Len() != 0 {
		t.Errorf("New heap should be empty")
	}

	// Push some messages out of order
	messages := []*MessageWithTimestamps{
		createMessageWithTimestamp(t0_5, 0),
		createMessageWithTimestamp(t3, 3),
		createMessageWithTimestamp(t1, 1),
		createMessageWithTimestamp(t2, 2),
	}

	for _, msg := range messages {
		heap.Push(mh, MessageHeapEntry{
			ReadyTime: msg.ReadyTime,
			MessageID: msg.MessageID,
		})
		// Verify heap property - should always return earliest time
		if mh.Peek().ReadyTime != t0_5 {
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

func TestExpirableMessageSet_Push_Has_Len(t *testing.T) {
	es := NewExpirableSet(1 * time.Hour)
	id1 := protocol.Bytes32{1}
	id2 := protocol.Bytes32{2}
	id3 := protocol.Bytes32{3}

	// Initially, set should be empty
	if es.Len() != 0 {
		t.Errorf("ExpirableMessageSet.Len() = %v, want 0", es.Len())
	}

	// Add one element
	expiry := time.Now().Add(1 * time.Hour)
	es.PushUnlessExists(id1, expiry)
	if !es.Has(id1) {
		t.Errorf("ExpirableMessageSet.Has(id1) = false, want true")
	}
	if es.Len() != 1 {
		t.Errorf("ExpirableMessageSet.Len() = %v, want 1", es.Len())
	}

	// Add a second element
	es.PushUnlessExists(id2, expiry)
	if !es.Has(id2) {
		t.Errorf("ExpirableMessageSet.Has(id2) = false, want true")
	}
	if es.Len() != 2 {
		t.Errorf("ExpirableMessageSet.Len() = %v, want 2", es.Len())
	}

	// Should not have a non-existent id
	if es.Has(id3) {
		t.Errorf("ExpirableMessageSet.Has(id3) = true, want false")
	}
}

func TestExpirableMessageSet_ExpiryBehavior(t *testing.T) {
	expiryDuration := 1 * time.Hour
	es := NewExpirableSet(expiryDuration)
	now := time.Now()

	id1 := protocol.Bytes32{1}
	id2 := protocol.Bytes32{2}

	// Push id1 at now
	es.PushUnlessExists(id1, now)
	// Push id2 an hour earlier than now (should be expired immediately after CleanExpired)
	es.PushUnlessExists(id2, now.Add(-expiryDuration))

	if !es.Has(id1) {
		t.Error("Expected id1 to be present right after push")
	}
	if !es.Has(id2) {
		t.Error("Expected id2 to be present right after push")
	}

	// id2 should expire immediately
	expired := es.CleanExpired(now)
	if expired != 1 {
		t.Errorf("Expected 1 message to expire, got %d", expired)
	}
	if es.Has(id2) {
		t.Error("Expected id2 to have been expired and removed")
	}
	if !es.Has(id1) {
		t.Error("id1 should still be present and unexpired")
	}

	// id1 should not be expired yet
	expired2 := es.CleanExpired(now)
	if expired2 != 0 {
		t.Errorf("Expected no more expired messages, got %d", expired2)
	}

	// Advance time far enough that id1 will expire
	expired3 := es.CleanExpired(now.Add(expiryDuration + time.Minute))
	if expired3 != 1 {
		t.Errorf("Expected id1 expired later, got %d", expired3)
	}
	if es.Len() != 0 {
		t.Errorf("Expected set to be empty after expiring all, got Len=%d", es.Len())
	}
}
func TestExpirableMessageSet_HasAndLen(t *testing.T) {
	expiryDuration := 30 * time.Minute
	es := NewExpirableSet(expiryDuration)
	now := time.Now()
	ids := []protocol.Bytes32{
		{1, 2, 3},
		{4, 5, 6},
		{7, 8, 9},
	}
	for i, id := range ids {
		es.PushUnlessExists(id, now.Add(time.Duration(i)*time.Minute))
	}

	for _, id := range ids {
		if !es.Has(id) {
			t.Errorf("Expected id %v to be present after Push", id)
		}
	}
	if got, want := es.Len(), len(ids); got != want {
		t.Errorf("Expected Len() = %d, got %d", want, got)
	}
}

func TestExpirableMessageSet_ExpiredInsertionOrder(t *testing.T) {
	expiryDuration := 1 * time.Minute
	es := NewExpirableSet(expiryDuration)
	base := time.Now()

	// Insert messages, with id2 inserted earlier, so should expire first
	id1 := protocol.Bytes32{1}
	id2 := protocol.Bytes32{2}
	id3 := protocol.Bytes32{3}

	es.PushUnlessExists(id2, base.Add(-2*time.Minute))  // Should expire first
	es.PushUnlessExists(id1, base.Add(-90*time.Second)) // Should expire second
	es.PushUnlessExists(id3, base)                      // Should not expire yet

	// Expire up to now
	expired := es.CleanExpired(base)
	if expired != 2 {
		t.Errorf("Expected 2 expired messages, got %d", expired)
	}

	if es.Has(id2) || es.Has(id1) {
		t.Errorf("Expired IDs should not remain in set")
	}
	if !es.Has(id3) {
		t.Errorf("id3 should still be present and unexpired")
	}

	// Now expire remaining
	expired2 := es.CleanExpired(base.Add(expiryDuration + time.Second))
	if expired2 != 1 {
		t.Errorf("Expected 1 expired message (id3), got %d", expired2)
	}
	if es.Len() != 0 {
		t.Errorf("Expected 0 after all expired, got %d", es.Len())
	}
}

func TestExpirableMessageSet_RePushDoesNotDuplicate(t *testing.T) {
	expiryDuration := 1 * time.Minute
	es := NewExpirableSet(expiryDuration)
	now := time.Now()
	id := protocol.Bytes32{9, 9, 9}

	es.PushUnlessExists(id, now)
	es.PushUnlessExists(id, now.Add(-2*time.Minute)) // Re-push same id, different time (should not duplicate entry)

	if es.Len() != 1 {
		t.Errorf("Duplicate Push of same id should not increase Len; got %d", es.Len())
	}
	// Expire entries far in future (ensures only one expiry occurs)
	expired := es.CleanExpired(now.Add(10 * time.Minute))
	// Since two pushes, but same id, only one expired
	if expired != 1 {
		t.Errorf("Expected only one expired even for duplicate pushes, got %d", expired)
	}
}

func TestExpirableMessageSet_EmptyBehavior(t *testing.T) {
	// Should not panic or crash on empty set
	expiryDuration := 1 * time.Minute
	es := NewExpirableSet(expiryDuration)
	now := time.Now()

	if n := es.Len(); n != 0 {
		t.Errorf("Expected empty set length 0, got %d", n)
	}
	expired := es.CleanExpired(now)
	if expired != 0 {
		t.Errorf("No items to expire, but got expired=%d", expired)
	}
	var id protocol.Bytes32
	if es.Has(id) {
		t.Error("Should not find id in empty set")
	}
}
