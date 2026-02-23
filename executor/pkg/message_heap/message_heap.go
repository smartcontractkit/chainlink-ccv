package message_heap

import (
	"container/heap"
	"errors"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// ExpiryWithMessage is the struct used to maintain data of a message, not used directly for priority queue.
type ExpiryWithMessage struct {
	Message       *protocol.Message
	ExpiryTime    time.Time
	RetryInterval time.Duration
}

// MessageWithTimestamps is the aggregated struct that is used when inserting and retrieving from the heap.
type MessageWithTimestamps struct {
	MessageID     protocol.Bytes32
	RetryInterval time.Duration
	ReadyTime     time.Time
	Message       *protocol.Message
	ExpiryTime    time.Time
}

// MessageHeapEntry is the minimal set of data needed to maintain the priority queue heap.
type MessageHeapEntry struct {
	ReadyTime time.Time
	MessageID protocol.Bytes32
}

type ReadyTimestampHeap []MessageHeapEntry

func (h ReadyTimestampHeap) Len() int {
	return len(h)
}

func (h ReadyTimestampHeap) Less(i, j int) bool {
	return h[i].ReadyTime.Before(h[j].ReadyTime)
}

func (h ReadyTimestampHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
}

func (h *ReadyTimestampHeap) Push(x any) {
	val, ok := x.(MessageHeapEntry)
	if !ok {
		return
	}
	*h = append(*h, val)
}

func (h *ReadyTimestampHeap) Pop() any {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]
	return x
}

var HeapIsEmptyErr = errors.New("heap is empty")

func (h *ReadyTimestampHeap) peek() (MessageHeapEntry, error) {
	if h.Len() <= 0 {
		return MessageHeapEntry{}, HeapIsEmptyErr
	}
	return (*h)[0], nil
}

// MessageHeap is the struct used to maintain the priority queue for timing messages in the coordinator.
// Internally, it uses a heap for timing, and a separate map for the data of the message.
// This is to reduce the amount of data and locking overhead when pushing and popping messages and fixing the heap.
type MessageHeap struct {
	heap    ReadyTimestampHeap
	dataMap map[protocol.Bytes32]ExpiryWithMessage
	mu      *sync.RWMutex
}

func NewMessageHeap() *MessageHeap {
	h := &ReadyTimestampHeap{}
	heap.Init(h)
	msgHeap := MessageHeap{
		heap:    *h,
		dataMap: make(map[protocol.Bytes32]ExpiryWithMessage),
		mu:      &sync.RWMutex{},
	}

	return &msgHeap
}

func (mh *MessageHeap) Push(msg MessageWithTimestamps) {
	mh.mu.Lock()
	defer mh.mu.Unlock()

	heap.Push(&mh.heap, MessageHeapEntry{
		ReadyTime: msg.ReadyTime,
		MessageID: msg.MessageID,
	})

	mh.dataMap[msg.MessageID] = ExpiryWithMessage{
		Message:       msg.Message,
		ExpiryTime:    msg.ExpiryTime,
		RetryInterval: msg.RetryInterval,
	}
}

func (mh *MessageHeap) PopAllReady(timestamp time.Time) []MessageWithTimestamps {
	mh.mu.Lock()
	defer mh.mu.Unlock()

	var readyMessages []MessageWithTimestamps

	for mh.heap.Len() > 0 {
		msg, err := mh.heap.peek()
		if err != nil || msg.ReadyTime.After(timestamp) {
			break
		}

		msg, ok := heap.Pop(&mh.heap).(MessageHeapEntry)
		if !ok {
			continue
		}
		readyMessages = append(readyMessages, MessageWithTimestamps{
			MessageID:     msg.MessageID,
			RetryInterval: mh.dataMap[msg.MessageID].RetryInterval,
			ReadyTime:     msg.ReadyTime,
			Message:       mh.dataMap[msg.MessageID].Message,
			ExpiryTime:    mh.dataMap[msg.MessageID].ExpiryTime,
		})
		delete(mh.dataMap, msg.MessageID)
	}
	return readyMessages
}

func (mh *MessageHeap) Has(id protocol.Bytes32) bool {
	mh.mu.RLock()
	defer mh.mu.RUnlock()
	_, exists := mh.dataMap[id]
	return exists
}

func (mh *MessageHeap) Len() int {
	mh.mu.RLock()
	defer mh.mu.RUnlock()
	return len(mh.dataMap)
}

// ExpirableMessageSet is a set of messageIDs associated with an expiry time.
// It's used in the indexer storage streamer to deduplicate messages, but only hold for 24 hours.
type ExpirableMessageSet struct {
	heap           ReadyTimestampHeap
	dataMap        map[protocol.Bytes32]struct{}
	expiryDuration time.Duration
	mu             *sync.RWMutex
}

func NewExpirableSet(expiryDuration time.Duration) *ExpirableMessageSet {
	h := &ReadyTimestampHeap{}
	heap.Init(h)
	msgHeap := ExpirableMessageSet{
		heap:           *h,
		dataMap:        make(map[protocol.Bytes32]struct{}),
		mu:             &sync.RWMutex{},
		expiryDuration: expiryDuration,
	}

	return &msgHeap
}

func (es *ExpirableMessageSet) PushUnlessExists(msg protocol.Bytes32, initTime time.Time) bool {
	es.mu.Lock()
	defer es.mu.Unlock()

	_, exists := es.dataMap[msg]
	if exists {
		return false
	}
	heap.Push(&es.heap, MessageHeapEntry{
		ReadyTime: initTime.Add(es.expiryDuration),
		MessageID: msg,
	})

	es.dataMap[msg] = struct{}{}
	return true
}

func (es *ExpirableMessageSet) Has(msg protocol.Bytes32) bool {
	es.mu.RLock()
	defer es.mu.RUnlock()
	_, exists := es.dataMap[msg]
	return exists
}

func (es *ExpirableMessageSet) Len() int {
	es.mu.RLock()
	defer es.mu.RUnlock()
	return len(es.dataMap)
}

func (es *ExpirableMessageSet) CleanExpired(timestamp time.Time) int {
	es.mu.Lock()
	defer es.mu.Unlock()

	expiredCount := 0
	for es.heap.Len() > 0 {
		msg, err := es.heap.peek()
		if err != nil || msg.ReadyTime.After(timestamp) {
			break
		}

		msg, ok := heap.Pop(&es.heap).(MessageHeapEntry)
		if !ok {
			continue
		}
		delete(es.dataMap, msg.MessageID)
		expiredCount++
	}
	return expiredCount
}
