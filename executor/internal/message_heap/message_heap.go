package message_heap

import (
	"container/heap"
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

func (h *ReadyTimestampHeap) Peek() MessageHeapEntry {
	if h.Len() <= 0 {
		return MessageHeapEntry{}
	}
	return (*h)[0]
}

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
	for mh.heap.Len() > 0 && !mh.heap.Peek().ReadyTime.After(timestamp) {
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

func (mh *MessageHeap) Peek() MessageWithTimestamps {
	mh.mu.RLock()
	defer mh.mu.RUnlock()
	peek := mh.heap.Peek()
	return MessageWithTimestamps{
		MessageID:     peek.MessageID,
		RetryInterval: mh.dataMap[peek.MessageID].RetryInterval,
		ReadyTime:     peek.ReadyTime,
		Message:       mh.dataMap[peek.MessageID].Message,
		ExpiryTime:    mh.dataMap[peek.MessageID].ExpiryTime,
	}
}

func (mh *MessageHeap) Len() int {
	mh.mu.RLock()
	defer mh.mu.RUnlock()
	return len(mh.dataMap)
}
