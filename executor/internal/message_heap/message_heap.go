package message_heap

import (
	"container/heap"
	"sync"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

type MessageHeap struct {
	heap    []*MessageHeapEntry
	dataMap map[protocol.Bytes32]ExpiryWithMessage
	mu      *sync.RWMutex
}

// MessageHeapEntry is the minimal set of data needed to maintain the priority queue heap.
type MessageHeapEntry struct {
	ReadyTime int64
	MessageID protocol.Bytes32
}

// ExpiryWithMessage is the struct used to maintain data of a message, not used directly for priority queue.
// Todo: Use a time.Time object rather than a int64 timestamp for better stringification and logging.
type ExpiryWithMessage struct {
	Message       *protocol.Message
	ExpiryTime    int64
	RetryInterval int64
}

// MessageWithTimestamps is the aggregated struct that is used when inserting and retrieving from the heap.
type MessageWithTimestamps struct {
	MessageID     protocol.Bytes32
	RetryInterval int64
	ReadyTime     int64
	Message       *protocol.Message
	ExpiryTime    int64
}

func NewMessageHeap() MessageHeap {
	h := MessageHeap{
		heap:    make([]*MessageHeapEntry, 0),
		dataMap: make(map[protocol.Bytes32]ExpiryWithMessage),
		mu:      &sync.RWMutex{},
	}
	heap.Init(&h)
	return h
}

func (mh MessageHeap) Len() int {
	return len(mh.heap)
}

func (mh MessageHeap) Less(i, j int) bool {
	return mh.heap[i].ReadyTime < mh.heap[j].ReadyTime
}

func (mh MessageHeap) Swap(i, j int) {
	mh.heap[i], mh.heap[j] = mh.heap[j], mh.heap[i]
}

func (mh *MessageHeap) Push(x any) {
	mh.mu.Lock()
	defer mh.mu.Unlock()
	// Push and Pop use pointer receivers because they modify the slice's length,
	// not just its contents.
	val, ok := x.(*MessageWithTimestamps)
	if !ok {
		return
	}

	mh.dataMap[val.MessageID] = ExpiryWithMessage{
		Message:       val.Message,
		ExpiryTime:    val.ExpiryTime,
		RetryInterval: val.RetryInterval,
	}
	mh.heap = append(mh.heap, &MessageHeapEntry{
		ReadyTime: val.ReadyTime,
		MessageID: val.MessageID,
	})
}

func (mh *MessageHeap) Pop() any {
	mh.mu.Lock()
	defer mh.mu.Unlock()

	old := mh.heap
	n := len(old)
	x := old[n-1]
	mh.heap = old[0 : n-1]

	ret := &MessageWithTimestamps{
		ReadyTime:     x.ReadyTime,
		Message:       mh.dataMap[x.MessageID].Message,
		ExpiryTime:    mh.dataMap[x.MessageID].ExpiryTime,
		RetryInterval: mh.dataMap[x.MessageID].RetryInterval,
		MessageID:     x.MessageID,
	}
	delete(mh.dataMap, x.MessageID)
	return ret
}

func (mh *MessageHeap) IsEmpty() bool {
	return len(mh.heap) == 0
}

func (mh *MessageHeap) PopAllReady(timestamp int64) []MessageWithTimestamps {
	var readyMessages []MessageWithTimestamps
	for mh.Len() > 0 && mh.peekTime() <= timestamp {
		msg, ok := heap.Pop(mh).(*MessageWithTimestamps)
		if !ok {
			continue
		}
		readyMessages = append(readyMessages, *msg)
	}
	return readyMessages
}

func (mh *MessageHeap) peekTime() int64 {
	if mh.Len() == 0 {
		return 0
	}
	return mh.heap[0].ReadyTime
}

func (mh *MessageHeap) Has(id protocol.Bytes32) bool {
	mh.mu.RLock()
	defer mh.mu.RUnlock()
	_, exists := mh.dataMap[id]
	return exists
}
