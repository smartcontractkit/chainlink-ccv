package message_heap

import (
	"container/heap"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// We can make this more performant by bringing expiryTime and message into the set
// the heap only needs to store the readyTime and messageID.
type MessageHeap struct {
	h   []*MessageHeapEntry
	set map[protocol.Bytes32]ExpiryWithMessage
}
type MessageHeapEntry struct {
	ReadyTime int64
	MessageID protocol.Bytes32
}
type ExpiryWithMessage struct {
	Message       *protocol.Message
	ExpiryTime    int64
	RetryInterval int64
}
type MessageWithTimestamps struct {
	MessageID     *protocol.Bytes32
	RetryInterval int64
	ReadyTime     int64
	Message       *protocol.Message
	ExpiryTime    int64
}

func (mh MessageHeap) Len() int {
	return len(mh.h)
}

func (mh MessageHeap) Less(i, j int) bool {
	return mh.h[i].ReadyTime < mh.h[j].ReadyTime
}

func (mh MessageHeap) Swap(i, j int) {
	mh.h[i], mh.h[j] = mh.h[j], mh.h[i]
}

func (mh *MessageHeap) Push(x any) {
	// Push and Pop use pointer receivers because they modify the slice's length,
	// not just its contents.
	val, ok := x.(*MessageWithTimestamps)
	if !ok {
		return
	}
	if mh.set == nil {
		mh.set = make(map[protocol.Bytes32]ExpiryWithMessage)
	}
	mh.set[*val.MessageID] = ExpiryWithMessage{
		Message:       val.Message,
		ExpiryTime:    val.ExpiryTime,
		RetryInterval: val.RetryInterval,
	}
	mh.h = append(mh.h, &MessageHeapEntry{
		ReadyTime: val.ReadyTime,
		MessageID: *val.MessageID,
	})
}

func (mh *MessageHeap) Pop() any {
	old := mh.h
	n := len(old)
	x := old[n-1]
	mh.h = old[0 : n-1]

	ret := &MessageWithTimestamps{
		ReadyTime:     x.ReadyTime,
		Message:       mh.set[x.MessageID].Message,
		ExpiryTime:    mh.set[x.MessageID].ExpiryTime,
		RetryInterval: mh.set[x.MessageID].RetryInterval,
		MessageID:     &x.MessageID,
	}
	delete(mh.set, x.MessageID)
	return ret
}

func (mh *MessageHeap) IsEmpty() bool {
	return mh.Len() == 0
}

func (mh *MessageHeap) PopAllReady(timestamp int64) []MessageWithTimestamps {
	var readyMessages []MessageWithTimestamps
	for mh.Len() > 0 && mh.peekTime() <= timestamp {
		msg, ok := heap.Pop(mh).(*MessageWithTimestamps)
		if !ok {
			continue
		}
		readyMessages = append(readyMessages, *msg)
		delete(mh.set, *msg.MessageID)
	}
	return readyMessages
}

func (mh *MessageHeap) peekTime() int64 {
	if mh.Len() == 0 {
		return 0
	}
	return mh.h[0].ReadyTime
}

func (mh *MessageHeap) Has(id protocol.Bytes32) bool {
	_, exists := mh.set[id]
	return exists
}
