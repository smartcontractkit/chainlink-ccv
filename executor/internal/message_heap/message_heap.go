package message_heap

import (
	"container/heap"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

type MessageHeap struct {
	h   []*MessageWithTimestamp
	set map[protocol.Bytes32]struct{}
}

type MessageWithTimestamp struct {
	ReadyTime int64
	Payload   *protocol.Message
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
	val, ok := x.(*MessageWithTimestamp)
	if !ok {
		return
	}
	id, _ := val.Payload.MessageID()
	if mh.set == nil {
		mh.set = make(map[protocol.Bytes32]struct{})
	}
	mh.set[id] = struct{}{}
	mh.h = append(mh.h, val)
}

func (mh *MessageHeap) Pop() any {
	old := mh.h
	n := len(old)
	x := old[n-1]
	mh.h = old[0 : n-1]

	id, _ := x.Payload.MessageID()
	delete(mh.set, id)

	return x
}

func (mh *MessageHeap) IsEmpty() bool {
	return mh.Len() == 0
}

func (mh *MessageHeap) PopAllReady(timestamp int64) []protocol.Message {
	var readyMessages []protocol.Message
	for mh.Len() > 0 && mh.PeekTime() <= timestamp {
		msg, ok := heap.Pop(mh).(*MessageWithTimestamp)
		if !ok {
			continue
		}
		readyMessages = append(readyMessages, *msg.Payload)
		id, _ := msg.Payload.MessageID()
		delete(mh.set, id)
	}
	return readyMessages
}

func (mh *MessageHeap) PeekTime() int64 {
	if mh.Len() == 0 {
		return 0
	}
	return mh.h[0].ReadyTime
}

func (mh *MessageHeap) Has(id protocol.Bytes32) bool {
	_, exists := mh.set[id]
	return exists
}
