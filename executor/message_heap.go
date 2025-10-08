package executor

import (
	"container/heap"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

type messageHeap []*messageWithTimestamp

type messageWithTimestamp struct {
	ReadyTime int64
	Payload   *protocol.Message
}

func (mh messageHeap) Len() int {
	return len(mh)
}

func (mh messageHeap) Less(i, j int) bool {
	return mh[i].ReadyTime < mh[j].ReadyTime
}

func (mh messageHeap) Swap(i, j int) {
	mh[i], mh[j] = mh[j], mh[i]
}

func (mh *messageHeap) Push(x any) {
	// Push and Pop use pointer receivers because they modify the slice's length,
	// not just its contents.
	val, ok := x.(*messageWithTimestamp)
	if !ok {
		return
	}
	*mh = append(*mh, val)
}

func (mh *messageHeap) Pop() any {
	old := *mh
	n := len(old)
	x := old[n-1]
	*mh = old[0 : n-1]
	return x
}

func (mh *messageHeap) IsEmpty() bool {
	return mh.Len() == 0
}

func (mh *messageHeap) PopAllReady(timestamp int64) []protocol.Message {
	var readyMessages []protocol.Message
	for mh.Len() > 0 && mh.PeekTime() <= timestamp {
		msg, ok := heap.Pop(mh).(*messageWithTimestamp)
		if !ok {
			continue
		}
		readyMessages = append(readyMessages, *msg.Payload)
	}
	return readyMessages
}

func (mh *messageHeap) PeekTime() int64 {
	if mh.Len() == 0 {
		return 0
	}
	return (*mh)[0].ReadyTime
}
