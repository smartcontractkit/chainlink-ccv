package timestamp_heap

import (
	"container/heap"

	"github.com/smartcontractkit/chainlink-ccv/executor/types"
)

type MessageHeap []*MessageWithTimestamp

type MessageWithTimestamp struct {
	Payload   *types.MessageWithCCVData
	ReadyTime int64
}

func (mh MessageHeap) Len() int {
	return len(mh)
}

func (mh MessageHeap) Less(i, j int) bool {
	return mh[i].ReadyTime < mh[j].ReadyTime
}

func (mh MessageHeap) Swap(i, j int) {
	mh[i], mh[j] = mh[j], mh[i]
}

func (mh *MessageHeap) Push(x any) {
	// Push and Pop use pointer receivers because they modify the slice's length,
	// not just its contents.
	val, ok := x.(*MessageWithTimestamp)
	if !ok {
		return
	}
	*mh = append(*mh, val)
}

func (mh *MessageHeap) Pop() any {
	old := *mh
	n := len(old)
	x := old[n-1]
	*mh = old[0 : n-1]
	return x
}

func (mh *MessageHeap) IsEmpty() bool {
	return mh.Len() == 0
}

func (mh *MessageHeap) PopAllReady(timestamp int64) []types.MessageWithCCVData {
	var readyMessages []types.MessageWithCCVData
	for mh.Len() > 0 && mh.PeekTime() <= timestamp {
		msg, ok := heap.Pop(mh).(*MessageWithTimestamp)
		if !ok {
			continue
		}
		readyMessages = append(readyMessages, *msg.Payload)
	}
	return readyMessages
}

func (mh *MessageHeap) PeekTime() int64 {
	if mh.Len() == 0 {
		return 0
	}
	return (*mh)[0].ReadyTime
}
