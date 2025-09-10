package utils

import (
	"container/heap"

	"github.com/smartcontractkit/chainlink-ccv/executor/types"
)

type MessageHeap []*MessageWithTimestamp

type MessageWithTimestamp struct {
	ReadyTime int64
	Payload   types.MessageWithCCVData
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
	*mh = append(*mh, x.(*MessageWithTimestamp))
}

func (mh *MessageHeap) Pop() any {
	old := *mh
	n := len(old)
	x := old[n-1]
	*mh = old[0 : n-1]
	return x.Payload
}

func (mh *MessageHeap) IsEmpty() bool {
	return mh.Len() == 0
}

func (mh *MessageHeap) PopAllReady(timestamp int64) []types.MessageWithCCVData {
	var readyMessages []types.MessageWithCCVData
	for mh.Len() > 0 && mh.PeekTime() <= timestamp {
		msg := heap.Pop(mh).(types.MessageWithCCVData)
		readyMessages = append(readyMessages, msg)
	}
	return readyMessages
}

func (mh *MessageHeap) PeekTime() int64 {
	return (*mh)[0].ReadyTime
}
