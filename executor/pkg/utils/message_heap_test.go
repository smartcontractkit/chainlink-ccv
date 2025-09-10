package utils

import (
	"container/heap"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/executor/types"
)

func TestMessageHeap_PopOrder(t *testing.T) {
	mh := &MessageHeap{}
	heap.Init(mh)

	// Insert messages with out-of-order ReadyTime
	heap.Push(mh, &MessageWithTimestamp{ReadyTime: 30, Payload: types.MessageWithCCVData{}})
	heap.Push(mh, &MessageWithTimestamp{ReadyTime: 10, Payload: types.MessageWithCCVData{}})
	heap.Push(mh, &MessageWithTimestamp{ReadyTime: 20, Payload: types.MessageWithCCVData{}})
	heap.Push(mh, &MessageWithTimestamp{ReadyTime: 15, Payload: types.MessageWithCCVData{}})

	var popped []int64
	for mh.Len() > 0 {
		msg := heap.Pop(mh).(*MessageWithTimestamp)
		popped = append(popped, msg.ReadyTime)
	}

	require.Equal(t, []uint64{10, 15, 20, 30}, popped)
}
