package e2e

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/load"
)

func newTestEVMTXGun(fireAndForget bool) *EVMTXGun {
	return &EVMTXGun{
		sentMsgCh:     make(chan load.SentMessage, load.SentMessageChannelBufferSize),
		fireAndForget: fireAndForget,
		pendingCh:     make(chan pendingTx, load.PendingMessageChannelBufferSize),
	}
}

func TestEVMTXGun_SendBeforeClose(t *testing.T) {
	for _, faf := range []bool{false, true} {
		g := newTestEVMTXGun(faf)
		g.sendPending(pendingTx{txHash: [32]byte{1}})
		g.sendSent(load.SentMessage{SeqNo: 1})
		require.Len(t, g.pendingCh, 1)
		require.Len(t, g.sentMsgCh, 1)

		g.CloseSentChannel()
		// Buffered sends must still be delivered to the consumer before close.
		msg, ok := <-g.SentMessages()
		require.True(t, ok)
		require.Equal(t, uint64(1), msg.SeqNo)
		_, ok = <-g.SentMessages()
		require.False(t, ok)
	}
}

func TestEVMTXGun_SendAfterClose(t *testing.T) {
	for _, faf := range []bool{false, true} {
		g := newTestEVMTXGun(faf)
		g.CloseSentChannel()
		// Straggler sends after close must be dropped
		g.sendPending(pendingTx{txHash: [32]byte{1}})
		g.sendSent(load.SentMessage{SeqNo: 1})
		require.Len(t, g.sentMsgCh, 0)

		g.CloseSentChannel() // idempotent
	}
}

func TestEVMTXGun_ConcurrentSendAndClose(t *testing.T) {
	for _, faf := range []bool{false, true} {
		g := newTestEVMTXGun(faf)
		var wg sync.WaitGroup
		go g.CloseSentChannel() // close first: maximize the race with senders
		for i := 0; i < 200; i++ {
			wg.Add(2)
			go func() {
				defer wg.Done()
				g.sendPending(pendingTx{txHash: [32]byte{2}})
			}()
			go func() {
				defer wg.Done()
				g.sendSent(load.SentMessage{SeqNo: 2})
			}()
		}
		wg.Wait()
		g.CloseSentChannel()
	}
}
