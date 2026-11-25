package e2e

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/load"
)

func newTestEVMTXGun(fireAndForget bool) *EVMTXGun {
	return &EVMTXGun{
		sentMsgCh:     make(chan load.SentMessage, load.SentMessageChannelBufferSize),
		fireAndForget: fireAndForget,
		pendingCh:     make(chan pendingTx, load.PendingMessageChannelBufferSize),
		shutdownCh:    make(chan struct{}),
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
		msg, ok := <-g.SentMessages()
		require.True(t, ok)
		require.Equal(t, uint64(1), msg.SeqNo)
		_, ok = <-g.SentMessages()
		require.False(t, ok)
	}
}

func TestEVMTXGun_FullBufferShutdown(t *testing.T) {
	// Regression: the staging mesh test runs the gun with no consumer; teardown must not hang.
	for _, faf := range []bool{false, true} {
		g := &EVMTXGun{
			sentMsgCh:     make(chan load.SentMessage, 1),
			pendingCh:     make(chan pendingTx, 1),
			fireAndForget: faf,
			shutdownCh:    make(chan struct{}),
		}
		g.sendPending(pendingTx{txHash: [32]byte{1}})
		g.sendSent(load.SentMessage{SeqNo: 1})
		var senders sync.WaitGroup
		for range 8 {
			senders.Add(1)
			go func() {
				defer senders.Done()
				g.sendPending(pendingTx{txHash: [32]byte{2}})
				g.sendSent(load.SentMessage{SeqNo: 2})
			}()
		}
		// Give blocked senders time to park on the full channels.
		time.Sleep(100 * time.Millisecond)

		finished := make(chan struct{})
		go func() {
			defer close(finished)
			g.CloseSentChannel()
		}()
		select {
		case <-finished:
		case <-time.After(10 * time.Second):
			t.Fatal("CloseSentChannel hung with full buffers and no consumer")
		}
		senders.Wait()

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
		for range 200 {
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
