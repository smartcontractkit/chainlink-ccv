package e2e

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/load"
)

func newTestEVMTXGun(fireAndForget bool, buf int) *EVMTXGun {
	return &EVMTXGun{
		sentMsgCh:     make(chan load.SentMessage, buf),
		fireAndForget: fireAndForget,
		pendingCh:     make(chan pendingTx, buf),
		shutdownCh:    make(chan struct{}),
		abandonCh:     make(chan struct{}),
	}
}

func TestEVMTXGun_SendBeforeClose(t *testing.T) {
	for _, faf := range []bool{false, true} {
		g := newTestEVMTXGun(faf, load.SentMessageChannelBufferSize)
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
		g := newTestEVMTXGun(faf, 1)
		g.sendPending(pendingTx{txHash: [32]byte{1}})
		g.sendSent(load.SentMessage{SeqNo: 1})
		var senders sync.WaitGroup
		for range 8 {
			senders.Go(func() {
				g.sendPending(pendingTx{txHash: [32]byte{2}})
				g.sendSent(load.SentMessage{SeqNo: 2})
			})
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

func TestEVMTXGun_WorkerPublishDuringShutdown(t *testing.T) {
	// Regression: a worker completing during teardown must still publish.
	g := newTestEVMTXGun(true, 1)
	g.fafWg.Go(func() {
		<-g.shutdownCh // block until teardown begins
		g.publishSent(load.SentMessage{SeqNo: 1})
	})

	finished := make(chan struct{})
	go func() {
		defer close(finished)
		g.CloseSentChannel()
	}()
	select {
	case <-finished:
	case <-time.After(10 * time.Second):
		t.Fatal("CloseSentChannel hung while a worker published during shutdown")
	}

	msg, ok := <-g.SentMessages()
	require.True(t, ok)
	require.Equal(t, uint64(1), msg.SeqNo)
	_, ok = <-g.SentMessages()
	require.False(t, ok)
}

func TestEVMTXGun_DrainBudgetExpires(t *testing.T) {
	old := receiptDrainBudget
	receiptDrainBudget = 50 * time.Millisecond
	defer func() { receiptDrainBudget = old }()
	g := newTestEVMTXGun(true, 1)
	g.fafWg.Go(func() {
		<-g.abandonCh // simulate a receipt fetch stuck past the budget
	})

	finished := make(chan struct{})
	go func() {
		defer close(finished)
		g.CloseSentChannel()
	}()
	select {
	case <-finished:
	case <-time.After(10 * time.Second):
		t.Fatal("CloseSentChannel ignored the drain budget")
	}

	// Late publishes must drop, not panic on the closed channel.
	g.publishSent(load.SentMessage{SeqNo: 1})
	require.Len(t, g.sentMsgCh, 0)
}

func TestEVMTXGun_SendAfterClose(t *testing.T) {
	for _, faf := range []bool{false, true} {
		g := newTestEVMTXGun(faf, load.SentMessageChannelBufferSize)
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
		g := newTestEVMTXGun(faf, load.SentMessageChannelBufferSize)
		var wg sync.WaitGroup
		go g.CloseSentChannel() // close first: maximize the race with senders
		for range 200 {
			wg.Go(func() {
				g.sendPending(pendingTx{txHash: [32]byte{2}})
			})
			wg.Go(func() {
				g.sendSent(load.SentMessage{SeqNo: 2})
			})
		}
		wg.Wait()
		g.CloseSentChannel()
	}
}
