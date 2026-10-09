package sourcereader

import (
	"context"
	"errors"
	"math/big"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// Start must return promptly without waiting on the DB/chain reads that derive
// the start block: those belong to the background loop so a hanging or failing
// dependency cannot block or abort process startup.
func TestSRS_StartDoesNotBlockOnInitIO(t *testing.T) {
	chain := protocol.ChainSelector(1337)

	reader := mocks.NewMockSourceReader(t)
	chainStatusMgr := mocks.NewMockChainStatusManager(t)
	curseDetector := mocks.NewMockCurseCheckerService(t)

	// Hold the DB read open until the test releases it.
	readStarted := make(chan struct{})
	release := make(chan struct{})
	chainStatusMgr.EXPECT().ReadChainStatuses(mock.Anything, mock.Anything).
		Run(func(context.Context, []protocol.ChainSelector) {
			close(readStarted)
			<-release
		}).
		Return(map[protocol.ChainSelector]*protocol.ChainStatusInfo{
			chain: {ChainSelector: chain, FinalizedBlockHeight: big.NewInt(100)},
		}, nil).
		Maybe()
	reader.EXPECT().LatestAndFinalizedBlock(mock.Anything).
		Return(&protocol.BlockHeader{Number: 200}, &protocol.BlockHeader{Number: 150}, nil).
		Maybe()
	reader.EXPECT().LatestSafeBlock(mock.Anything).Return(nil, nil).Maybe()
	reader.EXPECT().FetchMessageSentEvents(mock.Anything, mock.Anything, mock.Anything).
		Return([]protocol.MessageSentEvent{}, nil).
		Maybe()
	curseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).
		Return(false, nil).
		Maybe()

	srs, _, _ := newTestSRS(t, chain, reader, chainStatusMgr, curseDetector, 20*time.Millisecond, 100)

	// Start must return promptly without waiting on the init DB/chain read.
	// Start runs in a goroutine with its own timeout so a regression back to
	// synchronous init fails fast instead of deadlocking until the test
	// timeout, and release is always closed before Close so the deferred
	// shutdown can never wait on a blocked init attempt.
	startDone := make(chan error, 1)
	go func() { startDone <- srs.Start(t.Context()) }()
	select {
	case err := <-startDone:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("Start blocked on initialization I/O")
	}
	releaseOnce := sync.Once{}
	releaseFn := func() { releaseOnce.Do(func() { close(release) }) }
	defer func() {
		// Release first so Close's wg.Wait can never block on a stuck init.
		releaseFn()
		require.NoError(t, srs.Close())
	}()

	// The background init reaches the blocked read while the service reports not-ready.
	select {
	case <-readStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("background init never attempted the chain status read")
	}
	require.Error(t, srs.Ready(), "service must report not-ready until the start block is initialized")

	// Once the dependency recovers, init completes and the service becomes ready.
	releaseFn()
	require.Eventually(t, func() bool {
		return srs.Ready() == nil
	}, 2*time.Second, 5*time.Millisecond)
}

// A failing init (DB down, RPC down) must not fail Start; the service retries
// in the background and self-heals.
func TestSRS_StartRetriesFailedInit(t *testing.T) {
	chain := protocol.ChainSelector(1337)

	reader := mocks.NewMockSourceReader(t)
	chainStatusMgr := mocks.NewMockChainStatusManager(t)
	curseDetector := mocks.NewMockCurseCheckerService(t)

	var attempts atomic.Int32
	chainStatusMgr.EXPECT().ReadChainStatuses(mock.Anything, mock.Anything).
		RunAndReturn(func(context.Context, []protocol.ChainSelector) (map[protocol.ChainSelector]*protocol.ChainStatusInfo, error) {
			if attempts.Add(1) < 3 {
				return nil, errors.New("transient DB error")
			}
			return map[protocol.ChainSelector]*protocol.ChainStatusInfo{
				chain: {ChainSelector: chain, FinalizedBlockHeight: big.NewInt(100)},
			}, nil
		}).
		Maybe()
	reader.EXPECT().LatestAndFinalizedBlock(mock.Anything).
		Return(&protocol.BlockHeader{Number: 200}, &protocol.BlockHeader{Number: 150}, nil).
		Maybe()
	reader.EXPECT().LatestSafeBlock(mock.Anything).Return(nil, nil).Maybe()
	reader.EXPECT().FetchMessageSentEvents(mock.Anything, mock.Anything, mock.Anything).
		Return([]protocol.MessageSentEvent{}, nil).
		Maybe()
	curseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).
		Return(false, nil).
		Maybe()

	srs, _, _ := newTestSRS(t, chain, reader, chainStatusMgr, curseDetector, 20*time.Millisecond, 100)

	require.NoError(t, srs.Start(t.Context()))
	defer func() { require.NoError(t, srs.Close()) }()

	// No not-ready assertion here: the retrying init can succeed between Start
	// and any unsynchronized Ready check. The blocked-read test above verifies
	// non-readiness while initialization is deterministically held pending.
	require.Eventually(t, func() bool {
		return srs.Ready() == nil
	}, 2*time.Second, 5*time.Millisecond, "service should self-heal once init succeeds")
	require.GreaterOrEqual(t, attempts.Load(), int32(3))
}
