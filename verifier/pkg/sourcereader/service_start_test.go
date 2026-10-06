package sourcereader

import (
	"context"
	"errors"
	"math/big"
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

	// Start returns immediately even though the init DB read never completes.
	require.NoError(t, srs.Start(t.Context()))
	defer func() { require.NoError(t, srs.Close()) }()

	// The background init reaches the blocked read while the service reports not-ready.
	select {
	case <-readStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("background init never attempted the chain status read")
	}
	require.Error(t, srs.Ready(), "service must report not-ready until the start block is initialized")

	// Once the dependency recovers, init completes and the service becomes ready.
	close(release)
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
	require.Error(t, srs.Ready())

	require.Eventually(t, func() bool {
		return srs.Ready() == nil
	}, 2*time.Second, 5*time.Millisecond, "service should self-heal once init succeeds")
	require.GreaterOrEqual(t, attempts.Load(), int32(3))
}
