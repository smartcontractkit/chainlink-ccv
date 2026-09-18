package sourcereader

import (
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// fakeRangeTracker replays a fixed sequence of verdicts, repeating the last one once exhausted.
type fakeRangeTracker struct {
	verdicts []bool
	calls    int
}

func (f *fakeRangeTracker) UnfinalizedRangeChanged(_ context.Context, _, _ *protocol.BlockHeader) (bool, error) {
	verdict := f.verdicts[min(f.calls, len(f.verdicts)-1)]
	f.calls++
	return verdict, nil
}

// TestSRS_RangeTracker_ReadsOnlyNewBlocks is the RPC saving the tracker exists for: once the
// reader vouches for the unfinalized range, a poll reads only the blocks the head advanced by.
func TestSRS_RangeTracker_ReadsOnlyNewBlocks(t *testing.T) {
	ctx := context.Background()
	chain := protocol.ChainSelector(1337)

	finalized := &protocol.BlockHeader{Number: 100}
	head200, head205 := &protocol.BlockHeader{Number: 200}, &protocol.BlockHeader{Number: 205}

	reader := mocks.NewMockSourceReader(t)
	// Cycle 1 has nothing vouched for yet, so the whole unfinalized range is read.
	reader.EXPECT().
		FetchMessageSentEvents(mock.Anything, big.NewInt(100), big.NewInt(200)).
		Return(nil, nil).Once()
	// Cycle 2 reads only the five new blocks rather than re-reading [100, 205].
	reader.EXPECT().
		FetchMessageSentEvents(mock.Anything, big.NewInt(201), big.NewInt(205)).
		Return(nil, nil).Once()

	srs := newRangeTrackerSRS(t, chain, reader, &fakeRangeTracker{verdicts: []bool{true, false}}, 100)

	require.True(t, srs.processEventCycle(ctx, head200, finalized))
	require.Equal(t, uint64(200), srs.lastReadBlock.Load())
	require.True(t, srs.processEventCycle(ctx, head205, finalized))
	require.Equal(t, uint64(205), srs.lastReadBlock.Load())
}

// TestSRS_RangeTracker_StalledHeadReadsNothing verifies an unmoved head costs no log query.
func TestSRS_RangeTracker_StalledHeadReadsNothing(t *testing.T) {
	ctx := context.Background()
	chain := protocol.ChainSelector(1337)

	finalized, head := &protocol.BlockHeader{Number: 100}, &protocol.BlockHeader{Number: 200}

	reader := mocks.NewMockSourceReader(t)
	reader.EXPECT().
		FetchMessageSentEvents(mock.Anything, big.NewInt(100), big.NewInt(200)).
		Return(nil, nil).Once()

	srs := newRangeTrackerSRS(t, chain, reader, &fakeRangeTracker{verdicts: []bool{true, false}}, 100)

	require.True(t, srs.processEventCycle(ctx, head, finalized))
	// No further FetchMessageSentEvents expectation: another call would fail the mock.
	require.True(t, srs.processEventCycle(ctx, head, finalized))
	require.True(t, srs.processEventCycle(ctx, head, finalized))
}

// TestSRS_RangeTracker_ReorgReReadsFullRange verifies a reported change widens the window back
// to finalized and that messages which do not reappear are tracked as reorged.
func TestSRS_RangeTracker_ReorgReReadsFullRange(t *testing.T) {
	ctx := context.Background()
	chain := protocol.ChainSelector(1337)

	finalized := &protocol.BlockHeader{Number: 100}
	head200, head205 := &protocol.BlockHeader{Number: 200}, &protocol.BlockHeader{Number: 205}
	events := createTestMessageSentEvents(t, 1, chain, defaultDestChain, []uint64{160})

	reader := mocks.NewMockSourceReader(t)
	reader.EXPECT().
		FetchMessageSentEvents(mock.Anything, big.NewInt(100), big.NewInt(200)).
		Return(events, nil).Once()
	// The reorg forces a full re-read, and the message at block 160 is gone from the new chain.
	reader.EXPECT().
		FetchMessageSentEvents(mock.Anything, big.NewInt(100), big.NewInt(205)).
		Return(nil, nil).Once()

	srs := newRangeTrackerSRS(t, chain, reader, &fakeRangeTracker{verdicts: []bool{true}}, 100)

	require.True(t, srs.processEventCycle(ctx, head200, finalized))
	srs.mu.RLock()
	require.Len(t, srs.pendingTasks, 1)
	srs.mu.RUnlock()

	require.True(t, srs.processEventCycle(ctx, head205, finalized))

	srs.mu.RLock()
	defer srs.mu.RUnlock()
	require.Empty(t, srs.pendingTasks, "the reorged message should be dropped from pending")
	require.True(t,
		srs.reorgTracker.RequiresFinalization(defaultDestChain, events[0].Message.SequenceNumber),
		"the reorged seqNum should require full finalization")
}

// TestSRS_NoRangeTracker_ReReadsEveryPoll covers chain families whose readers cannot prove the
// unfinalized range is unchanged: they keep re-reading all of it.
func TestSRS_NoRangeTracker_ReReadsEveryPoll(t *testing.T) {
	ctx := context.Background()
	chain := protocol.ChainSelector(1337)

	finalized := &protocol.BlockHeader{Number: 100}
	head200, head205 := &protocol.BlockHeader{Number: 200}, &protocol.BlockHeader{Number: 205}

	reader := mocks.NewMockSourceReader(t)
	reader.EXPECT().
		FetchMessageSentEvents(mock.Anything, big.NewInt(100), big.NewInt(200)).
		Return(nil, nil).Once()
	reader.EXPECT().
		FetchMessageSentEvents(mock.Anything, big.NewInt(100), big.NewInt(205)).
		Return(nil, nil).Once()

	srs := newRangeTrackerSRS(t, chain, reader, nil, 100)
	require.Nil(t, srs.rangeTracker, "a plain SourceReader must not be treated as a tracker")

	require.True(t, srs.processEventCycle(ctx, head200, finalized))
	require.True(t, srs.processEventCycle(ctx, head205, finalized))
}

// newRangeTrackerSRS builds a Service with the given range tracker and checkpoint.
func newRangeTrackerSRS(
	t *testing.T,
	chainSelector protocol.ChainSelector,
	reader *mocks.MockSourceReader,
	tracker *fakeRangeTracker,
	checkpoint int64,
) *Service {
	t.Helper()

	chainStatusMgr := mocks.NewMockChainStatusManager(t)
	chainStatusMgr.EXPECT().ReadChainStatuses(mock.Anything, mock.Anything).
		Return(map[protocol.ChainSelector]*protocol.ChainStatusInfo{}, nil).Maybe()

	curseDetector := mocks.NewMockCurseCheckerService(t)
	curseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).
		Return(false, nil).Maybe()

	srs, _, _ := newTestSRS(t, chainSelector, reader, chainStatusMgr, curseDetector, 10*time.Millisecond, 5000)
	if tracker != nil {
		srs.rangeTracker = tracker
	}
	srs.lastProcessedFinalizedBlock.Store(big.NewInt(checkpoint))
	return srs
}

// TestSRS_Reorg_HeadRewindReReadsRemined covers a reorg that rewinds the head below blocks
// already read, as a snapshot revert does. Blocks re-mined at those heights carry different
// content, so the read extent has to move backwards or they are never queried again.
func TestSRS_Reorg_HeadRewindReReadsRemined(t *testing.T) {
	ctx := context.Background()
	chain := protocol.ChainSelector(1337)

	finalized := &protocol.BlockHeader{Number: 100}

	reader := mocks.NewMockSourceReader(t)
	// Cycle 1 seeds and reads the whole range up to head 200.
	reader.EXPECT().
		FetchMessageSentEvents(mock.Anything, big.NewInt(100), big.NewInt(200)).
		Return(nil, nil).Once()
	// Cycle 3: the rewound chain re-mines 191 with different content, so the range is re-read.
	reader.EXPECT().
		FetchMessageSentEvents(mock.Anything, big.NewInt(100), big.NewInt(191)).
		Return(nil, nil).Once()
	// Cycle 4: 192 links onto the rebuilt tail and must still be read, even though a block at
	// that height was read before the rewind.
	reader.EXPECT().
		FetchMessageSentEvents(mock.Anything, big.NewInt(192), big.NewInt(192)).
		Return(nil, nil).Once()

	tracker := &fakeRangeTracker{verdicts: []bool{true, false, true, false}}
	srs := newRangeTrackerSRS(t, chain, reader, tracker, 100)

	// Cycle 1: head 200.
	require.True(t, srs.processEventCycle(ctx, &protocol.BlockHeader{Number: 200}, finalized))
	require.Equal(t, uint64(200), srs.lastReadBlock.Load())

	// Cycle 2: reverted to 190, whose hash is unchanged, so nothing to read.
	require.True(t, srs.processEventCycle(ctx, &protocol.BlockHeader{Number: 190}, finalized))

	// Cycle 3: 191 re-mined with different content - the reorg is detected here.
	require.True(t, srs.processEventCycle(ctx, &protocol.BlockHeader{Number: 191}, finalized))
	require.Equal(t, uint64(191), srs.lastReadBlock.Load(),
		"the read extent must follow the rewound chain, not stay at the pre-reorg high water mark")

	// Cycle 4: 192 on the new chain.
	require.True(t, srs.processEventCycle(ctx, &protocol.BlockHeader{Number: 192}, finalized))
}
