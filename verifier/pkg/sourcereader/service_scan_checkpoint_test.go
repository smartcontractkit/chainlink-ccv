package sourcereader

import (
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	verifier "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vtypes"
)

// These tests use runPollCycle and hashOf from service_reorg_rescan_test.go.
// All cycles run synchronously; no background service goroutines are started.

type scanCheckpointState struct {
	height uint64
	writes []uint64
}

func newScanCheckpointService(t *testing.T, reader *mocks.MockSourceReader, state *scanCheckpointState, maxRange uint64) (*Service, *fakeTaskQueue) {
	t.Helper()
	chain := protocol.ChainSelector(1337)
	status := mocks.NewMockChainStatusManager(t)
	status.EXPECT().ReadChainStatuses(mock.Anything, []protocol.ChainSelector{chain}).
		RunAndReturn(func(context.Context, []protocol.ChainSelector) (map[protocol.ChainSelector]*protocol.ChainStatusInfo, error) {
			return map[protocol.ChainSelector]*protocol.ChainStatusInfo{
				chain: {ChainSelector: chain, FinalizedBlockHeight: new(big.Int).SetUint64(state.height)},
			}, nil
		}).Maybe()
	// Register before newTestSRS installs its permissive write expectation.
	status.EXPECT().WriteChainStatuses(mock.Anything, mock.Anything).
		RunAndReturn(func(_ context.Context, updates []protocol.ChainStatusInfo) error {
			require.Len(t, updates, 1)
			require.Equal(t, chain, updates[0].ChainSelector)
			state.height = updates[0].FinalizedBlockHeight.Uint64()
			state.writes = append(state.writes, state.height)
			return nil
		}).Maybe()
	curse := mocks.NewMockCurseCheckerService(t)
	curse.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).
		Return(false, nil).Maybe()
	srs, _, queue := newTestSRS(t, chain, reader, status, curse, time.Millisecond, maxRange)
	start, err := srs.initializeStartBlock(t.Context())
	require.NoError(t, err)
	srs.lastProcessedFinalizedBlock.Store(start)
	srs.startBlockInitialized.Store(true)
	return srs, queue
}

type scanCheckpointFailingQueue struct {
	*fakeTaskQueue
	err   error
	calls int
}

func (q *scanCheckpointFailingQueue) Publish(ctx context.Context, tasks ...verifier.VerificationTask) error {
	q.calls++
	if q.err != nil {
		return q.err
	}
	return q.fakeTaskQueue.Publish(ctx, tasks...)
}

func TestSRS_ScanCheckpoint_UnpublishedTaskSurvivesFailedScan(t *testing.T) {
	for _, failure := range []string{"header_error", "missing_header", "publish_error"} {
		for _, recovery := range []string{"restart", "retry_present", "retry_removed"} {
			t.Run(failure+"/"+recovery, func(t *testing.T) {
				state := &scanCheckpointState{height: 89}
				reader := mocks.NewMockSourceReader(t)
				srs, queue := newScanCheckpointService(t, reader, state, 5000)
				events := createTestMessageSentEvents(t, 1, protocol.ChainSelector(1337), defaultDestChain, []uint64{100})
				events[0].BlockHash = hashOf(0x64)
				id := events[0].MessageID.String()
				headers := map[uint64]protocol.BlockHeader{
					100: {Number: 100, Hash: protocol.Bytes32{0x64}},
				}
				failingQueue := &scanCheckpointFailingQueue{fakeTaskQueue: queue}
				srs.taskQueue = failingQueue
				switch failure {
				case "header_error":
					reader.EXPECT().GetBlocksHeaders(mock.Anything, []uint64{100}).Return(nil, assert.AnError).Once()
				case "missing_header":
					reader.EXPECT().GetBlocksHeaders(mock.Anything, []uint64{100}).Return(map[uint64]protocol.BlockHeader{}, nil).Once()
				case "publish_error":
					reader.EXPECT().GetBlocksHeaders(mock.Anything, []uint64{100}).Return(headers, nil).Once()
					failingQueue.err = assert.AnError
				}
				reader.EXPECT().FetchMessageSentEvents(mock.Anything, uint64(90), uint64(0)).Return(events, nil).Once()
				runPollCycle(t.Context(), srs, 110, 100)
				require.Equal(t, uint64(100), srs.lastProcessedFinalizedBlock.Load())
				require.Empty(t, queue.Published())
				require.Empty(t, state.writes)
				require.Contains(t, srs.pendingTasks, id)
				if failure == "publish_error" {
					require.Equal(t, 1, failingQueue.calls)
				} else {
					require.Zero(t, failingQueue.calls)
				}

				// No scan progress: coverage ends at 99, but the cursor is 100.
				// The skipped task must still prevent checkpointing block 100.
				reader.EXPECT().FetchMessageSentEvents(mock.Anything, uint64(100), uint64(0)).Return(nil, assert.AnError).Once()
				runPollCycle(t.Context(), srs, 115, 105)
				require.Empty(t, queue.Published())
				require.Contains(t, srs.pendingTasks, id)
				require.Empty(t, state.writes)
				require.Equal(t, uint64(89), state.height)
				reader.AssertNumberOfCalls(t, "GetBlocksHeaders", 1)

				from := uint64(100)
				if recovery == "restart" {
					// Discard all volatile state and use only the persisted checkpoint.
					reader = mocks.NewMockSourceReader(t)
					srs, queue = newScanCheckpointService(t, reader, state, 5000)
					from = 90
					require.Empty(t, srs.pendingTasks)
					require.Equal(t, from, srs.lastProcessedFinalizedBlock.Load())
				}
				failingQueue.err = nil
				if recovery == "retry_removed" {
					reader.EXPECT().FetchMessageSentEvents(mock.Anything, from, uint64(0)).Return(nil, nil).Once()
				} else {
					reader.EXPECT().FetchMessageSentEvents(mock.Anything, from, uint64(0)).Return(events, nil).Once()
					reader.EXPECT().GetBlocksHeaders(mock.Anything, []uint64{100}).Return(headers, nil).Once()
				}
				runPollCycle(t.Context(), srs, 115, 105)
				require.NotContains(t, srs.pendingTasks, id)
				require.Equal(t, []uint64{105}, state.writes)
				if recovery == "retry_removed" {
					require.Empty(t, queue.Published())
				} else {
					require.Len(t, queue.Published(), 1)
					require.Equal(t, id, queue.Published()[0].MessageID)
				}
			})
		}
	}
}

func TestSRS_ScanCheckpoint_PartialScanAllowsCheckpointBelowSkippedTask(t *testing.T) {
	state := &scanCheckpointState{height: 89}
	reader := mocks.NewMockSourceReader(t)
	srs, queue := newScanCheckpointService(t, reader, state, 10)
	events := createTestMessageSentEvents(t, 1, protocol.ChainSelector(1337), defaultDestChain, []uint64{95, 110})
	// Empty hashes keep this test focused on scan coverage and persistence.
	for i := range events {
		events[i].BlockHash = nil
	}
	reader.EXPECT().FetchMessageSentEvents(mock.Anything, uint64(90), uint64(100)).Return(events[:1], nil).Once()
	reader.EXPECT().FetchMessageSentEvents(mock.Anything, uint64(101), uint64(0)).Return(events[1:], nil).Once()
	runPollCycle(t.Context(), srs, 110, 90)
	require.Empty(t, queue.Published())
	require.Equal(t, []uint64{90}, state.writes)

	reader.EXPECT().FetchMessageSentEvents(mock.Anything, uint64(90), uint64(100)).Return(events[:1], nil).Once()
	reader.EXPECT().FetchMessageSentEvents(mock.Anything, uint64(101), uint64(111)).Return(nil, assert.AnError).Once()
	runPollCycle(t.Context(), srs, 120, 115)
	require.Len(t, queue.Published(), 1)
	require.Equal(t, events[0].MessageID.String(), queue.Published()[0].MessageID)
	require.Contains(t, srs.pendingTasks, events[1].MessageID.String())
	require.Equal(t, []uint64{90, 100}, state.writes,
		"task at 110 must not block checkpoint 100, even though finalized is 115")

	// A successful retry publishes the remaining task and resumes checkpointing.
	reader.EXPECT().FetchMessageSentEvents(mock.Anything, uint64(100), uint64(110)).Return(events[1:], nil).Once()
	reader.EXPECT().FetchMessageSentEvents(mock.Anything, uint64(111), uint64(0)).Return(nil, nil).Once()
	runPollCycle(t.Context(), srs, 120, 115)
	require.Len(t, queue.Published(), 2)
	require.Equal(t, events[1].MessageID.String(), queue.Published()[1].MessageID)
	require.Empty(t, srs.pendingTasks)
	require.Equal(t, []uint64{90, 100, 115}, state.writes)
}

func TestSRS_ScanCheckpoint_OpenEndedTailDoesNotStarveCheckpoint(t *testing.T) {
	state := &scanCheckpointState{height: 89}
	reader := mocks.NewMockSourceReader(t)
	srs, queue := newScanCheckpointService(t, reader, state, 5000)
	events := createTestMessageSentEvents(t, 1, protocol.ChainSelector(1337), defaultDestChain, []uint64{101, 102, 103})
	for i := range events {
		events[i].BlockHash = nil
	}
	for i := range events {
		// The RPC head advances after sampling latest. Each successful query
		// returns one new task above scannedThrough, reproducing steady traffic.
		from := srs.lastProcessedFinalizedBlock.Load()
		reader.EXPECT().FetchMessageSentEvents(mock.Anything, from, uint64(0)).Return(events[:i+1], nil).Once()
		runPollCycle(t.Context(), srs, uint64(100+i), uint64(90+i))
		require.Equal(t, uint64(90+i), state.height)
		require.Len(t, state.writes, i+1)
		require.Contains(t, srs.pendingTasks, events[i].MessageID.String())
	}
	require.Empty(t, queue.Published())
	require.Equal(t, []uint64{90, 91, 92}, state.writes)

	reader.EXPECT().FetchMessageSentEvents(mock.Anything, uint64(92), uint64(0)).Return(events, nil).Once()
	runPollCycle(t.Context(), srs, 120, 110)
	require.Len(t, queue.Published(), 3)
	require.Empty(t, srs.pendingTasks)
	require.Equal(t, []uint64{90, 91, 92, 110}, state.writes)
}
