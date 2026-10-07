package sourcereader

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	verifier "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vtypes"
	"github.com/smartcontractkit/chainlink-ccv/verifier/testutil"
)

// newRescanTestSRS makes a service with permissive chain status and curse mocks.
func newRescanTestSRS(t *testing.T, reader *mocks.MockSourceReader, maxBlockRange uint64) (*Service, *fakeTaskQueue) {
	t.Helper()
	chainStatusMgr := mocks.NewMockChainStatusManager(t)
	chainStatusMgr.EXPECT().ReadChainStatuses(mock.Anything, mock.Anything).
		Return(map[protocol.ChainSelector]*protocol.ChainStatusInfo{}, nil).Maybe()

	curseDetector := mocks.NewMockCurseCheckerService(t)
	curseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()

	srs, _, queue := newTestSRS(t, protocol.ChainSelector(1337), reader, chainStatusMgr, curseDetector, 10*time.Millisecond, maxBlockRange)
	srs.startBlockInitialized.Store(true)
	return srs, queue
}

// runPollCycle does the same steps as one eventMonitoringLoop tick after the head reads.
func runPollCycle(ctx context.Context, srs *Service, latest, finalized uint64) {
	latestHeader := &protocol.BlockHeader{Number: latest}
	finalizedHeader := &protocol.BlockHeader{Number: finalized}
	srs.processEventCycle(ctx, latestHeader, finalizedHeader)
	srs.sendReadyMessages(ctx, latestHeader, nil, finalizedHeader)
}

// hashOf returns a 32-byte block hash that starts with the given bytes.
func hashOf(prefix ...byte) protocol.ByteSlice {
	var hash protocol.Bytes32
	copy(hash[:], prefix)
	return hash[:]
}

func publishedIDs(queue *fakeTaskQueue) []string {
	published := queue.Published()
	ids := make([]string, 0, len(published))
	for _, task := range published {
		ids = append(ids, task.MessageID)
	}
	return ids
}

// A rescan that finds M in a different block uses the new block for readiness.
func TestSRS_Rescan_MovedMessageUsesLatestBlock(t *testing.T) {
	ctx := context.Background()
	reader := mocks.NewMockSourceReader(t)
	srs, queue := newRescanTestSRS(t, reader, 5000)
	srs.lastProcessedFinalizedBlock.Store(85)

	atOldBlock := createTestMessageSentEvents(t, 1, protocol.ChainSelector(1337), defaultDestChain, []uint64{100})
	atNewBlock := []protocol.MessageSentEvent{atOldBlock[0]}
	atNewBlock[0].BlockNumber = 101
	atNewBlock[0].TxHash = protocol.ByteSlice{0xbe, 0xef}
	atOldBlock[0].BlockHash = hashOf(0x10, 0x0a)
	atNewBlock[0].BlockHash = hashOf(0x10, 0x1b)
	msgID := atOldBlock[0].MessageID.String()
	reader.EXPECT().GetBlocksHeaders(mock.Anything, mock.Anything).Return(map[uint64]protocol.BlockHeader{
		100: {Number: 100, Hash: protocol.Bytes32{0x10, 0x0b}},
		101: {Number: 101, Hash: protocol.Bytes32(atNewBlock[0].BlockHash)},
	}, nil).Maybe()

	reader.EXPECT().FetchMessageSentEvents(mock.Anything, mock.Anything, mock.Anything).Return(atOldBlock, nil).Once()
	reader.EXPECT().FetchMessageSentEvents(mock.Anything, mock.Anything, mock.Anything).Return(atNewBlock, nil)

	runPollCycle(ctx, srs, 100, 90) // M is found at 100.
	runPollCycle(ctx, srs, 101, 90) // The canonical chain now has M at 101.
	require.Empty(t, queue.Published())

	runPollCycle(ctx, srs, 105, 100) // Block 100 is final, but block 101 is not.
	require.Empty(t, queue.Published(), "M waits for block 101 to be final")

	runPollCycle(ctx, srs, 106, 101)
	require.Equal(t, []string{msgID}, publishedIDs(queue))
	require.Equal(t, uint64(101), queue.Published()[0].BlockNumber)
	require.Equal(t, atNewBlock[0].BlockHash, queue.Published()[0].SourceBlockHash)
}

// A task stays pending until a successful scan covers its block.
func TestSRS_Rescan_FailedScanKeepsTaskPending(t *testing.T) {
	ctx := context.Background()
	reader := mocks.NewMockSourceReader(t)
	srs, queue := newRescanTestSRS(t, reader, 5000)
	srs.lastProcessedFinalizedBlock.Store(85)

	events := createTestMessageSentEvents(t, 1, protocol.ChainSelector(1337), defaultDestChain, []uint64{100})
	msgID := events[0].MessageID.String()

	reader.EXPECT().FetchMessageSentEvents(mock.Anything, mock.Anything, mock.Anything).Return(events, nil).Once()
	reader.EXPECT().FetchMessageSentEvents(mock.Anything, mock.Anything, mock.Anything).Return(nil, assert.AnError).Once()
	reader.EXPECT().FetchMessageSentEvents(mock.Anything, mock.Anything, mock.Anything).Return(nil, nil).Once()

	runPollCycle(ctx, srs, 100, 90) // M is found at 100, the cursor moves to 90.
	require.Equal(t, uint64(90), srs.lastProcessedFinalizedBlock.Load())

	runPollCycle(ctx, srs, 110, 105) // M is gone from the chain and the query fails.
	require.Empty(t, queue.Published(), "M stays pending until a scan covers block 100")

	runPollCycle(ctx, srs, 110, 105) // The next good scan does not return M.
	require.Empty(t, queue.Published())
	srs.mu.RLock()
	defer srs.mu.RUnlock()
	require.NotContains(t, srs.pendingTasks, msgID)
}

// A partial scan makes ready only the tasks in the scanned chunks.
func TestSRS_Rescan_PartialScanPublishesScannedRange(t *testing.T) {
	ctx := context.Background()
	reader := mocks.NewMockSourceReader(t)
	srs, queue := newRescanTestSRS(t, reader, 10)
	srs.lastProcessedFinalizedBlock.Store(90)

	events := createTestMessageSentEvents(t, 1, protocol.ChainSelector(1337), defaultDestChain, []uint64{95, 110})
	scanned, notScanned := events[0], events[1]
	srs.mu.Lock()
	for _, ev := range events {
		srs.pendingTasks[ev.MessageID.String()] = verifier.VerificationTask{
			Message: ev.Message, BlockNumber: ev.BlockNumber, MessageID: ev.MessageID.String(),
		}
	}
	srs.mu.Unlock()

	// Chunks are [90,100], [101,111], [112,latest]. The second chunk fails.
	reader.EXPECT().FetchMessageSentEvents(mock.Anything, uint64(90), uint64(100)).
		Return([]protocol.MessageSentEvent{scanned}, nil).Once()
	reader.EXPECT().FetchMessageSentEvents(mock.Anything, uint64(101), uint64(111)).
		Return(nil, assert.AnError).Once()

	runPollCycle(ctx, srs, 120, 115)

	require.Equal(t, []string{scanned.MessageID.String()}, publishedIDs(queue),
		"the task at 110 stays pending until a scan covers it")
	srs.mu.RLock()
	defer srs.mu.RUnlock()
	require.Contains(t, srs.pendingTasks, notScanned.MessageID.String())
}

// seedHashedTask adds a full-finality task at block 940 with the given block hash.
func seedHashedTask(t *testing.T, srs *Service, nonce uint64, blockHash protocol.ByteSlice) verifier.VerificationTask {
	t.Helper()
	msg := testutil.CreateTestMessage(t, protocol.SequenceNumber(nonce), protocol.ChainSelector(1337), defaultDestChain, 0, 300_000)
	msgID, err := msg.MessageID()
	require.NoError(t, err)
	task := verifier.VerificationTask{Message: msg, BlockNumber: 940, SourceBlockHash: blockHash, MessageID: msgID.String()}
	srs.mu.Lock()
	srs.pendingTasks[task.MessageID] = task
	srs.pendingSince[task.MessageID] = time.Now()
	srs.mu.Unlock()
	return task
}

func headersAt940(hash protocol.ByteSlice) map[uint64]protocol.BlockHeader {
	return map[uint64]protocol.BlockHeader{940: {Number: 940, Hash: protocol.Bytes32(hash)}}
}

var (
	readHash  = hashOf(0x94, 0x0a)
	otherHash = hashOf(0x94, 0x0b)
	latest1k  = &protocol.BlockHeader{Number: 1000}
	final950  = &protocol.BlockHeader{Number: 950}
)

func TestSRS_BlockHash_MatchingHashPublishes(t *testing.T) {
	reader := mocks.NewMockSourceReader(t)
	srs, queue := newRescanTestSRS(t, reader, 5000)
	task := seedHashedTask(t, srs, 1, readHash)
	reader.EXPECT().GetBlocksHeaders(mock.Anything, mock.Anything).Return(headersAt940(readHash), nil).Maybe()

	srs.sendReadyMessages(context.Background(), latest1k, nil, final950)

	require.Equal(t, []string{task.MessageID}, publishedIDs(queue))
}

func TestSRS_BlockHash_DifferentHashScansBlockAgain(t *testing.T) {
	ctx := context.Background()
	reader := mocks.NewMockSourceReader(t)
	var checkpointWrites int
	chainStatusMgr := mocks.NewMockChainStatusManager(t)
	chainStatusMgr.EXPECT().WriteChainStatuses(mock.Anything, mock.Anything).
		RunAndReturn(func(context.Context, []protocol.ChainStatusInfo) error {
			checkpointWrites++
			return nil
		}).Maybe()
	curseDetector := mocks.NewMockCurseCheckerService(t)
	curseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()
	srs, _, queue := newTestSRS(t, protocol.ChainSelector(1337), reader, chainStatusMgr, curseDetector, 10*time.Millisecond, 5000)
	srs.lastProcessedFinalizedBlock.Store(950)
	srs.startBlockInitialized.Store(true)

	task := seedHashedTask(t, srs, 1, readHash)
	reader.EXPECT().GetBlocksHeaders(mock.Anything, mock.Anything).Return(headersAt940(otherHash), nil).Once()

	srs.sendReadyMessages(ctx, latest1k, nil, final950)

	require.Empty(t, queue.Published(), "a task is sent only when its block is canonical")
	require.Zero(t, checkpointWrites, "the checkpoint stays below the task block")
	require.Equal(t, uint64(939), srs.lastProcessedFinalizedBlock.Load(), "the next scan covers the task block")
	srs.mu.RLock()
	require.Contains(t, srs.pendingTasks, task.MessageID)
	require.True(t, srs.reorgTracker.RequiresFinalization(defaultDestChain, task.Message.SequenceNumber))
	srs.mu.RUnlock()

	// The next scan starts below block 940 and finds the message in block 941.
	moved := createTestMessageSentEvents(t, 1, protocol.ChainSelector(1337), defaultDestChain, []uint64{941})
	moved[0].BlockHash = hashOf(0x94, 0x1a)
	reader.EXPECT().FetchMessageSentEvents(mock.Anything, uint64(939), mock.Anything).Return(moved, nil).Once()
	reader.EXPECT().GetBlocksHeaders(mock.Anything, mock.Anything).Return(map[uint64]protocol.BlockHeader{
		941: {Number: 941, Hash: protocol.Bytes32(moved[0].BlockHash)},
	}, nil).Once()

	runPollCycle(ctx, srs, 1000, 950)

	require.Equal(t, []string{task.MessageID}, publishedIDs(queue))
	require.Equal(t, uint64(941), queue.Published()[0].BlockNumber)
	require.Equal(t, moved[0].BlockHash, queue.Published()[0].SourceBlockHash)
	require.Equal(t, 1, checkpointWrites)
}

// The interface permits a partial map with an error, so no hashed task is confirmed.
func TestSRS_BlockHash_HeaderErrorWithPartialResultKeepsTaskPending(t *testing.T) {
	reader := mocks.NewMockSourceReader(t)
	srs, queue := newRescanTestSRS(t, reader, 5000)
	task := seedHashedTask(t, srs, 1, readHash)
	reader.EXPECT().GetBlocksHeaders(mock.Anything, mock.Anything).Return(headersAt940(readHash), assert.AnError).Once()

	srs.sendReadyMessages(context.Background(), latest1k, nil, final950)

	require.Empty(t, queue.Published())
	srs.mu.RLock()
	defer srs.mu.RUnlock()
	require.Contains(t, srs.pendingTasks, task.MessageID)
}

func TestSRS_BlockHash_MissingHeaderKeepsTaskPending(t *testing.T) {
	reader := mocks.NewMockSourceReader(t)
	var checkpointWrites int
	chainStatusMgr := mocks.NewMockChainStatusManager(t)
	chainStatusMgr.EXPECT().WriteChainStatuses(mock.Anything, mock.Anything).
		RunAndReturn(func(context.Context, []protocol.ChainStatusInfo) error {
			checkpointWrites++
			return nil
		}).Maybe()
	curseDetector := mocks.NewMockCurseCheckerService(t)
	curseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()
	srs, _, queue := newTestSRS(t, protocol.ChainSelector(1337), reader, chainStatusMgr, curseDetector, 10*time.Millisecond, 5000)
	srs.lastProcessedFinalizedBlock.Store(950)
	srs.startBlockInitialized.Store(true)

	task := seedHashedTask(t, srs, 1, readHash)
	reader.EXPECT().GetBlocksHeaders(mock.Anything, mock.Anything).Return(map[uint64]protocol.BlockHeader{}, nil).Once()
	reader.EXPECT().GetBlocksHeaders(mock.Anything, mock.Anything).Return(headersAt940(readHash), nil).Maybe()

	srs.sendReadyMessages(context.Background(), latest1k, nil, final950)
	require.Empty(t, queue.Published(), "the task waits until its block header is available")
	require.Zero(t, checkpointWrites, "the checkpoint stays below the pending task")
	srs.mu.RLock()
	require.Contains(t, srs.pendingTasks, task.MessageID)
	srs.mu.RUnlock()

	srs.sendReadyMessages(context.Background(), latest1k, nil, final950)
	require.Equal(t, []string{task.MessageID}, publishedIDs(queue))
	require.Equal(t, 1, checkpointWrites)
}

func TestSRS_BlockHash_HeaderErrorKeepsTaskPending(t *testing.T) {
	reader := mocks.NewMockSourceReader(t)
	srs, queue := newRescanTestSRS(t, reader, 5000)
	task := seedHashedTask(t, srs, 1, readHash)
	reader.EXPECT().GetBlocksHeaders(mock.Anything, mock.Anything).Return(nil, assert.AnError).Once()
	reader.EXPECT().GetBlocksHeaders(mock.Anything, mock.Anything).Return(headersAt940(readHash), nil).Maybe()

	srs.sendReadyMessages(context.Background(), latest1k, nil, final950)
	require.Empty(t, queue.Published(), "the task waits until the header request succeeds")

	srs.sendReadyMessages(context.Background(), latest1k, nil, final950)
	require.Equal(t, []string{task.MessageID}, publishedIDs(queue))
}

// No GetBlocksHeaders expectation: a call fails the test.
func TestSRS_BlockHash_EmptyHashPublishesWithoutHeaderRequest(t *testing.T) {
	reader := mocks.NewMockSourceReader(t)
	srs, queue := newRescanTestSRS(t, reader, 5000)
	task := seedHashedTask(t, srs, 1, nil)

	srs.sendReadyMessages(context.Background(), latest1k, nil, final950)

	require.Equal(t, []string{task.MessageID}, publishedIDs(queue))
}

// No GetBlocksHeaders expectation: a call fails the test.
func TestSRS_BlockHash_NoHeaderRequestWhenNothingIsReady(t *testing.T) {
	reader := mocks.NewMockSourceReader(t)
	srs, queue := newRescanTestSRS(t, reader, 5000)
	seedHashedTask(t, srs, 1, readHash)

	srs.sendReadyMessages(context.Background(), latest1k, nil, &protocol.BlockHeader{Number: 930})

	require.Empty(t, queue.Published())
}

// A rescan that finds M at the same height in a different block uses the new block hash.
func TestSRS_Rescan_SameHeightNewBlockUsesNewHash(t *testing.T) {
	ctx := context.Background()
	reader := mocks.NewMockSourceReader(t)
	srs, queue := newRescanTestSRS(t, reader, 5000)
	srs.lastProcessedFinalizedBlock.Store(85)

	first := createTestMessageSentEvents(t, 1, protocol.ChainSelector(1337), defaultDestChain, []uint64{100})
	first[0].BlockHash = hashOf(0x10, 0x0a)
	second := []protocol.MessageSentEvent{first[0]}
	second[0].BlockHash = hashOf(0x10, 0x0b)
	reader.EXPECT().FetchMessageSentEvents(mock.Anything, mock.Anything, mock.Anything).Return(first, nil).Once()
	reader.EXPECT().FetchMessageSentEvents(mock.Anything, mock.Anything, mock.Anything).Return(second, nil)
	reader.EXPECT().GetBlocksHeaders(mock.Anything, mock.Anything).Return(map[uint64]protocol.BlockHeader{
		100: {Number: 100, Hash: protocol.Bytes32(second[0].BlockHash)},
	}, nil).Maybe()

	runPollCycle(ctx, srs, 100, 90)
	runPollCycle(ctx, srs, 105, 100)

	require.Equal(t, []string{first[0].MessageID.String()}, publishedIDs(queue))
	require.Equal(t, second[0].BlockHash, queue.Published()[0].SourceBlockHash)
}
