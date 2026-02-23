package verifier

import (
	"context"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/jobqueue"
	vservices "github.com/smartcontractkit/chainlink-ccv/verifier/services"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/utils/tests"
)

// fakeTaskQueue is an in-memory implementation of jobqueue.JobQueue[VerificationTask]
// used to capture tasks published by SourceReaderServiceDB without needing a real DB.
type fakeTaskQueue struct {
	mu        sync.Mutex
	published []VerificationTask
}

func (q *fakeTaskQueue) Publish(_ context.Context, tasks ...VerificationTask) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.published = append(q.published, tasks...)
	return nil
}

func (q *fakeTaskQueue) PublishWithDelay(_ context.Context, _ time.Duration, tasks ...VerificationTask) error {
	return q.Publish(context.Background(), tasks...)
}

func (q *fakeTaskQueue) Consume(_ context.Context, _ int) ([]jobqueue.Job[VerificationTask], error) {
	return nil, nil
}

func (q *fakeTaskQueue) Complete(_ context.Context, _ ...string) error { return nil }
func (q *fakeTaskQueue) Retry(_ context.Context, _ time.Duration, _ map[string]error, _ ...string) error {
	return nil
}
func (q *fakeTaskQueue) Fail(_ context.Context, _ map[string]error, _ ...string) error { return nil }
func (q *fakeTaskQueue) Cleanup(_ context.Context, _ time.Duration) (int, error)       { return 0, nil }
func (q *fakeTaskQueue) Name() string                                                  { return "fake-task-queue" }

func (q *fakeTaskQueue) Published() []VerificationTask {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := make([]VerificationTask, len(q.published))
	copy(out, q.published)
	return out
}

func newTestSRSDB(
	t *testing.T,
	chainSelector protocol.ChainSelector,
	reader *mocks.MockSourceReader,
	chainStatusMgr protocol.ChainStatusManager,
	curseDetector *mocks.MockCurseCheckerService,
	pollInterval time.Duration,
	maxBlockRange uint64,
) (*SourceReaderServiceDB, *mocks.MockFinalityViolationChecker, *fakeTaskQueue) {
	t.Helper()

	lggr := logger.Test(t)
	queue := &fakeTaskQueue{}

	srs, err := NewSourceReaderServiceDB(
		t.Context(),
		reader,
		chainSelector,
		chainStatusMgr,
		lggr,
		SourceConfig{PollInterval: pollInterval, MaxBlockRange: maxBlockRange},
		curseDetector,
		&noopFilter{},
		&noopMetricLabeler{},
		NewPendingWritingTracker(lggr),
		queue,
	)
	require.NoError(t, err)

	mockFC := mocks.NewMockFinalityViolationChecker(t)
	srs.finalityChecker = mockFC
	mockFC.EXPECT().UpdateFinalized(mock.Anything, mock.Anything).Return(nil).Maybe()
	mockFC.EXPECT().IsFinalityViolated().Return(false).Maybe()

	return srs, mockFC, queue
}

func TestSRSDB_FetchesAndQueuesMessages(t *testing.T) {
	ctx := context.Background()
	chain := protocol.ChainSelector(1337)

	reader := mocks.NewMockSourceReader(t)

	latest := &protocol.BlockHeader{Number: 110}
	finalized := &protocol.BlockHeader{Number: 100}

	reader.EXPECT().LatestAndFinalizedBlock(mock.Anything).Return(latest, finalized, nil).Maybe()

	blockNums := []uint64{101, 102, 105}
	events := createTestMessageSentEvents(t, 1, chain, defaultDestChain, blockNums)

	reader.EXPECT().
		FetchMessageSentEvents(mock.Anything, big.NewInt(95), mock.Anything).
		Return(events, nil)

	chainStatusMgr := mocks.NewMockChainStatusManager(t)
	chainStatusMgr.EXPECT().ReadChainStatuses(mock.Anything, mock.Anything).
		Return(map[protocol.ChainSelector]*protocol.ChainStatusInfo{}, nil).Maybe()
	chainStatusMgr.EXPECT().WriteChainStatuses(mock.Anything, mock.Anything).Return(nil).Maybe()

	curseDetector := mocks.NewMockCurseCheckerService(t)
	curseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).Return(false).Maybe()
	curseDetector.EXPECT().Start(mock.Anything).Return(nil).Maybe()
	curseDetector.EXPECT().Close().Return(nil).Maybe()

	srs, _, _ := newTestSRSDB(t, chain, reader, chainStatusMgr, curseDetector, 10*time.Millisecond, 5000)
	srs.lastProcessedFinalizedBlock.Store(big.NewInt(95))

	srs.processEventCycle(ctx, latest, finalized)

	srs.mu.RLock()
	defer srs.mu.RUnlock()

	require.Len(t, srs.pendingTasks, len(events))
	for _, ev := range events {
		id := ev.MessageID.String()
		task, ok := srs.pendingTasks[id]
		require.True(t, ok, "task with MessageID %s should be present", id)
		require.Equal(t, ev.BlockNumber, task.BlockNumber)
	}
}

func TestSRSDB_DeduplicatesByMessageID(t *testing.T) {
	ctx := context.Background()
	chain := protocol.ChainSelector(1337)

	reader := mocks.NewMockSourceReader(t)

	latest := &protocol.BlockHeader{Number: 105}
	finalized := &protocol.BlockHeader{Number: 100}
	reader.EXPECT().LatestAndFinalizedBlock(mock.Anything).Return(latest, finalized, nil).Maybe()

	events := createTestMessageSentEvents(t, 1, chain, defaultDestChain, []uint64{101})
	// Add duplicate
	events = append(events, events[0])

	reader.EXPECT().
		FetchMessageSentEvents(mock.Anything, mock.Anything, mock.Anything).
		Return(events, nil)

	chainStatusMgr := mocks.NewMockChainStatusManager(t)
	chainStatusMgr.EXPECT().ReadChainStatuses(mock.Anything, mock.Anything).
		Return(map[protocol.ChainSelector]*protocol.ChainStatusInfo{}, nil).Maybe()

	curseDetector := mocks.NewMockCurseCheckerService(t)
	curseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).Return(false).Maybe()
	curseDetector.EXPECT().Start(mock.Anything).Return(nil).Maybe()
	curseDetector.EXPECT().Close().Return(nil).Maybe()

	srs, _, _ := newTestSRSDB(t, chain, reader, chainStatusMgr, curseDetector, 10*time.Millisecond, 5000)
	srs.lastProcessedFinalizedBlock.Store(big.NewInt(95))

	srs.processEventCycle(ctx, latest, finalized)

	srs.mu.RLock()
	defer srs.mu.RUnlock()
	require.Len(t, srs.pendingTasks, 1, "duplicate events by MessageID should be deduped")
}

func TestSRSDB_Reorg_DropsMissingPendingAndSent(t *testing.T) {
	chain := protocol.ChainSelector(1337)
	reader := mocks.NewMockSourceReader(t)
	chainStatusMgr := mocks.NewMockChainStatusManager(t)

	curseDetector := mocks.NewMockCurseCheckerService(t)
	curseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).Return(false).Maybe()
	curseDetector.EXPECT().Start(mock.Anything).Return(nil).Maybe()
	curseDetector.EXPECT().Close().Return(nil).Maybe()

	srs, _, _ := newTestSRSDB(t, chain, reader, chainStatusMgr, curseDetector, 10*time.Millisecond, 5000)

	msgs := createTestMessageSentEvents(t, 1, chain, defaultDestChain, []uint64{100, 101, 102})
	taskA := VerificationTask{Message: msgs[0].Message, BlockNumber: msgs[0].BlockNumber, MessageID: msgs[0].MessageID.String()}
	taskB := VerificationTask{Message: msgs[1].Message, BlockNumber: msgs[1].BlockNumber, MessageID: msgs[1].MessageID.String()}
	taskC := VerificationTask{Message: msgs[2].Message, BlockNumber: msgs[2].BlockNumber, MessageID: msgs[2].MessageID.String()}

	srs.mu.Lock()
	srs.pendingTasks = map[string]VerificationTask{taskA.MessageID: taskA, taskB.MessageID: taskB}
	srs.sentTasks = map[string]VerificationTask{taskC.MessageID: taskC}
	srs.mu.Unlock()

	// New canonical events keep A, add D; B and C are gone
	msgsD := createTestMessageSentEvents(t, 10, chain, defaultDestChain, []uint64{103})
	taskD := VerificationTask{Message: msgsD[0].Message, BlockNumber: msgsD[0].BlockNumber, MessageID: msgsD[0].MessageID.String()}

	srs.addToPendingQueueHandleReorg([]VerificationTask{taskA, taskD}, big.NewInt(100))

	srs.mu.RLock()
	defer srs.mu.RUnlock()

	require.Len(t, srs.pendingTasks, 2)
	_, hasA := srs.pendingTasks[taskA.MessageID]
	_, hasD := srs.pendingTasks[taskD.MessageID]
	require.True(t, hasA)
	require.True(t, hasD)
	require.Len(t, srs.sentTasks, 0)
}

func TestSRSDB_Curse_DropsAtSendTime(t *testing.T) {
	ctx := context.Background()
	chain := protocol.ChainSelector(1337)
	reader := mocks.NewMockSourceReader(t)
	chainStatusMgr := mocks.NewMockChainStatusManager(t)

	curseDetector := mocks.NewMockCurseCheckerService(t)
	curseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).Return(true).Maybe()
	curseDetector.EXPECT().Start(mock.Anything).Return(nil).Maybe()
	curseDetector.EXPECT().Close().Return(nil).Maybe()

	srs, mockFC, queue := newTestSRSDB(t, chain, reader, chainStatusMgr, curseDetector, 10*time.Millisecond, 5000)
	mockFC.EXPECT().UpdateFinalized(mock.Anything, mock.Anything).Return(nil).Maybe()
	mockFC.EXPECT().IsFinalityViolated().Return(false).Maybe()

	events := createTestMessageSentEvents(t, 1, chain, defaultDestChain, []uint64{100, 101})
	tasks := []VerificationTask{
		{Message: events[0].Message, BlockNumber: events[0].BlockNumber, MessageID: events[0].MessageID.String()},
		{Message: events[1].Message, BlockNumber: events[1].BlockNumber, MessageID: events[1].MessageID.String()},
	}
	srs.addToPendingQueueHandleReorg(tasks, big.NewInt(100))

	latest := &protocol.BlockHeader{Number: 150}
	finalized := &protocol.BlockHeader{Number: 120}
	srs.sendReadyMessages(ctx, latest, finalized)

	srs.mu.RLock()
	defer srs.mu.RUnlock()
	require.Len(t, srs.pendingTasks, 0, "cursed tasks should be dropped at send time")
	require.Len(t, queue.Published(), 0, "no tasks should be published to queue for cursed lanes")
}

func TestSRSDB_Readiness_DefaultFinality_PublishesToQueue(t *testing.T) {
	ctx := context.Background()
	chain := protocol.ChainSelector(1337)
	reader := mocks.NewMockSourceReader(t)

	latest := &protocol.BlockHeader{Number: 1000}
	finalized := &protocol.BlockHeader{Number: 950}

	chainStatusMgr := mocks.NewMockChainStatusManager(t)
	chainStatusMgr.EXPECT().ReadChainStatuses(mock.Anything, mock.Anything).
		Return(map[protocol.ChainSelector]*protocol.ChainStatusInfo{}, nil).Maybe()
	chainStatusMgr.EXPECT().WriteChainStatuses(mock.Anything, mock.Anything).Return(nil).Maybe()

	curseDetector := mocks.NewMockCurseCheckerService(t)
	curseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).Return(false).Maybe()
	curseDetector.EXPECT().Start(mock.Anything).Return(nil).Maybe()
	curseDetector.EXPECT().Close().Return(nil).Maybe()

	srs, mockFC, queue := newTestSRSDB(t, chain, reader, chainStatusMgr, curseDetector, 10*time.Millisecond, 5000)
	mockFC.EXPECT().UpdateFinalized(mock.Anything, finalized.Number).Return(nil).Maybe()
	mockFC.EXPECT().IsFinalityViolated().Return(false).Maybe()

	// Task with Finality=0 at block <= finalized — should be ready immediately.
	msg := CreateTestMessage(t, 1, chain, defaultDestChain, 0, 300_000)
	msgID, _ := msg.MessageID()
	task := VerificationTask{Message: msg, BlockNumber: 940, MessageID: msgID.String()}

	srs.mu.Lock()
	srs.pendingTasks[msgID.String()] = task
	srs.mu.Unlock()

	srs.sendReadyMessages(ctx, latest, finalized)

	require.Eventually(t, func() bool {
		return len(queue.Published()) == 1
	}, tests.WaitTimeout(t), 10*time.Millisecond)

	published := queue.Published()
	require.Equal(t, task.MessageID, published[0].MessageID)

	srs.mu.RLock()
	defer srs.mu.RUnlock()
	require.Len(t, srs.pendingTasks, 0)
	require.Len(t, srs.sentTasks, 1)
}

func TestSRSDB_Readiness_CustomFinality_PublishesToQueue(t *testing.T) {
	ctx := context.Background()
	chain := protocol.ChainSelector(1337)
	reader := mocks.NewMockSourceReader(t)

	latest := &protocol.BlockHeader{Number: 1000}
	finalized := &protocol.BlockHeader{Number: 950}

	chainStatusMgr := mocks.NewMockChainStatusManager(t)
	chainStatusMgr.EXPECT().ReadChainStatuses(mock.Anything, mock.Anything).
		Return(map[protocol.ChainSelector]*protocol.ChainStatusInfo{}, nil).Maybe()

	curseDetector := mocks.NewMockCurseCheckerService(t)
	curseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).Return(false).Maybe()
	curseDetector.EXPECT().Start(mock.Anything).Return(nil).Maybe()
	curseDetector.EXPECT().Close().Return(nil).Maybe()

	srs, _, queue := newTestSRSDB(t, chain, reader, chainStatusMgr, curseDetector, 10*time.Millisecond, 5000)

	const f uint16 = 10
	msg := CreateTestMessage(t, 1, chain, defaultDestChain, f, 300_000)
	msgID, _ := msg.MessageID()
	// block = latest - f  => custom finality met
	task := VerificationTask{Message: msg, BlockNumber: latest.Number - uint64(f), MessageID: msgID.String()}

	srs.mu.Lock()
	srs.pendingTasks[msgID.String()] = task
	srs.mu.Unlock()

	srs.sendReadyMessages(ctx, latest, finalized)

	require.Eventually(t, func() bool {
		return len(queue.Published()) == 1
	}, tests.WaitTimeout(t), 10*time.Millisecond)

	require.Equal(t, task.MessageID, queue.Published()[0].MessageID)
}

func TestSRSDB_Readiness_NotReadyTask_NotPublished(t *testing.T) {
	ctx := context.Background()
	chain := protocol.ChainSelector(1337)
	reader := mocks.NewMockSourceReader(t)

	latest := &protocol.BlockHeader{Number: 1000}
	finalized := &protocol.BlockHeader{Number: 950}

	chainStatusMgr := mocks.NewMockChainStatusManager(t)
	curseDetector := mocks.NewMockCurseCheckerService(t)
	curseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).Return(false).Maybe()
	curseDetector.EXPECT().Start(mock.Anything).Return(nil).Maybe()
	curseDetector.EXPECT().Close().Return(nil).Maybe()

	srs, _, queue := newTestSRSDB(t, chain, reader, chainStatusMgr, curseDetector, 10*time.Millisecond, 5000)

	// Block 980 > finalized 950, Finality=0 — not ready yet.
	msg := CreateTestMessage(t, 1, chain, defaultDestChain, 0, 300_000)
	msgID, _ := msg.MessageID()
	task := VerificationTask{Message: msg, BlockNumber: 980, MessageID: msgID.String()}

	srs.mu.Lock()
	srs.pendingTasks[msgID.String()] = task
	srs.mu.Unlock()

	srs.sendReadyMessages(ctx, latest, finalized)

	srs.mu.RLock()
	defer srs.mu.RUnlock()
	require.Len(t, srs.pendingTasks, 1, "not-ready task should remain in pending")
	require.Len(t, queue.Published(), 0, "nothing should be published for not-ready task")
}

func TestSRSDB_isMessageReadyForVerification(t *testing.T) {
	chain := protocol.ChainSelector(1337)
	reader := mocks.NewMockSourceReader(t)
	chainStatusMgr := mocks.NewMockChainStatusManager(t)
	curseDetector := mocks.NewMockCurseCheckerService(t)

	srs, _, _ := newTestSRSDB(t, chain, reader, chainStatusMgr, curseDetector, 10*time.Millisecond, 5000)

	testCases := []struct {
		name           string
		blockDepth     uint16
		msgBlock       uint64
		latestBlock    uint64
		finalizedBlock uint64
		expectedReady  bool
	}{
		{
			name:     "DefaultFinality_Ready_BelowFinalized",
			msgBlock: 100, latestBlock: 200, finalizedBlock: 150,
			expectedReady: true,
		},
		{
			name:     "DefaultFinality_NotReady_AboveFinalized",
			msgBlock: 160, latestBlock: 200, finalizedBlock: 150,
			expectedReady: false,
		},
		{
			name:       "CustomFinality_Ready_MetCustomRequirement",
			blockDepth: 10,
			msgBlock:   180, latestBlock: 200, finalizedBlock: 150,
			expectedReady: true,
		},
		{
			name:       "CustomFinality_Ready_CappedAtFinality",
			blockDepth: 100,
			msgBlock:   140, latestBlock: 200, finalizedBlock: 150,
			expectedReady: true,
		},
		{
			name:       "CustomFinality_NotReady_NeitherConditionMet",
			blockDepth: 20,
			msgBlock:   190, latestBlock: 200, finalizedBlock: 180,
			expectedReady: false,
		},
		{
			name:       "DOSAttack_MAXUint16_Ready_CappedAtFinality",
			blockDepth: 65535,
			msgBlock:   100, latestBlock: 200, finalizedBlock: 150,
			expectedReady: true,
		},
		{
			name:       "EdgeCase_ExactlyAtFinalized",
			blockDepth: 50,
			msgBlock:   150, latestBlock: 200, finalizedBlock: 150,
			expectedReady: true,
		},
		{
			name:       "EdgeCase_ExactlyAtCustomRequirement",
			blockDepth: 10,
			msgBlock:   190, latestBlock: 200, finalizedBlock: 180,
			expectedReady: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			msg := CreateTestMessage(t, 1, chain, defaultDestChain, tc.blockDepth, 300_000)
			msgID, _ := msg.MessageID()
			task := VerificationTask{Message: msg, BlockNumber: tc.msgBlock, MessageID: msgID.String()}

			ready := srs.isMessageReadyForVerification(
				task,
				big.NewInt(int64(tc.latestBlock)),
				big.NewInt(int64(tc.finalizedBlock)),
			)
			require.Equal(t, tc.expectedReady, ready)
		})
	}
}

func TestSRSDB_FinalityViolation_DisablesChainAndFlushesTasks(t *testing.T) {
	ctx := context.Background()
	chain := protocol.ChainSelector(1337)
	reader := mocks.NewMockSourceReader(t)

	chainStatusMgr := mocks.NewMockChainStatusManager(t)
	chainStatusMgr.EXPECT().ReadChainStatuses(mock.Anything, mock.Anything).
		Return(map[protocol.ChainSelector]*protocol.ChainStatusInfo{}, nil).Maybe()
	chainStatusMgr.EXPECT().
		WriteChainStatuses(mock.Anything, mock.Anything).
		RunAndReturn(func(_ context.Context, infos []protocol.ChainStatusInfo) error {
			require.Len(t, infos, 1)
			require.True(t, infos[0].Disabled)
			return nil
		}).Maybe()

	curseDetector := mocks.NewMockCurseCheckerService(t)
	curseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).Return(false).Maybe()
	curseDetector.EXPECT().Start(mock.Anything).Return(nil).Maybe()
	curseDetector.EXPECT().Close().Return(nil).Maybe()

	srs, mockFC, _ := newTestSRSDB(t, chain, reader, chainStatusMgr, curseDetector, 10*time.Millisecond, 5000)
	mockFC.EXPECT().IsFinalityViolated().Unset()
	mockFC.EXPECT().IsFinalityViolated().Return(true).Maybe()

	msgs := createTestMessageSentEvents(t, 1, chain, defaultDestChain, []uint64{940, 960})
	task1 := VerificationTask{Message: msgs[0].Message, BlockNumber: msgs[0].BlockNumber, MessageID: msgs[0].MessageID.String()}
	task2 := VerificationTask{Message: msgs[1].Message, BlockNumber: msgs[1].BlockNumber, MessageID: msgs[1].MessageID.String()}

	srs.mu.Lock()
	srs.pendingTasks[task1.MessageID] = task1
	srs.sentTasks[task2.MessageID] = task2
	srs.mu.Unlock()

	latest := &protocol.BlockHeader{Number: 1000}
	finalized := &protocol.BlockHeader{Number: 950}
	srs.sendReadyMessages(ctx, latest, finalized)

	require.True(t, srs.disabled.Load(), "chain should be disabled after finality violation")

	srs.mu.RLock()
	defer srs.mu.RUnlock()
	require.Len(t, srs.pendingTasks, 0, "pending tasks should be flushed on finality violation")
	require.Len(t, srs.sentTasks, 0, "sent tasks should be flushed on finality violation")
}

func TestSRSDB_Reorg_TracksSequenceNumbers(t *testing.T) {
	chain := protocol.ChainSelector(1337)
	reader := mocks.NewMockSourceReader(t)
	chainStatusMgr := mocks.NewMockChainStatusManager(t)

	curseDetector := mocks.NewMockCurseCheckerService(t)
	curseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).Return(false).Maybe()
	curseDetector.EXPECT().Start(mock.Anything).Return(nil).Maybe()
	curseDetector.EXPECT().Close().Return(nil).Maybe()

	srs, _, _ := newTestSRSDB(t, chain, reader, chainStatusMgr, curseDetector, 10*time.Millisecond, 5000)

	msgs := createTestMessageSentEvents(t, 1, chain, defaultDestChain, []uint64{100, 101})
	taskA := VerificationTask{Message: msgs[0].Message, BlockNumber: msgs[0].BlockNumber, MessageID: msgs[0].MessageID.String()}
	taskB := VerificationTask{Message: msgs[1].Message, BlockNumber: msgs[1].BlockNumber, MessageID: msgs[1].MessageID.String()}

	srs.mu.Lock()
	srs.pendingTasks = map[string]VerificationTask{taskA.MessageID: taskA, taskB.MessageID: taskB}
	srs.mu.Unlock()

	// Reorg: only A survives; B is dropped
	srs.addToPendingQueueHandleReorg([]VerificationTask{taskA}, big.NewInt(100))

	require.True(t, srs.reorgTracker.RequiresFinalization(defaultDestChain, taskB.Message.SequenceNumber),
		"reorged message B should require finalization")
	require.False(t, srs.reorgTracker.RequiresFinalization(defaultDestChain, taskA.Message.SequenceNumber),
		"surviving message A should not require finalization")
}

func TestSRSDB_DisableFinalityChecker(t *testing.T) {
	chain := protocol.ChainSelector(1337)
	reader := mocks.NewMockSourceReader(t)
	chainStatusMgr := mocks.NewMockChainStatusManager(t)
	curseDetector := mocks.NewMockCurseCheckerService(t)
	lggr := logger.Test(t)

	srs, err := NewSourceReaderServiceDB(
		context.Background(),
		reader,
		chain,
		chainStatusMgr,
		lggr,
		SourceConfig{
			PollInterval:           10 * time.Millisecond,
			MaxBlockRange:          5000,
			DisableFinalityChecker: true,
		},
		curseDetector,
		&noopFilter{},
		&noopMetricLabeler{},
		NewPendingWritingTracker(lggr),
		&fakeTaskQueue{},
	)
	require.NoError(t, err)

	_, ok := srs.finalityChecker.(*vservices.NoOpFinalityViolationChecker)
	require.True(t, ok, "finalityChecker should be NoOpFinalityViolationChecker when disabled")
}
