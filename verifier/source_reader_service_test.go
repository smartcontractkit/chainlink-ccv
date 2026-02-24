package verifier

import (
	"context"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/jobqueue"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/utils/tests"
)

// fakeTaskQueue is an in-memory implementation of jobqueue.JobQueue[VerificationTask]
// used to capture tasks published by SourceReaderService without needing a real DB.
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

func newTestSRS(
	t *testing.T,
	chainSelector protocol.ChainSelector,
	reader *mocks.MockSourceReader,
	chainStatusMgr protocol.ChainStatusManager,
	curseDetector *mocks.MockCurseCheckerService,
	pollInterval time.Duration,
	maxBlockRange uint64,
) (*SourceReaderService, *mocks.MockFinalityViolationChecker, *fakeTaskQueue) {
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

func TestSRS_FetchesAndQueuesMessages(t *testing.T) {
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

	srs, _, _ := newTestSRS(t, chain, reader, chainStatusMgr, curseDetector, 10*time.Millisecond, 5000)
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

func TestSRS_DeduplicatesByMessageID(t *testing.T) {
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

	srs, _, _ := newTestSRS(t, chain, reader, chainStatusMgr, curseDetector, 10*time.Millisecond, 5000)
	srs.lastProcessedFinalizedBlock.Store(big.NewInt(95))

	srs.processEventCycle(ctx, latest, finalized)

	srs.mu.RLock()
	defer srs.mu.RUnlock()
	require.Len(t, srs.pendingTasks, 1, "duplicate events by MessageID should be deduped")
}

func TestSRS_Reorg_DropsMissingPendingAndSent(t *testing.T) {
	chain := protocol.ChainSelector(1337)
	reader := mocks.NewMockSourceReader(t)
	chainStatusMgr := mocks.NewMockChainStatusManager(t)

	curseDetector := mocks.NewMockCurseCheckerService(t)
	curseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).Return(false).Maybe()
	curseDetector.EXPECT().Start(mock.Anything).Return(nil).Maybe()
	curseDetector.EXPECT().Close().Return(nil).Maybe()

	srs, _, _ := newTestSRS(t, chain, reader, chainStatusMgr, curseDetector, 10*time.Millisecond, 5000)

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

func TestSRS_Curse_DropsAtSendTime(t *testing.T) {
	ctx := context.Background()
	chain := protocol.ChainSelector(1337)
	reader := mocks.NewMockSourceReader(t)
	chainStatusMgr := mocks.NewMockChainStatusManager(t)

	curseDetector := mocks.NewMockCurseCheckerService(t)
	curseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).Return(true).Maybe()
	curseDetector.EXPECT().Start(mock.Anything).Return(nil).Maybe()
	curseDetector.EXPECT().Close().Return(nil).Maybe()

	srs, mockFC, queue := newTestSRS(t, chain, reader, chainStatusMgr, curseDetector, 10*time.Millisecond, 5000)
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

func TestSRS_Readiness_DefaultFinality_PublishesToQueue(t *testing.T) {
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

	srs, mockFC, queue := newTestSRS(t, chain, reader, chainStatusMgr, curseDetector, 10*time.Millisecond, 5000)
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

func TestSRS_Readiness_CustomFinality_PublishesToQueue(t *testing.T) {
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

	srs, _, queue := newTestSRS(t, chain, reader, chainStatusMgr, curseDetector, 10*time.Millisecond, 5000)

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

func TestSRS_Readiness_NotReadyTask_NotPublished(t *testing.T) {
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

	srs, _, queue := newTestSRS(t, chain, reader, chainStatusMgr, curseDetector, 10*time.Millisecond, 5000)

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

func TestSRS_isMessageReadyForVerification(t *testing.T) {
	chain := protocol.ChainSelector(1337)
	reader := mocks.NewMockSourceReader(t)
	chainStatusMgr := mocks.NewMockChainStatusManager(t)
	curseDetector := mocks.NewMockCurseCheckerService(t)

	srs, _, _ := newTestSRS(t, chain, reader, chainStatusMgr, curseDetector, 10*time.Millisecond, 5000)

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

func TestSRS_FinalityViolation_DisablesChainAndFlushesTasks(t *testing.T) {
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

	srs, mockFC, _ := newTestSRS(t, chain, reader, chainStatusMgr, curseDetector, 10*time.Millisecond, 5000)
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

func TestSRS_Reorg_TracksSequenceNumbers(t *testing.T) {
	chain := protocol.ChainSelector(1337)
	reader := mocks.NewMockSourceReader(t)
	chainStatusMgr := mocks.NewMockChainStatusManager(t)

	curseDetector := mocks.NewMockCurseCheckerService(t)
	curseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).Return(false).Maybe()
	curseDetector.EXPECT().Start(mock.Anything).Return(nil).Maybe()
	curseDetector.EXPECT().Close().Return(nil).Maybe()

	srs, _, _ := newTestSRS(t, chain, reader, chainStatusMgr, curseDetector, 10*time.Millisecond, 5000)

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

func TestSRS_DisableFinalityChecker(t *testing.T) {
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

	_, ok := srs.finalityChecker.(*NoOpFinalityViolationChecker)
	require.True(t, ok, "finalityChecker should be NoOpFinalityViolationChecker when disabled")
}

// ----------------------
// Advanced Reorg Tracking Tests
// ----------------------

func TestSRS_Reorg_TracksSentTasksSequenceNumbers(t *testing.T) {
	chain := protocol.ChainSelector(1337)
	reader := mocks.NewMockSourceReader(t)
	chainStatusMgr := mocks.NewMockChainStatusManager(t)

	curseDetector := mocks.NewMockCurseCheckerService(t)
	curseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).Return(false).Maybe()
	curseDetector.EXPECT().Start(mock.Anything).Return(nil).Maybe()
	curseDetector.EXPECT().Close().Return(nil).Maybe()

	srs, _, _ := newTestSRS(t, chain, reader, chainStatusMgr, curseDetector, 10*time.Millisecond, 5000)

	// Task A was already sent (in sentTasks)
	msgs := createTestMessageSentEvents(t, 1, chain, defaultDestChain, []uint64{100})
	taskA := VerificationTask{Message: msgs[0].Message, BlockNumber: msgs[0].BlockNumber, MessageID: msgs[0].MessageID.String()}

	srs.mu.Lock()
	srs.sentTasks = map[string]VerificationTask{taskA.MessageID: taskA}
	srs.mu.Unlock()

	// New query results: A is gone (reorged after being sent)
	newTasks := []VerificationTask{}

	srs.addToPendingQueueHandleReorg(newTasks, big.NewInt(100))

	srs.mu.RLock()
	defer srs.mu.RUnlock()

	// A's seqNum should be tracked as reorged even though it was in sentTasks
	require.True(t, srs.reorgTracker.RequiresFinalization(defaultDestChain, taskA.Message.SequenceNumber),
		"reorged sent task's seqNum should be tracked")
}

func TestSRS_ReorgedMessage_CustomFinality_WaitsForFinalization(t *testing.T) {
	chain := protocol.ChainSelector(1337)
	reader := mocks.NewMockSourceReader(t)
	chainStatusMgr := mocks.NewMockChainStatusManager(t)

	curseDetector := mocks.NewMockCurseCheckerService(t)
	curseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).Return(false).Maybe()
	curseDetector.EXPECT().Start(mock.Anything).Return(nil).Maybe()
	curseDetector.EXPECT().Close().Return(nil).Maybe()

	srs, _, _ := newTestSRS(t, chain, reader, chainStatusMgr, curseDetector, 10*time.Millisecond, 5000)

	// Create message with custom finality of 5 blocks
	const customFinality uint16 = 5
	msg := CreateTestMessage(t, 10, chain, defaultDestChain, customFinality, 300_000)
	msgID, _ := msg.MessageID()
	task := VerificationTask{
		Message:     msg,
		BlockNumber: 190,
		MessageID:   msgID.String(),
	}

	// Mark this seqNum as reorged
	srs.reorgTracker.Track(defaultDestChain, msg.SequenceNumber)

	latestBlock := big.NewInt(200)    // msgBlock(190) + finality(5) = 195 <= 200, custom finality would be met
	finalizedBlock := big.NewInt(180) // msgBlock(190) > finalized(180)

	// Even though custom finality (195 <= 200) would be met, reorg tracking should require finalization
	ready := srs.isMessageReadyForVerification(task, latestBlock, finalizedBlock)

	require.False(t, ready, "reorged message should wait for finalization even if custom finality is met")

	// Now set finalized block past message block
	finalizedBlock = big.NewInt(195)
	ready = srs.isMessageReadyForVerification(task, latestBlock, finalizedBlock)

	require.True(t, ready, "reorged message should be ready once finalized")
}

func TestSRS_NonReorgedMessage_UsesCustomFinality(t *testing.T) {
	chain := protocol.ChainSelector(1337)
	reader := mocks.NewMockSourceReader(t)
	chainStatusMgr := mocks.NewMockChainStatusManager(t)

	curseDetector := mocks.NewMockCurseCheckerService(t)
	curseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).Return(false).Maybe()
	curseDetector.EXPECT().Start(mock.Anything).Return(nil).Maybe()
	curseDetector.EXPECT().Close().Return(nil).Maybe()

	srs, _, _ := newTestSRS(t, chain, reader, chainStatusMgr, curseDetector, 10*time.Millisecond, 5000)

	// Create message with custom finality of 5 blocks
	const customFinality uint16 = 5
	msg := CreateTestMessage(t, 10, chain, defaultDestChain, customFinality, 300_000)
	msgID, _ := msg.MessageID()
	task := VerificationTask{
		Message:     msg,
		BlockNumber: 190,
		MessageID:   msgID.String(),
	}

	// Don't mark this seqNum as reorged

	latestBlock := big.NewInt(200)    // msgBlock(190) + finality(5) = 195 <= 200
	finalizedBlock := big.NewInt(180) // msgBlock(190) > finalized(180)

	// Custom finality should be used (no reorg tracking)
	ready := srs.isMessageReadyForVerification(task, latestBlock, finalizedBlock)

	require.True(t, ready, "non-reorged message should use custom finality")
}

func TestSRS_ReorgedMessage_DifferentDest_UsesCustomFinality(t *testing.T) {
	chain := protocol.ChainSelector(1337)
	dest1 := protocol.ChainSelector(100)
	dest2 := protocol.ChainSelector(200)
	reader := mocks.NewMockSourceReader(t)
	chainStatusMgr := mocks.NewMockChainStatusManager(t)

	curseDetector := mocks.NewMockCurseCheckerService(t)
	curseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).Return(false).Maybe()
	curseDetector.EXPECT().Start(mock.Anything).Return(nil).Maybe()
	curseDetector.EXPECT().Close().Return(nil).Maybe()

	srs, _, _ := newTestSRS(t, chain, reader, chainStatusMgr, curseDetector, 10*time.Millisecond, 5000)

	// Mark seqNum 10 for dest1 as reorged
	srs.reorgTracker.Track(dest1, 10)

	// Create message with same seqNum 10 but for dest2 (different lane)
	const customFinality uint16 = 5
	msg := CreateTestMessage(t, 10, chain, dest2, customFinality, 300_000)
	msgID, _ := msg.MessageID()
	task := VerificationTask{
		Message:     msg,
		BlockNumber: 190,
		MessageID:   msgID.String(),
	}

	latestBlock := big.NewInt(200)
	finalizedBlock := big.NewInt(180)

	// Message to dest2 should use custom finality (dest1's reorg doesn't affect it)
	ready := srs.isMessageReadyForVerification(task, latestBlock, finalizedBlock)

	require.True(t, ready, "message to different dest should not be affected by other dest's reorg tracking")
}

func TestSRS_ReorgTracker_RemovedAfterFinalization(t *testing.T) {
	ctx := context.Background()
	chain := protocol.ChainSelector(1337)
	reader := mocks.NewMockSourceReader(t)
	chainStatusMgr := mocks.NewMockChainStatusManager(t)

	curseDetector := mocks.NewMockCurseCheckerService(t)
	curseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).Return(false).Maybe()
	curseDetector.EXPECT().Start(mock.Anything).Return(nil).Maybe()
	curseDetector.EXPECT().Close().Return(nil).Maybe()

	srs, mockFC, queue := newTestSRS(t, chain, reader, chainStatusMgr, curseDetector, 10*time.Millisecond, 5000)
	mockFC.EXPECT().UpdateFinalized(mock.Anything, mock.Anything).Return(nil).Maybe()
	mockFC.EXPECT().IsFinalityViolated().Return(false).Maybe()

	// Create a message and mark its seqNum as reorged
	msg := CreateTestMessage(t, 10, chain, defaultDestChain, 0, 300_000)
	msgID, _ := msg.MessageID()
	task := VerificationTask{
		Message:     msg,
		BlockNumber: 100,
		MessageID:   msgID.String(),
	}

	srs.reorgTracker.Track(defaultDestChain, msg.SequenceNumber)
	require.True(t, srs.reorgTracker.RequiresFinalization(defaultDestChain, msg.SequenceNumber))

	// Add task to pending
	srs.mu.Lock()
	srs.pendingTasks[msgID.String()] = task
	srs.mu.Unlock()

	// Finalized block is past message block
	latest := &protocol.BlockHeader{Number: 200}
	finalized := &protocol.BlockHeader{Number: 150}

	srs.sendReadyMessages(ctx, latest, finalized)

	// Wait for task to be published
	require.Eventually(t, func() bool {
		return len(queue.Published()) == 1
	}, tests.WaitTimeout(t), 10*time.Millisecond)

	// SeqNum should be removed from reorg tracker after finalization
	require.False(t, srs.reorgTracker.RequiresFinalization(defaultDestChain, msg.SequenceNumber),
		"seqNum should be removed from reorg tracker after finalization")
	require.False(t, len(srs.reorgTracker.reorgedSeqNums) > 0)
}

// ----------------------
// Block Range Chunking Tests
// ----------------------

func TestSRS_MultiCycle_SmallRangeCompletesInOneTick(t *testing.T) {
	ctx := context.Background()
	chain := protocol.ChainSelector(1337)

	reader := mocks.NewMockSourceReader(t)

	latest := &protocol.BlockHeader{Number: 200}
	finalized := &protocol.BlockHeader{Number: 150}

	reader.EXPECT().
		LatestAndFinalizedBlock(mock.Anything).
		Return(latest, finalized, nil).
		Maybe()

	events := createTestMessageSentEvents(t, 1, chain, defaultDestChain, []uint64{110, 120})

	// Range fits in one chunk (< 5000 default), last chunk uses nil toBlock
	nilBigInt := mock.MatchedBy(func(arg *big.Int) bool { return arg == nil })
	reader.EXPECT().
		FetchMessageSentEvents(mock.Anything, big.NewInt(99), nilBigInt).
		Return(events, nil).
		Once()

	chainStatusMgr := mocks.NewMockChainStatusManager(t)
	chainStatusMgr.EXPECT().
		ReadChainStatuses(mock.Anything, mock.Anything).
		Return(map[protocol.ChainSelector]*protocol.ChainStatusInfo{}, nil).
		Maybe()
	chainStatusMgr.EXPECT().
		WriteChainStatuses(mock.Anything, mock.Anything).
		Return(nil).
		Maybe()

	curseDetector := mocks.NewMockCurseCheckerService(t)
	curseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).Return(false).Maybe()
	curseDetector.EXPECT().Start(mock.Anything).Return(nil).Maybe()
	curseDetector.EXPECT().Close().Return(nil).Maybe()

	srs, _, _ := newTestSRS(t, chain, reader, chainStatusMgr, curseDetector, 10*time.Millisecond, 5000)
	srs.lastProcessedFinalizedBlock.Store(big.NewInt(99))

	srs.processEventCycle(ctx, latest, finalized)

	srs.mu.RLock()
	defer srs.mu.RUnlock()

	require.Len(t, srs.pendingTasks, 2, "both events should be queued")
	require.Equal(t, int64(150), srs.lastProcessedFinalizedBlock.Load().Int64(),
		"progress should advance to finalized")
}

func TestSRS_LargeRangeChunkedInSingleCycle(t *testing.T) {
	ctx := context.Background()
	chain := protocol.ChainSelector(1337)

	reader := mocks.NewMockSourceReader(t)

	// Large range: 100 to 12000 (11900 blocks, > 5000 default)
	latest := &protocol.BlockHeader{Number: 12000}
	finalized := &protocol.BlockHeader{Number: 11000}

	reader.EXPECT().
		LatestAndFinalizedBlock(mock.Anything).
		Return(latest, finalized, nil).
		Maybe()

	events1 := createTestMessageSentEvents(t, 1, chain, defaultDestChain, []uint64{500, 2000})
	events2 := createTestMessageSentEvents(t, 10, chain, defaultDestChain, []uint64{6000})
	events3 := createTestMessageSentEvents(t, 20, chain, defaultDestChain, []uint64{11500})

	nilBigInt := mock.MatchedBy(func(arg *big.Int) bool { return arg == nil })

	// All chunks processed in a single cycle
	reader.EXPECT().
		FetchMessageSentEvents(mock.Anything, big.NewInt(99), big.NewInt(5099)).
		Return(events1, nil).
		Once()
	reader.EXPECT().
		FetchMessageSentEvents(mock.Anything, big.NewInt(5100), big.NewInt(10100)).
		Return(events2, nil).
		Once()
	// Last chunk uses nil toBlock
	reader.EXPECT().
		FetchMessageSentEvents(mock.Anything, big.NewInt(10101), nilBigInt).
		Return(events3, nil).
		Once()

	chainStatusMgr := mocks.NewMockChainStatusManager(t)
	chainStatusMgr.EXPECT().
		ReadChainStatuses(mock.Anything, mock.Anything).
		Return(map[protocol.ChainSelector]*protocol.ChainStatusInfo{}, nil).
		Maybe()
	chainStatusMgr.EXPECT().
		WriteChainStatuses(mock.Anything, mock.Anything).
		Return(nil).
		Maybe()

	curseDetector := mocks.NewMockCurseCheckerService(t)
	curseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).Return(false).Maybe()
	curseDetector.EXPECT().Start(mock.Anything).Return(nil).Maybe()
	curseDetector.EXPECT().Close().Return(nil).Maybe()

	srs, _, _ := newTestSRS(t, chain, reader, chainStatusMgr, curseDetector, 10*time.Millisecond, 0)
	srs.lastProcessedFinalizedBlock.Store(big.NewInt(99))

	srs.processEventCycle(ctx, latest, finalized)

	// Progress should advance to finalized (11000)
	require.Equal(t, int64(11000), srs.lastProcessedFinalizedBlock.Load().Int64(),
		"should advance to finalized after processing all chunks")

	srs.mu.RLock()
	defer srs.mu.RUnlock()
	require.Len(t, srs.pendingTasks, 4, "all events from all chunks should be queued")
}

func TestSRS_CustomMaxBlockRangeChunksCorrectly(t *testing.T) {
	ctx := context.Background()
	chain := protocol.ChainSelector(1337)

	reader := mocks.NewMockSourceReader(t)

	// Range with custom maxBlockRange of 100
	latest := &protocol.BlockHeader{Number: 400}
	finalized := &protocol.BlockHeader{Number: 350}

	reader.EXPECT().
		LatestAndFinalizedBlock(mock.Anything).
		Return(latest, finalized, nil).
		Maybe()

	nilBigInt := mock.MatchedBy(func(arg *big.Int) bool { return arg == nil })

	// All chunks processed in single cycle with maxBlockRange=100
	// Chunk 1: [99, 199]
	reader.EXPECT().
		FetchMessageSentEvents(mock.Anything, big.NewInt(99), big.NewInt(199)).
		Return(nil, nil).
		Once()
	// Chunk 2: [200, 300]
	reader.EXPECT().
		FetchMessageSentEvents(mock.Anything, big.NewInt(200), big.NewInt(300)).
		Return(nil, nil).
		Once()
	// Chunk 3: [301, nil] - toBlock >= latest so use nil
	reader.EXPECT().
		FetchMessageSentEvents(mock.Anything, big.NewInt(301), nilBigInt).
		Return(nil, nil).
		Once()

	chainStatusMgr := mocks.NewMockChainStatusManager(t)
	chainStatusMgr.EXPECT().
		ReadChainStatuses(mock.Anything, mock.Anything).
		Return(map[protocol.ChainSelector]*protocol.ChainStatusInfo{}, nil).
		Maybe()
	chainStatusMgr.EXPECT().
		WriteChainStatuses(mock.Anything, mock.Anything).
		Return(nil).
		Maybe()

	curseDetector := mocks.NewMockCurseCheckerService(t)
	curseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).Return(false).Maybe()
	curseDetector.EXPECT().Start(mock.Anything).Return(nil).Maybe()
	curseDetector.EXPECT().Close().Return(nil).Maybe()

	srs, _, _ := newTestSRS(t, chain, reader, chainStatusMgr, curseDetector, 10*time.Millisecond, 100)
	srs.sourceCfg.MaxBlockRange = 100
	srs.lastProcessedFinalizedBlock.Store(big.NewInt(99))

	srs.processEventCycle(ctx, latest, finalized)

	require.Equal(t, int64(350), srs.lastProcessedFinalizedBlock.Load().Int64(),
		"should advance to finalized after processing all chunks")
}

func TestSRS_OneBlockChunkAdvancesProgress(t *testing.T) {
	ctx := context.Background()
	chain := protocol.ChainSelector(1337)

	reader := mocks.NewMockSourceReader(t)

	latest := &protocol.BlockHeader{Number: 100}
	finalized := &protocol.BlockHeader{Number: 100}

	reader.EXPECT().
		LatestAndFinalizedBlock(mock.Anything).
		Return(latest, finalized, nil).
		Maybe()

	nilBigInt := mock.MatchedBy(func(arg *big.Int) bool { return arg == nil })

	// Single block query with maxBlockRange=1
	reader.EXPECT().
		FetchMessageSentEvents(mock.Anything, big.NewInt(99), nilBigInt).
		Return(nil, nil).
		Once()

	chainStatusMgr := mocks.NewMockChainStatusManager(t)
	chainStatusMgr.EXPECT().
		ReadChainStatuses(mock.Anything, mock.Anything).
		Return(map[protocol.ChainSelector]*protocol.ChainStatusInfo{}, nil).
		Maybe()
	chainStatusMgr.EXPECT().
		WriteChainStatuses(mock.Anything, mock.Anything).
		Return(nil).
		Maybe()

	curseDetector := mocks.NewMockCurseCheckerService(t)
	curseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).Return(false).Maybe()
	curseDetector.EXPECT().Start(mock.Anything).Return(nil).Maybe()
	curseDetector.EXPECT().Close().Return(nil).Maybe()

	srs, _, _ := newTestSRS(t, chain, reader, chainStatusMgr, curseDetector, 10*time.Millisecond, 100)
	srs.sourceCfg.MaxBlockRange = 1
	srs.lastProcessedFinalizedBlock.Store(big.NewInt(99))

	srs.processEventCycle(ctx, latest, finalized)

	require.Equal(t, int64(100), srs.lastProcessedFinalizedBlock.Load().Int64(),
		"progress should advance to finalized")
}

// ----------------------
// Error Handling & Recovery Tests
// ----------------------

func TestSRS_FailureRetriesNextTick(t *testing.T) {
	ctx := context.Background()
	chain := protocol.ChainSelector(1337)

	reader := mocks.NewMockSourceReader(t)

	latest := &protocol.BlockHeader{Number: 1000}
	finalized := &protocol.BlockHeader{Number: 900}

	reader.EXPECT().
		LatestAndFinalizedBlock(mock.Anything).
		Return(latest, finalized, nil).
		Maybe()

	events := createTestMessageSentEvents(t, 1, chain, defaultDestChain, []uint64{500})

	nilBigInt := mock.MatchedBy(func(arg *big.Int) bool { return arg == nil })

	// First cycle fails
	reader.EXPECT().
		FetchMessageSentEvents(mock.Anything, big.NewInt(99), nilBigInt).
		Return(nil, assert.AnError).
		Once()
	// Second cycle retries from same position since no progress was made
	reader.EXPECT().
		FetchMessageSentEvents(mock.Anything, big.NewInt(99), nilBigInt).
		Return(events, nil).
		Once()

	chainStatusMgr := mocks.NewMockChainStatusManager(t)
	chainStatusMgr.EXPECT().
		ReadChainStatuses(mock.Anything, mock.Anything).
		Return(map[protocol.ChainSelector]*protocol.ChainStatusInfo{}, nil).
		Maybe()
	chainStatusMgr.EXPECT().
		WriteChainStatuses(mock.Anything, mock.Anything).
		Return(nil).
		Maybe()

	curseDetector := mocks.NewMockCurseCheckerService(t)
	curseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).Return(false).Maybe()
	curseDetector.EXPECT().Start(mock.Anything).Return(nil).Maybe()
	curseDetector.EXPECT().Close().Return(nil).Maybe()

	srs, _, _ := newTestSRS(t, chain, reader, chainStatusMgr, curseDetector, 10*time.Millisecond, 5000)
	srs.lastProcessedFinalizedBlock.Store(big.NewInt(99))

	// Cycle 1: fails
	srs.processEventCycle(ctx, latest, finalized)

	require.Equal(t, int64(99), srs.lastProcessedFinalizedBlock.Load().Int64(),
		"progress should not advance on failure")

	srs.mu.RLock()
	require.Len(t, srs.pendingTasks, 0, "no events should be queued on failure")
	srs.mu.RUnlock()

	// Cycle 2: succeeds
	srs.processEventCycle(ctx, latest, finalized)

	require.Equal(t, int64(900), srs.lastProcessedFinalizedBlock.Load().Int64(),
		"progress should advance after successful retry")

	srs.mu.RLock()
	defer srs.mu.RUnlock()
	require.Len(t, srs.pendingTasks, 1, "events should be queued after retry")
}

func TestSRS_NoNewBlocksStaysAtSameProgress(t *testing.T) {
	ctx := context.Background()
	chain := protocol.ChainSelector(1337)

	reader := mocks.NewMockSourceReader(t)

	// lastProcessed=100, latest=100 - no new blocks to process
	latest := &protocol.BlockHeader{Number: 100}
	finalized := &protocol.BlockHeader{Number: 100}

	reader.EXPECT().
		LatestAndFinalizedBlock(mock.Anything).
		Return(latest, finalized, nil).
		Maybe()

	chainStatusMgr := mocks.NewMockChainStatusManager(t)
	chainStatusMgr.EXPECT().
		ReadChainStatuses(mock.Anything, mock.Anything).
		Return(map[protocol.ChainSelector]*protocol.ChainStatusInfo{}, nil).
		Maybe()
	chainStatusMgr.EXPECT().
		WriteChainStatuses(mock.Anything, mock.Anything).
		Return(nil).
		Maybe()

	curseDetector := mocks.NewMockCurseCheckerService(t)
	curseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).Return(false).Maybe()
	curseDetector.EXPECT().Start(mock.Anything).Return(nil).Maybe()
	curseDetector.EXPECT().Close().Return(nil).Maybe()

	nilBigInt := mock.MatchedBy(func(arg *big.Int) bool { return arg == nil })

	// Query still happens but returns error (simulating edge case)
	reader.EXPECT().
		FetchMessageSentEvents(mock.Anything, big.NewInt(100), nilBigInt).
		Return(nil, assert.AnError).
		Once()

	srs, _, _ := newTestSRS(t, chain, reader, chainStatusMgr, curseDetector, 10*time.Millisecond, 100)
	srs.lastProcessedFinalizedBlock.Store(big.NewInt(100))

	srs.processEventCycle(ctx, latest, finalized)

	srs.mu.RLock()
	defer srs.mu.RUnlock()

	require.Len(t, srs.pendingTasks, 0)
	require.Equal(t, int64(100), srs.lastProcessedFinalizedBlock.Load().Int64(),
		"progress should stay at 100 after failed query")
}

func TestSRS_FailureDoesNotDeleteExistingTasks(t *testing.T) {
	ctx := context.Background()
	chain := protocol.ChainSelector(1337)

	reader := mocks.NewMockSourceReader(t)

	latest := &protocol.BlockHeader{Number: 1000}
	finalized := &protocol.BlockHeader{Number: 900}

	reader.EXPECT().
		LatestAndFinalizedBlock(mock.Anything).
		Return(latest, finalized, nil).
		Maybe()

	nilBigInt := mock.MatchedBy(func(arg *big.Int) bool { return arg == nil })

	reader.EXPECT().
		FetchMessageSentEvents(mock.Anything, big.NewInt(99), nilBigInt).
		Return(nil, assert.AnError).
		Once()

	chainStatusMgr := mocks.NewMockChainStatusManager(t)
	chainStatusMgr.EXPECT().
		ReadChainStatuses(mock.Anything, mock.Anything).
		Return(map[protocol.ChainSelector]*protocol.ChainStatusInfo{}, nil).
		Maybe()

	curseDetector := mocks.NewMockCurseCheckerService(t)
	curseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).Return(false).Maybe()
	curseDetector.EXPECT().Start(mock.Anything).Return(nil).Maybe()
	curseDetector.EXPECT().Close().Return(nil).Maybe()

	srs, _, _ := newTestSRS(t, chain, reader, chainStatusMgr, curseDetector, 10*time.Millisecond, 5000)
	srs.lastProcessedFinalizedBlock.Store(big.NewInt(99))

	// Pre-seed a pending task
	existingEvent := createTestMessageSentEvents(t, 1, chain, defaultDestChain, []uint64{100})
	existingTask := VerificationTask{
		Message:     existingEvent[0].Message,
		BlockNumber: existingEvent[0].BlockNumber,
		MessageID:   existingEvent[0].MessageID.String(),
	}

	srs.mu.Lock()
	srs.pendingTasks[existingTask.MessageID] = existingTask
	srs.mu.Unlock()

	srs.processEventCycle(ctx, latest, finalized)

	srs.mu.RLock()
	defer srs.mu.RUnlock()

	// Existing task preserved because query failed (no reorg reconciliation on failure)
	require.Len(t, srs.pendingTasks, 1, "existing task should be preserved on failure")

	_, hasExisting := srs.pendingTasks[existingTask.MessageID]
	require.True(t, hasExisting, "task should NOT be deleted when query fails")

	// Progress should not have advanced
	require.Equal(t, int64(99), srs.lastProcessedFinalizedBlock.Load().Int64(),
		"progress should not advance on failure")
}

// ----------------------
// Edge Cases & Boundary Conditions
// ----------------------

func TestSRS_FromBlockAheadOfLatestResetsToFinalized(t *testing.T) {
	ctx := context.Background()
	chain := protocol.ChainSelector(1337)

	reader := mocks.NewMockSourceReader(t)

	// lastProcessed=1000 > latest=500 - possible reorg scenario
	latest := &protocol.BlockHeader{Number: 500}
	finalized := &protocol.BlockHeader{Number: 400}

	reader.EXPECT().
		LatestAndFinalizedBlock(mock.Anything).
		Return(latest, finalized, nil).
		Maybe()

	nilBigInt := mock.MatchedBy(func(arg *big.Int) bool { return arg == nil })

	// Query still happens with lastProcessed as fromBlock
	reader.EXPECT().
		FetchMessageSentEvents(mock.Anything, big.NewInt(1000), nilBigInt).
		Return(nil, nil).
		Once()

	chainStatusMgr := mocks.NewMockChainStatusManager(t)
	chainStatusMgr.EXPECT().
		ReadChainStatuses(mock.Anything, mock.Anything).
		Return(map[protocol.ChainSelector]*protocol.ChainStatusInfo{}, nil).
		Maybe()
	chainStatusMgr.EXPECT().
		WriteChainStatuses(mock.Anything, mock.Anything).
		Return(nil).
		Maybe()

	curseDetector := mocks.NewMockCurseCheckerService(t)
	curseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).Return(false).Maybe()
	curseDetector.EXPECT().Start(mock.Anything).Return(nil).Maybe()
	curseDetector.EXPECT().Close().Return(nil).Maybe()

	srs, _, _ := newTestSRS(t, chain, reader, chainStatusMgr, curseDetector, 10*time.Millisecond, 5000)
	srs.lastProcessedFinalizedBlock.Store(big.NewInt(1000))

	srs.processEventCycle(ctx, latest, finalized)

	// Progress resets to current finalized
	require.Equal(t, int64(400), srs.lastProcessedFinalizedBlock.Load().Int64(),
		"progress should reset to finalized when ahead of latest")

	srs.mu.RLock()
	defer srs.mu.RUnlock()
	require.Len(t, srs.pendingTasks, 0, "no tasks should be added")
}

func TestSRS_FinalizedBehindLastProcessed_QueriesAndUpdatesToFinalized(t *testing.T) {
	ctx := context.Background()
	chain := protocol.ChainSelector(1337)

	reader := mocks.NewMockSourceReader(t)

	// finalized=50 is behind lastProcessed=100 (edge case)
	latest := &protocol.BlockHeader{Number: 10000}
	finalized := &protocol.BlockHeader{Number: 50}

	reader.EXPECT().
		LatestAndFinalizedBlock(mock.Anything).
		Return(latest, finalized, nil).
		Maybe()

	nilBigInt := mock.MatchedBy(func(arg *big.Int) bool { return arg == nil })

	// Queries all chunks up to latest
	reader.EXPECT().
		FetchMessageSentEvents(mock.Anything, big.NewInt(100), big.NewInt(5100)).
		Return(nil, nil).
		Once()
	reader.EXPECT().
		FetchMessageSentEvents(mock.Anything, big.NewInt(5101), nilBigInt).
		Return(nil, nil).
		Once()

	chainStatusMgr := mocks.NewMockChainStatusManager(t)
	chainStatusMgr.EXPECT().
		ReadChainStatuses(mock.Anything, mock.Anything).
		Return(map[protocol.ChainSelector]*protocol.ChainStatusInfo{}, nil).
		Maybe()
	chainStatusMgr.EXPECT().
		WriteChainStatuses(mock.Anything, mock.Anything).
		Return(nil).
		Maybe()

	curseDetector := mocks.NewMockCurseCheckerService(t)
	curseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).Return(false).Maybe()
	curseDetector.EXPECT().Start(mock.Anything).Return(nil).Maybe()
	curseDetector.EXPECT().Close().Return(nil).Maybe()

	srs, _, _ := newTestSRS(t, chain, reader, chainStatusMgr, curseDetector, 10*time.Millisecond, 5000)
	srs.lastProcessedFinalizedBlock.Store(big.NewInt(100))

	srs.processEventCycle(ctx, latest, finalized)

	// Progress updates to current finalized (safe restart point)
	require.Equal(t, int64(50), srs.lastProcessedFinalizedBlock.Load().Int64(),
		"progress should update to finalized after querying all blocks")
}
