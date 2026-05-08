package sourcereader

import (
	"context"
	"errors"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/common"
	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/jobqueue"
	verifier "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vtypes"
	"github.com/smartcontractkit/chainlink-ccv/verifier/testutil"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/utils/tests"
)

// fakeTaskQueue is an in-memory implementation of jobqueue.JobQueue[verifier.VerificationTask]
// used to capture tasks published by Service without needing a real DB.
type fakeTaskQueue struct {
	mu        sync.Mutex
	published []verifier.VerificationTask
}

func (q *fakeTaskQueue) Publish(_ context.Context, tasks ...verifier.VerificationTask) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.published = append(q.published, tasks...)
	return nil
}

func (q *fakeTaskQueue) PublishWithDelay(_ context.Context, _ time.Duration, tasks ...verifier.VerificationTask) error {
	return q.Publish(context.Background(), tasks...)
}

func (q *fakeTaskQueue) Consume(_ context.Context, _ int) ([]jobqueue.Job[verifier.VerificationTask], error) {
	return nil, nil
}

func (q *fakeTaskQueue) Complete(_ context.Context, _ ...string) error { return nil }
func (q *fakeTaskQueue) Retry(_ context.Context, _ time.Duration, _ map[string]error, _ ...string) error {
	return nil
}
func (q *fakeTaskQueue) Fail(_ context.Context, _ map[string]error, _ ...string) error { return nil }
func (q *fakeTaskQueue) Cleanup(_ context.Context, _ time.Duration) (int, error)       { return 0, nil }
func (q *fakeTaskQueue) Name() string                                                  { return "fake-task-queue" }
func (q *fakeTaskQueue) Size(_ context.Context) (int, error)                           { return 0, nil }

func (q *fakeTaskQueue) Published() []verifier.VerificationTask {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := make([]verifier.VerificationTask, len(q.published))
	copy(out, q.published)
	return out
}

func newTestSRS(
	t *testing.T,
	chainSelector protocol.ChainSelector,
	reader chainaccess.SourceReader,
	chainStatusMgr protocol.ChainStatusManager,
	curseDetector *mocks.MockCurseCheckerService,
	pollInterval time.Duration,
	maxBlockRange uint64,
) (*Service, *mocks.MockFinalityViolationChecker, *fakeTaskQueue) {
	t.Helper()

	lggr := logger.Test(t)
	queue := &fakeTaskQueue{}

	srs, err := NewService(
		reader,
		chainSelector,
		chainStatusMgr,
		lggr,
		verifier.SourceConfig{PollInterval: pollInterval, MaxBlockRange: maxBlockRange},
		curseDetector,
		&noopFilter{},
		&testutil.NoopMetricLabeler{},
		queue,
	)
	require.NoError(t, err)

	mockFC := mocks.NewMockFinalityViolationChecker(t)
	srs.finalityChecker = mockFC
	mockFC.EXPECT().UpdateFinalized(mock.Anything, mock.Anything).Return(nil).Maybe()
	mockFC.EXPECT().IsFinalityViolated().Return(false).Maybe()

	// SRS now writes checkpoints after every successful publish/cycle.
	// Allow WriteChainStatuses on any mock passed in so individual tests don't
	// have to set this up unless they specifically want to assert on it.
	if mockCSM, ok := chainStatusMgr.(*mocks.MockChainStatusManager); ok {
		mockCSM.EXPECT().WriteChainStatuses(mock.Anything, mock.Anything).Return(nil).Maybe()
	}

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
	curseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()
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
	curseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()
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
	curseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()
	curseDetector.EXPECT().Start(mock.Anything).Return(nil).Maybe()
	curseDetector.EXPECT().Close().Return(nil).Maybe()

	srs, _, _ := newTestSRS(t, chain, reader, chainStatusMgr, curseDetector, 10*time.Millisecond, 5000)

	msgs := createTestMessageSentEvents(t, 1, chain, defaultDestChain, []uint64{100, 101, 102})
	taskA := verifier.VerificationTask{Message: msgs[0].Message, BlockNumber: msgs[0].BlockNumber, MessageID: msgs[0].MessageID.String()}
	taskB := verifier.VerificationTask{Message: msgs[1].Message, BlockNumber: msgs[1].BlockNumber, MessageID: msgs[1].MessageID.String()}
	taskC := verifier.VerificationTask{Message: msgs[2].Message, BlockNumber: msgs[2].BlockNumber, MessageID: msgs[2].MessageID.String()}

	srs.mu.Lock()
	srs.pendingTasks = map[string]verifier.VerificationTask{taskA.MessageID: taskA, taskB.MessageID: taskB}
	srs.sentTasks = map[string]verifier.VerificationTask{taskC.MessageID: taskC}
	srs.mu.Unlock()

	// New canonical events keep A, add D; B and C are gone
	msgsD := createTestMessageSentEvents(t, 10, chain, defaultDestChain, []uint64{103})
	taskD := verifier.VerificationTask{Message: msgsD[0].Message, BlockNumber: msgsD[0].BlockNumber, MessageID: msgsD[0].MessageID.String()}

	srs.addToPendingQueueHandleReorg([]verifier.VerificationTask{taskA, taskD}, big.NewInt(100), big.NewInt(103))

	srs.mu.RLock()
	defer srs.mu.RUnlock()

	require.Len(t, srs.pendingTasks, 2)
	_, hasA := srs.pendingTasks[taskA.MessageID]
	_, hasD := srs.pendingTasks[taskD.MessageID]
	require.True(t, hasA)
	require.True(t, hasD)
	require.Len(t, srs.sentTasks, 0)
}

func TestSRS_CurseStateUnknown_RetainsTaskAndBlocksCheckpointUntilResolved(t *testing.T) {
	ctx := context.Background()
	chain := protocol.ChainSelector(1337)
	reader := mocks.NewMockSourceReader(t)

	var checkpointWriteCount int
	chainStatusMgr := mocks.NewMockChainStatusManager(t)
	chainStatusMgr.EXPECT().WriteChainStatuses(mock.Anything, mock.Anything).
		RunAndReturn(func(_ context.Context, _ []protocol.ChainStatusInfo) error {
			checkpointWriteCount++
			return nil
		}).Maybe()

	curseDetector := mocks.NewMockCurseCheckerService(t)
	curseDetector.EXPECT().Start(mock.Anything).Return(nil).Maybe()
	curseDetector.EXPECT().Close().Return(nil).Maybe()

	srs, mockFC, queue := newTestSRS(t, chain, reader, chainStatusMgr, curseDetector, 10*time.Millisecond, 5000)
	mockFC.EXPECT().UpdateFinalized(mock.Anything, mock.Anything).Return(nil).Maybe()
	mockFC.EXPECT().IsFinalityViolated().Return(false).Maybe()

	msg := testutil.CreateTestMessage(t, 1, chain, defaultDestChain, 0, 300_000)
	msgID, _ := msg.MessageID()
	task := verifier.VerificationTask{Message: msg, BlockNumber: 940, MessageID: msgID.String()}

	srs.mu.Lock()
	srs.pendingTasks[msgID.String()] = task
	srs.mu.Unlock()

	latest := &protocol.BlockHeader{Number: 1000}
	finalized := &protocol.BlockHeader{Number: 950}

	// Tick 1: curse state unknown — task must be retained, checkpoint must NOT advance
	curseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, chain, defaultDestChain).
		Return(true, common.ErrCurseStateUnknown).Once()

	srs.sendReadyMessages(ctx, latest, nil, finalized)

	srs.mu.RLock()
	assert.Len(t, srs.pendingTasks, 1, "task must remain in pendingTasks when curse state is unknown")
	assert.Len(t, srs.sentTasks, 0, "task must not be moved to sentTasks")
	srs.mu.RUnlock()
	assert.Len(t, queue.Published(), 0, "no tasks should be published when curse state is unknown")
	assert.Equal(t, 0, checkpointWriteCount, "checkpoint must not be written when curse state is unknown")

	// Tick 2: curse resolved (lane is NOT cursed) — task should be published and checkpoint should advance
	curseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, chain, defaultDestChain).
		Return(false, nil).Once()

	srs.sendReadyMessages(ctx, latest, nil, finalized)

	srs.mu.RLock()
	assert.Len(t, srs.pendingTasks, 0, "task should be removed from pendingTasks after curse resolves")
	assert.Len(t, srs.sentTasks, 1, "task should be moved to sentTasks after publish")
	srs.mu.RUnlock()
	assert.Len(t, queue.Published(), 1, "task should be published after curse resolves")
	assert.Equal(t, task.MessageID, queue.Published()[0].MessageID)
	assert.Equal(t, 1, checkpointWriteCount, "checkpoint should be written after curse resolves")
}

func TestSRS_Curse_DropsAtSendTime(t *testing.T) {
	ctx := context.Background()
	chain := protocol.ChainSelector(1337)
	reader := mocks.NewMockSourceReader(t)
	chainStatusMgr := mocks.NewMockChainStatusManager(t)

	curseDetector := mocks.NewMockCurseCheckerService(t)
	curseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).Return(true, nil).Maybe()
	curseDetector.EXPECT().Start(mock.Anything).Return(nil).Maybe()
	curseDetector.EXPECT().Close().Return(nil).Maybe()

	srs, mockFC, queue := newTestSRS(t, chain, reader, chainStatusMgr, curseDetector, 10*time.Millisecond, 5000)
	mockFC.EXPECT().UpdateFinalized(mock.Anything, mock.Anything).Return(nil).Maybe()
	mockFC.EXPECT().IsFinalityViolated().Return(false).Maybe()

	events := createTestMessageSentEvents(t, 1, chain, defaultDestChain, []uint64{100, 101})
	tasks := []verifier.VerificationTask{
		{Message: events[0].Message, BlockNumber: events[0].BlockNumber, MessageID: events[0].MessageID.String()},
		{Message: events[1].Message, BlockNumber: events[1].BlockNumber, MessageID: events[1].MessageID.String()},
	}
	srs.addToPendingQueueHandleReorg(tasks, big.NewInt(100), big.NewInt(101))

	latest := &protocol.BlockHeader{Number: 150}
	finalized := &protocol.BlockHeader{Number: 120}
	srs.sendReadyMessages(ctx, latest, nil, finalized)

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
	curseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()
	curseDetector.EXPECT().Start(mock.Anything).Return(nil).Maybe()
	curseDetector.EXPECT().Close().Return(nil).Maybe()

	srs, mockFC, queue := newTestSRS(t, chain, reader, chainStatusMgr, curseDetector, 10*time.Millisecond, 5000)
	mockFC.EXPECT().UpdateFinalized(mock.Anything, finalized.Number).Return(nil).Maybe()
	mockFC.EXPECT().IsFinalityViolated().Return(false).Maybe()

	// Task with Finality=0 at block <= finalized — should be ready immediately.
	msg := testutil.CreateTestMessage(t, 1, chain, defaultDestChain, 0, 300_000)
	msgID, _ := msg.MessageID()
	task := verifier.VerificationTask{Message: msg, BlockNumber: 940, MessageID: msgID.String()}

	srs.mu.Lock()
	srs.pendingTasks[msgID.String()] = task
	srs.mu.Unlock()

	srs.sendReadyMessages(ctx, latest, nil, finalized)

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
	curseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()
	curseDetector.EXPECT().Start(mock.Anything).Return(nil).Maybe()
	curseDetector.EXPECT().Close().Return(nil).Maybe()

	srs, _, queue := newTestSRS(t, chain, reader, chainStatusMgr, curseDetector, 10*time.Millisecond, 5000)

	const f protocol.Finality = 10
	msg := testutil.CreateTestMessage(t, 1, chain, defaultDestChain, f, 300_000)
	msgID, _ := msg.MessageID()
	// block = latest - f  => custom finality met
	task := verifier.VerificationTask{Message: msg, BlockNumber: latest.Number - uint64(f), MessageID: msgID.String()}

	srs.mu.Lock()
	srs.pendingTasks[msgID.String()] = task
	srs.mu.Unlock()

	srs.sendReadyMessages(ctx, latest, nil, finalized)

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
	curseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()
	curseDetector.EXPECT().Start(mock.Anything).Return(nil).Maybe()
	curseDetector.EXPECT().Close().Return(nil).Maybe()

	srs, _, queue := newTestSRS(t, chain, reader, chainStatusMgr, curseDetector, 10*time.Millisecond, 5000)

	// Block 980 > finalized 950, Finality=0 — not ready yet.
	msg := testutil.CreateTestMessage(t, 1, chain, defaultDestChain, 0, 300_000)
	msgID, _ := msg.MessageID()
	task := verifier.VerificationTask{Message: msg, BlockNumber: 980, MessageID: msgID.String()}

	srs.mu.Lock()
	srs.pendingTasks[msgID.String()] = task
	srs.mu.Unlock()

	srs.sendReadyMessages(ctx, latest, nil, finalized)

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
		blockDepth     protocol.Finality
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
			msg := testutil.CreateTestMessage(t, 1, chain, defaultDestChain, tc.blockDepth, 300_000)
			msgID, _ := msg.MessageID()
			task := verifier.VerificationTask{Message: msg, BlockNumber: tc.msgBlock, MessageID: msgID.String()}

			ready := srs.isMessageReadyForVerification(
				task,
				big.NewInt(int64(tc.latestBlock)),
				nil,
				big.NewInt(int64(tc.finalizedBlock)),
			)
			require.Equal(t, tc.expectedReady, ready)
		})
	}
}

func TestSRS_isMessageReadyForVerification_SafeTag(t *testing.T) {
	chain := protocol.ChainSelector(1337)
	reader := mocks.NewMockSourceReader(t)
	chainStatusMgr := mocks.NewMockChainStatusManager(t)
	curseDetector := mocks.NewMockCurseCheckerService(t)

	srs, _, _ := newTestSRS(t, chain, reader, chainStatusMgr, curseDetector, 10*time.Millisecond, 5000)

	testCases := []struct {
		name           string
		msgBlock       uint64
		safeBlock      *big.Int // nil means safe head unavailable
		finalizedBlock uint64
		expectedReady  bool
	}{
		{
			name:           "Ready_BelowSafeBlock",
			msgBlock:       900,
			safeBlock:      big.NewInt(950),
			finalizedBlock: 800,
			expectedReady:  true,
		},
		{
			name:           "Ready_ExactlyAtSafeBlock",
			msgBlock:       950,
			safeBlock:      big.NewInt(950),
			finalizedBlock: 800,
			expectedReady:  true,
		},
		{
			name:           "NotReady_AboveSafeBlock",
			msgBlock:       960,
			safeBlock:      big.NewInt(950),
			finalizedBlock: 800,
			expectedReady:  false,
		},
		{
			name:           "FallbackToFinality_Ready_WhenSafeUnavailable",
			msgBlock:       790,
			safeBlock:      nil,
			finalizedBlock: 800,
			expectedReady:  true,
		},
		{
			name:           "FallbackToFinality_NotReady_WhenSafeUnavailable",
			msgBlock:       850,
			safeBlock:      nil,
			finalizedBlock: 800,
			expectedReady:  false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			msg := testutil.CreateTestMessage(t, 1, chain, defaultDestChain, protocol.FinalityWaitForSafe, 300_000)
			msgID, _ := msg.MessageID()
			task := verifier.VerificationTask{Message: msg, BlockNumber: tc.msgBlock, MessageID: msgID.String()}

			ready := srs.isMessageReadyForVerification(
				task,
				big.NewInt(int64(tc.msgBlock+1000)), // latestBlock well ahead — irrelevant for safe-tag mode
				tc.safeBlock,
				big.NewInt(int64(tc.finalizedBlock)),
			)
			require.Equal(t, tc.expectedReady, ready)
		})
	}
}

func TestSRS_Readiness_SafeTag_PublishesToQueue(t *testing.T) {
	ctx := context.Background()
	chain := protocol.ChainSelector(1337)
	reader := mocks.NewMockSourceReader(t)

	latest := &protocol.BlockHeader{Number: 1000}
	safe := &protocol.BlockHeader{Number: 970}
	finalized := &protocol.BlockHeader{Number: 950}

	chainStatusMgr := mocks.NewMockChainStatusManager(t)
	chainStatusMgr.EXPECT().ReadChainStatuses(mock.Anything, mock.Anything).
		Return(map[protocol.ChainSelector]*protocol.ChainStatusInfo{}, nil).Maybe()

	curseDetector := mocks.NewMockCurseCheckerService(t)
	curseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()
	curseDetector.EXPECT().Start(mock.Anything).Return(nil).Maybe()
	curseDetector.EXPECT().Close().Return(nil).Maybe()

	srs, _, queue := newTestSRS(t, chain, reader, chainStatusMgr, curseDetector, 10*time.Millisecond, 5000)

	// Message at block 960 ≤ safe(970) — should be published.
	msg := testutil.CreateTestMessage(t, 1, chain, defaultDestChain, protocol.FinalityWaitForSafe, 300_000)
	msgID, _ := msg.MessageID()
	task := verifier.VerificationTask{Message: msg, BlockNumber: 960, MessageID: msgID.String()}

	srs.mu.Lock()
	srs.pendingTasks[msgID.String()] = task
	srs.mu.Unlock()

	srs.sendReadyMessages(ctx, latest, safe, finalized)

	require.Eventually(t, func() bool {
		return len(queue.Published()) == 1
	}, tests.WaitTimeout(t), 10*time.Millisecond)

	require.Equal(t, task.MessageID, queue.Published()[0].MessageID)
}

func TestSRS_Readiness_SafeTag_NotReady_AboveSafeBlock(t *testing.T) {
	ctx := context.Background()
	chain := protocol.ChainSelector(1337)
	reader := mocks.NewMockSourceReader(t)

	latest := &protocol.BlockHeader{Number: 1000}
	safe := &protocol.BlockHeader{Number: 970}
	finalized := &protocol.BlockHeader{Number: 950}

	chainStatusMgr := mocks.NewMockChainStatusManager(t)
	curseDetector := mocks.NewMockCurseCheckerService(t)
	curseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()
	curseDetector.EXPECT().Start(mock.Anything).Return(nil).Maybe()
	curseDetector.EXPECT().Close().Return(nil).Maybe()

	srs, _, queue := newTestSRS(t, chain, reader, chainStatusMgr, curseDetector, 10*time.Millisecond, 5000)

	// Message at block 980 > safe(970), also > finalized(950) — must not be published yet.
	msg := testutil.CreateTestMessage(t, 1, chain, defaultDestChain, protocol.FinalityWaitForSafe, 300_000)
	msgID, _ := msg.MessageID()
	task := verifier.VerificationTask{Message: msg, BlockNumber: 980, MessageID: msgID.String()}

	srs.mu.Lock()
	srs.pendingTasks[msgID.String()] = task
	srs.mu.Unlock()

	srs.sendReadyMessages(ctx, latest, safe, finalized)

	srs.mu.RLock()
	defer srs.mu.RUnlock()
	require.Len(t, srs.pendingTasks, 1, "not-ready safe-tag task should remain pending")
	require.Len(t, queue.Published(), 0)
}

func TestSRS_Readiness_SafeTag_FallsBackToFinality_WhenSafeUnavailable(t *testing.T) {
	ctx := context.Background()
	chain := protocol.ChainSelector(1337)
	reader := mocks.NewMockSourceReader(t)

	latest := &protocol.BlockHeader{Number: 1000}
	finalized := &protocol.BlockHeader{Number: 950}

	chainStatusMgr := mocks.NewMockChainStatusManager(t)
	chainStatusMgr.EXPECT().ReadChainStatuses(mock.Anything, mock.Anything).
		Return(map[protocol.ChainSelector]*protocol.ChainStatusInfo{}, nil).Maybe()

	curseDetector := mocks.NewMockCurseCheckerService(t)
	curseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()
	curseDetector.EXPECT().Start(mock.Anything).Return(nil).Maybe()
	curseDetector.EXPECT().Close().Return(nil).Maybe()

	srs, _, queue := newTestSRS(t, chain, reader, chainStatusMgr, curseDetector, 10*time.Millisecond, 5000)

	// Message at block 940 ≤ finalized(950) — safe is nil, fallback must publish it.
	msg := testutil.CreateTestMessage(t, 1, chain, defaultDestChain, protocol.FinalityWaitForSafe, 300_000)
	msgID, _ := msg.MessageID()
	task := verifier.VerificationTask{Message: msg, BlockNumber: 940, MessageID: msgID.String()}

	srs.mu.Lock()
	srs.pendingTasks[msgID.String()] = task
	srs.mu.Unlock()

	srs.sendReadyMessages(ctx, latest, nil /* safe unavailable */, finalized)

	require.Eventually(t, func() bool {
		return len(queue.Published()) == 1
	}, tests.WaitTimeout(t), 10*time.Millisecond)

	require.Equal(t, task.MessageID, queue.Published()[0].MessageID)
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
	curseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()
	curseDetector.EXPECT().Start(mock.Anything).Return(nil).Maybe()
	curseDetector.EXPECT().Close().Return(nil).Maybe()

	srs, mockFC, _ := newTestSRS(t, chain, reader, chainStatusMgr, curseDetector, 10*time.Millisecond, 5000)
	mockFC.EXPECT().IsFinalityViolated().Unset()
	mockFC.EXPECT().IsFinalityViolated().Return(true).Maybe()

	msgs := createTestMessageSentEvents(t, 1, chain, defaultDestChain, []uint64{940, 960})
	task1 := verifier.VerificationTask{Message: msgs[0].Message, BlockNumber: msgs[0].BlockNumber, MessageID: msgs[0].MessageID.String()}
	task2 := verifier.VerificationTask{Message: msgs[1].Message, BlockNumber: msgs[1].BlockNumber, MessageID: msgs[1].MessageID.String()}

	srs.mu.Lock()
	srs.pendingTasks[task1.MessageID] = task1
	srs.sentTasks[task2.MessageID] = task2
	srs.mu.Unlock()

	latest := &protocol.BlockHeader{Number: 1000}
	finalized := &protocol.BlockHeader{Number: 950}
	srs.sendReadyMessages(ctx, latest, nil, finalized)

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
	curseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()
	curseDetector.EXPECT().Start(mock.Anything).Return(nil).Maybe()
	curseDetector.EXPECT().Close().Return(nil).Maybe()

	srs, _, _ := newTestSRS(t, chain, reader, chainStatusMgr, curseDetector, 10*time.Millisecond, 5000)

	msgs := createTestMessageSentEvents(t, 1, chain, defaultDestChain, []uint64{100, 101})
	taskA := verifier.VerificationTask{Message: msgs[0].Message, BlockNumber: msgs[0].BlockNumber, MessageID: msgs[0].MessageID.String()}
	taskB := verifier.VerificationTask{Message: msgs[1].Message, BlockNumber: msgs[1].BlockNumber, MessageID: msgs[1].MessageID.String()}

	srs.mu.Lock()
	srs.pendingTasks = map[string]verifier.VerificationTask{taskA.MessageID: taskA, taskB.MessageID: taskB}
	srs.mu.Unlock()

	// Reorg: only A survives; B is dropped
	srs.addToPendingQueueHandleReorg([]verifier.VerificationTask{taskA}, big.NewInt(100), big.NewInt(101))

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

	srs, err := NewService(
		reader,
		chain,
		chainStatusMgr,
		lggr,
		verifier.SourceConfig{
			PollInterval:           10 * time.Millisecond,
			MaxBlockRange:          5000,
			DisableFinalityChecker: true,
		},
		curseDetector,
		&noopFilter{},
		&testutil.NoopMetricLabeler{},
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
	curseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()
	curseDetector.EXPECT().Start(mock.Anything).Return(nil).Maybe()
	curseDetector.EXPECT().Close().Return(nil).Maybe()

	srs, _, _ := newTestSRS(t, chain, reader, chainStatusMgr, curseDetector, 10*time.Millisecond, 5000)

	// Task A was already sent (in sentTasks)
	msgs := createTestMessageSentEvents(t, 1, chain, defaultDestChain, []uint64{100})
	taskA := verifier.VerificationTask{Message: msgs[0].Message, BlockNumber: msgs[0].BlockNumber, MessageID: msgs[0].MessageID.String()}

	srs.mu.Lock()
	srs.sentTasks = map[string]verifier.VerificationTask{taskA.MessageID: taskA}
	srs.mu.Unlock()

	// New query results: A is gone (reorged after being sent)
	newTasks := []verifier.VerificationTask{}

	srs.addToPendingQueueHandleReorg(newTasks, big.NewInt(100), big.NewInt(100))

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
	curseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()
	curseDetector.EXPECT().Start(mock.Anything).Return(nil).Maybe()
	curseDetector.EXPECT().Close().Return(nil).Maybe()

	srs, _, _ := newTestSRS(t, chain, reader, chainStatusMgr, curseDetector, 10*time.Millisecond, 5000)

	// Create message with custom finality of 5 blocks
	const customFinality protocol.Finality = 5
	msg := testutil.CreateTestMessage(t, 10, chain, defaultDestChain, customFinality, 300_000)
	msgID, _ := msg.MessageID()
	task := verifier.VerificationTask{
		Message:     msg,
		BlockNumber: 190,
		MessageID:   msgID.String(),
	}

	// Mark this seqNum as reorged
	srs.reorgTracker.Track(defaultDestChain, msg.SequenceNumber)

	latestBlock := big.NewInt(200)    // msgBlock(190) + finality(5) = 195 <= 200, custom finality would be met
	finalizedBlock := big.NewInt(180) // msgBlock(190) > finalized(180)

	// Even though custom finality (195 <= 200) would be met, reorg tracking should require finalization
	ready := srs.isMessageReadyForVerification(task, latestBlock, nil, finalizedBlock)

	require.False(t, ready, "reorged message should wait for finalization even if custom finality is met")

	// Now set finalized block past message block
	finalizedBlock = big.NewInt(195)
	ready = srs.isMessageReadyForVerification(task, latestBlock, nil, finalizedBlock)

	require.True(t, ready, "reorged message should be ready once finalized")
}

func TestSRS_NonReorgedMessage_UsesCustomFinality(t *testing.T) {
	chain := protocol.ChainSelector(1337)
	reader := mocks.NewMockSourceReader(t)
	chainStatusMgr := mocks.NewMockChainStatusManager(t)

	curseDetector := mocks.NewMockCurseCheckerService(t)
	curseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()
	curseDetector.EXPECT().Start(mock.Anything).Return(nil).Maybe()
	curseDetector.EXPECT().Close().Return(nil).Maybe()

	srs, _, _ := newTestSRS(t, chain, reader, chainStatusMgr, curseDetector, 10*time.Millisecond, 5000)

	// Create message with custom finality of 5 blocks
	const customFinality protocol.Finality = 5
	msg := testutil.CreateTestMessage(t, 10, chain, defaultDestChain, customFinality, 300_000)
	msgID, _ := msg.MessageID()
	task := verifier.VerificationTask{
		Message:     msg,
		BlockNumber: 190,
		MessageID:   msgID.String(),
	}

	// Don't mark this seqNum as reorged

	latestBlock := big.NewInt(200)    // msgBlock(190) + finality(5) = 195 <= 200
	finalizedBlock := big.NewInt(180) // msgBlock(190) > finalized(180)

	// Custom finality should be used (no reorg tracking)
	ready := srs.isMessageReadyForVerification(task, latestBlock, nil, finalizedBlock)

	require.True(t, ready, "non-reorged message should use custom finality")
}

func TestSRS_ReorgedMessage_DifferentDest_UsesCustomFinality(t *testing.T) {
	chain := protocol.ChainSelector(1337)
	dest1 := protocol.ChainSelector(100)
	dest2 := protocol.ChainSelector(200)
	reader := mocks.NewMockSourceReader(t)
	chainStatusMgr := mocks.NewMockChainStatusManager(t)

	curseDetector := mocks.NewMockCurseCheckerService(t)
	curseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()
	curseDetector.EXPECT().Start(mock.Anything).Return(nil).Maybe()
	curseDetector.EXPECT().Close().Return(nil).Maybe()

	srs, _, _ := newTestSRS(t, chain, reader, chainStatusMgr, curseDetector, 10*time.Millisecond, 5000)

	// Mark seqNum 10 for dest1 as reorged
	srs.reorgTracker.Track(dest1, 10)

	// Create message with same seqNum 10 but for dest2 (different lane)
	const customFinality protocol.Finality = 5
	msg := testutil.CreateTestMessage(t, 10, chain, dest2, customFinality, 300_000)
	msgID, _ := msg.MessageID()
	task := verifier.VerificationTask{
		Message:     msg,
		BlockNumber: 190,
		MessageID:   msgID.String(),
	}

	latestBlock := big.NewInt(200)
	finalizedBlock := big.NewInt(180)

	// Message to dest2 should use custom finality (dest1's reorg doesn't affect it)
	ready := srs.isMessageReadyForVerification(task, latestBlock, nil, finalizedBlock)

	require.True(t, ready, "message to different dest should not be affected by other dest's reorg tracking")
}

func TestSRS_ReorgTracker_RemovedAfterFinalization(t *testing.T) {
	ctx := context.Background()
	chain := protocol.ChainSelector(1337)
	reader := mocks.NewMockSourceReader(t)
	chainStatusMgr := mocks.NewMockChainStatusManager(t)

	curseDetector := mocks.NewMockCurseCheckerService(t)
	curseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()
	curseDetector.EXPECT().Start(mock.Anything).Return(nil).Maybe()
	curseDetector.EXPECT().Close().Return(nil).Maybe()

	srs, mockFC, queue := newTestSRS(t, chain, reader, chainStatusMgr, curseDetector, 10*time.Millisecond, 5000)
	mockFC.EXPECT().UpdateFinalized(mock.Anything, mock.Anything).Return(nil).Maybe()
	mockFC.EXPECT().IsFinalityViolated().Return(false).Maybe()

	// Create a message and mark its seqNum as reorged
	msg := testutil.CreateTestMessage(t, 10, chain, defaultDestChain, 0, 300_000)
	msgID, _ := msg.MessageID()
	task := verifier.VerificationTask{
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

	srs.sendReadyMessages(ctx, latest, nil, finalized)

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
	curseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()
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

	// Large range: 100 to 12000 (11900 blocks, > 1500 default)
	latest := &protocol.BlockHeader{Number: 12000}
	finalized := &protocol.BlockHeader{Number: 11000}

	reader.EXPECT().
		LatestAndFinalizedBlock(mock.Anything).
		Return(latest, finalized, nil).
		Maybe()

	// Split events so each falls in the chunk matching its block number.
	// maxBlockRange=1500: chunks are [99,1599],[1600,3100],[3101,4601],[4602,6102],[6103,7603],[7604,9104],[9105,10605],[10606,nil]
	event500 := createTestMessageSentEvents(t, 1, chain, defaultDestChain, []uint64{500})
	event2000 := createTestMessageSentEvents(t, 2, chain, defaultDestChain, []uint64{2000})
	events2 := createTestMessageSentEvents(t, 10, chain, defaultDestChain, []uint64{6000})
	events3 := createTestMessageSentEvents(t, 20, chain, defaultDestChain, []uint64{11500})

	nilBigInt := mock.MatchedBy(func(arg *big.Int) bool { return arg == nil })

	// chunk 1: [99, 1599]  (99 + 1500 = 1599) — block 500 falls here
	reader.EXPECT().
		FetchMessageSentEvents(mock.Anything, big.NewInt(99), big.NewInt(1599)).
		Return(event500, nil).
		Once()
	// chunk 2: [1600, 3100]  (1600 + 1500 = 3100) — block 2000 falls here
	reader.EXPECT().
		FetchMessageSentEvents(mock.Anything, big.NewInt(1600), big.NewInt(3100)).
		Return(event2000, nil).
		Once()
	// chunk 3: [3101, 4601]
	reader.EXPECT().
		FetchMessageSentEvents(mock.Anything, big.NewInt(3101), big.NewInt(4601)).
		Return([]protocol.MessageSentEvent{}, nil).
		Once()
	// chunk 4: [4602, 6102]  — block 6000 falls here
	reader.EXPECT().
		FetchMessageSentEvents(mock.Anything, big.NewInt(4602), big.NewInt(6102)).
		Return(events2, nil).
		Once()
	// chunk 5: [6103, 7603]
	reader.EXPECT().
		FetchMessageSentEvents(mock.Anything, big.NewInt(6103), big.NewInt(7603)).
		Return([]protocol.MessageSentEvent{}, nil).
		Once()
	// chunk 6: [7604, 9104]
	reader.EXPECT().
		FetchMessageSentEvents(mock.Anything, big.NewInt(7604), big.NewInt(9104)).
		Return([]protocol.MessageSentEvent{}, nil).
		Once()
	// chunk 7: [9105, 10605]
	reader.EXPECT().
		FetchMessageSentEvents(mock.Anything, big.NewInt(9105), big.NewInt(10605)).
		Return([]protocol.MessageSentEvent{}, nil).
		Once()
	// chunk 8: [10606, nil]  (10606 + 1500 = 12106 >= 12000) — block 11500 falls here
	reader.EXPECT().
		FetchMessageSentEvents(mock.Anything, big.NewInt(10606), nilBigInt).
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
	curseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()
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
	curseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()
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
	curseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()
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
	curseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()
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
	curseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()
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
	curseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()
	curseDetector.EXPECT().Start(mock.Anything).Return(nil).Maybe()
	curseDetector.EXPECT().Close().Return(nil).Maybe()

	srs, _, _ := newTestSRS(t, chain, reader, chainStatusMgr, curseDetector, 10*time.Millisecond, 5000)
	srs.lastProcessedFinalizedBlock.Store(big.NewInt(99))

	// Pre-seed a pending task
	existingEvent := createTestMessageSentEvents(t, 1, chain, defaultDestChain, []uint64{100})
	existingTask := verifier.VerificationTask{
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
	curseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()
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
	curseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()
	curseDetector.EXPECT().Start(mock.Anything).Return(nil).Maybe()
	curseDetector.EXPECT().Close().Return(nil).Maybe()

	srs, _, _ := newTestSRS(t, chain, reader, chainStatusMgr, curseDetector, 10*time.Millisecond, 5000)
	srs.lastProcessedFinalizedBlock.Store(big.NewInt(100))

	srs.processEventCycle(ctx, latest, finalized)

	// Progress updates to current finalized (safe restart point)
	require.Equal(t, int64(50), srs.lastProcessedFinalizedBlock.Load().Int64(),
		"progress should update to finalized after querying all blocks")
}

// TestSRS_EventMonitoringLoop_ContinuesAfterPanic verifies that the event monitoring loop
// continues processing after recovering from a panic in one iteration.
func TestSRS_EventMonitoringLoop_ContinuesAfterPanic(t *testing.T) {
	chain := protocol.ChainSelector(1337)

	reader := mocks.NewMockSourceReader(t)
	chainStatusMgr := mocks.NewMockChainStatusManager(t)
	curseDetector := mocks.NewMockCurseCheckerService(t)

	chainStatusMgr.EXPECT().
		ReadChainStatuses(mock.Anything, mock.Anything).
		Return(map[protocol.ChainSelector]*protocol.ChainStatusInfo{
			chain: {
				ChainSelector:        chain,
				FinalizedBlockHeight: big.NewInt(100),
				Disabled:             false,
			},
		}, nil).
		Maybe()

	latest := &protocol.BlockHeader{Number: 200}
	finalized := &protocol.BlockHeader{Number: 150}

	// Track how many times LatestAndFinalizedBlock is called
	callCount := 0
	var mu sync.Mutex

	reader.EXPECT().
		LatestAndFinalizedBlock(mock.Anything).
		Run(func(_ context.Context) {
			mu.Lock()
			defer mu.Unlock()
			callCount++
			// Simulate panic on the 2nd call
			if callCount == 2 {
				panic("simulated panic in readyToQuery")
			}
		}).
		Return(latest, finalized, nil).
		Maybe()
	reader.EXPECT().LatestSafeBlock(mock.Anything).Return(nil, nil).Maybe()

	reader.EXPECT().
		FetchMessageSentEvents(mock.Anything, mock.Anything, mock.Anything).
		Return([]protocol.MessageSentEvent{}, nil).
		Maybe()

	curseDetector.EXPECT().
		IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).
		Return(false, nil).
		Maybe()

	// Create SRS with fast poll interval for testing
	srs, mockFC, _ := newTestSRS(t, chain, reader, chainStatusMgr, curseDetector, 50*time.Millisecond, 5000)
	mockFC.EXPECT().UpdateFinalized(mock.Anything, mock.Anything).Return(nil).Maybe()
	mockFC.EXPECT().IsFinalityViolated().Return(false).Maybe()

	// Start the service
	err := srs.Start(t.Context())
	require.NoError(t, err)
	defer func() {
		require.NoError(t, srs.Close())
	}()

	// Wait for multiple poll cycles to complete
	// This gives time for:
	// - 1st call: successful processing
	// - 2nd call: panic and recovery
	// - 3rd+ calls: continued processing after panic
	time.Sleep(300 * time.Millisecond)

	// Verify that the loop continued processing after the panic
	mu.Lock()
	actualCallCount := callCount
	mu.Unlock()

	// We should have at least 3 calls:
	// 1. First successful call
	// 2. Call that panicked
	// 3. Call(s) after recovery proving the loop continued
	assert.GreaterOrEqual(t, actualCallCount, 3,
		"eventMonitoringLoop should continue processing after panic recovery")

	t.Logf("LatestAndFinalizedBlock called %d times (including 1 panic)", actualCallCount)
}

func TestSRS_EventMonitoringLoop_PanicInProcessEventCycle(t *testing.T) {
	chain := protocol.ChainSelector(1337)

	reader := mocks.NewMockSourceReader(t)
	chainStatusMgr := mocks.NewMockChainStatusManager(t)
	curseDetector := mocks.NewMockCurseCheckerService(t)

	chainStatusMgr.EXPECT().
		ReadChainStatuses(mock.Anything, mock.Anything).
		Return(map[protocol.ChainSelector]*protocol.ChainStatusInfo{
			chain: {
				ChainSelector:        chain,
				FinalizedBlockHeight: big.NewInt(100),
				Disabled:             false,
			},
		}, nil).
		Maybe()

	latest := &protocol.BlockHeader{Number: 200}
	finalized := &protocol.BlockHeader{Number: 150}

	reader.EXPECT().
		LatestAndFinalizedBlock(mock.Anything).
		Return(latest, finalized, nil).
		Maybe()
	reader.EXPECT().LatestSafeBlock(mock.Anything).Return(nil, nil).Maybe()

	// Track how many times FetchMessageSentEvents is called
	fetchCallCount := 0
	var mu sync.Mutex

	reader.EXPECT().
		FetchMessageSentEvents(mock.Anything, mock.Anything, mock.Anything).
		Run(func(_ context.Context, _, _ *big.Int) {
			mu.Lock()
			defer mu.Unlock()
			fetchCallCount++
			// Simulate panic on the 2nd fetch call
			if fetchCallCount == 2 {
				panic("simulated panic in processEventCycle")
			}
		}).
		Return([]protocol.MessageSentEvent{}, nil).
		Maybe()

	curseDetector.EXPECT().
		IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).
		Return(false, nil).
		Maybe()

	// Create SRS with fast poll interval for testing
	srs, mockFC, _ := newTestSRS(t, chain, reader, chainStatusMgr, curseDetector, 50*time.Millisecond, 5000)
	mockFC.EXPECT().UpdateFinalized(mock.Anything, mock.Anything).Return(nil).Maybe()
	mockFC.EXPECT().IsFinalityViolated().Return(false).Maybe()

	// Start the service
	err := srs.Start(t.Context())
	require.NoError(t, err)
	defer func() {
		require.NoError(t, srs.Close())
	}()

	// Wait for multiple poll cycles
	time.Sleep(300 * time.Millisecond)

	// Verify that the loop continued processing after the panic
	mu.Lock()
	actualFetchCount := fetchCallCount
	mu.Unlock()

	// Should have at least 3 fetch calls (before, panic, after)
	assert.GreaterOrEqual(t, actualFetchCount, 3,
		"eventMonitoringLoop should continue processing after panic in processEventCycle")

	t.Logf("FetchMessageSentEvents called %d times (including 1 panic)", actualFetchCount)
}

// nestedReader composes a mockery-generated SourceReader and services.Service mock.
type nestedReader struct {
	*mocks.MockSourceReader
	*mocks.MockService
}

// allowNestedPollLoop registers no-op expectations for the read calls the verifier's poll loop
// makes when it actually runs. only care about nested Start/Close ordering here.
func allowNestedPollLoop(sr *mocks.MockSourceReader, curse *mocks.MockCurseCheckerService) {
	sr.EXPECT().LatestAndFinalizedBlock(mock.Anything).Return(
		&protocol.BlockHeader{Number: 200}, &protocol.BlockHeader{Number: 150}, nil).Maybe()
	sr.EXPECT().LatestSafeBlock(mock.Anything).Return(nil, nil).Maybe()
	sr.EXPECT().FetchMessageSentEvents(mock.Anything, mock.Anything, mock.Anything).Return(nil, nil).Maybe()
	curse.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()
}

// TestSRS_NestedSourceReader verifies that the verifier Service drives the optional
// services.Service lifecycle on chain readers that own long-lived background workers
// (e.g. Solana logpoller). Pure pull readers (e.g. EVM) skip the lifecycle branch since
// they don't satisfy services.Service.
func TestSRS_NestedSourceReader(t *testing.T) {
	ctx := context.Background()
	chain := protocol.ChainSelector(1337)

	t.Run("happy_path", func(t *testing.T) {
		t.Parallel()
		sr := mocks.NewMockSourceReader(t)
		svc := mocks.NewMockService(t)
		w := &nestedReader{MockSourceReader: sr, MockService: svc}
		mgr := mocks.NewMockChainStatusManager(t)
		curse := mocks.NewMockCurseCheckerService(t)

		// nested Start runs once before init; nested Close runs once on SRS Close.
		svc.EXPECT().Start(mock.Anything).Return(nil).Once()
		svc.EXPECT().Close().Return(nil).Once()
		// init succeeds so the poll goroutine starts.
		mgr.EXPECT().ReadChainStatuses(mock.Anything, mock.Anything).Return(map[protocol.ChainSelector]*protocol.ChainStatusInfo{
			chain: {ChainSelector: chain, FinalizedBlockHeight: big.NewInt(100)},
		}, nil).Times(1)
		allowNestedPollLoop(sr, curse)

		srs, _, _ := newTestSRS(t, chain, w, mgr, curse, 50*time.Millisecond, 5000)
		require.NoError(t, srs.Start(ctx))
		// Between Start and Close: nested Start ran exactly once, nested Close not yet.
		svc.AssertNumberOfCalls(t, "Start", 1)
		svc.AssertNumberOfCalls(t, "Close", 0)
		require.NoError(t, srs.Close())
		// SRS Close stops the loop then calls nested Close once (asserted by Once() via t.Cleanup).
	})

	t.Run("close_after_init_fails", func(t *testing.T) {
		t.Parallel()
		sr := mocks.NewMockSourceReader(t)
		svc := mocks.NewMockService(t)
		w := &nestedReader{MockSourceReader: sr, MockService: svc}
		mgr := mocks.NewMockChainStatusManager(t)
		curse := mocks.NewMockCurseCheckerService(t)

		initErr := errors.New("read chain status failed")
		// nested Start succeeds; ReadChainStatuses fails before the poll loop is spawned;
		// verifier unwinds with nested Close.
		svc.EXPECT().Start(mock.Anything).Return(nil).Once()
		svc.EXPECT().Close().Return(nil).Once()
		mgr.EXPECT().ReadChainStatuses(mock.Anything, mock.Anything).Return(nil, initErr).Times(1)
		// Start returns the init error; verifier unwinds with nested Close.
		srs, _, _ := newTestSRS(t, chain, w, mgr, curse, time.Second, 5000)
		require.ErrorIs(t, srs.Start(ctx), initErr)
	})

	t.Run("nested_start_err", func(t *testing.T) {
		t.Parallel()
		sr := mocks.NewMockSourceReader(t)
		svc := mocks.NewMockService(t)
		w := &nestedReader{MockSourceReader: sr, MockService: svc}
		mgr := mocks.NewMockChainStatusManager(t)
		curse := mocks.NewMockCurseCheckerService(t)

		nestErr := errors.New("nested start failed")
		// nested Start fails; verifier must NOT call nested Close
		svc.EXPECT().Start(mock.Anything).Return(nestErr).Once()

		srs, _, _ := newTestSRS(t, chain, w, mgr, curse, time.Second, 5000)
		require.Same(t, w, srs.sourceReader)
		err := srs.Start(ctx)
		// failure is wrapped; inner error is still observable via errors.Is.
		require.Error(t, err)
		assert.Contains(t, err.Error(), "start chain source reader service")
		require.ErrorIs(t, err, nestErr)
		// Close must not have been called
		svc.AssertNumberOfCalls(t, "Close", 0)
	})
}

// ----------------------
// Partial Read Tests
//
// These tests cover the behavior introduced by returning accumulated events on
// fetch error in loadEvents, and the min-progress formula in processEventCycle:
//
//   newBlock = min(lastQueriedBlock, finalized)
//
//   • nil lastQueriedBlock (full success)     → finalized
//   • lastQueriedBlock < finalized (partial)  → lastQueriedBlock (chunk toBlock)
//   • lastQueriedBlock ≥ finalized (partial)  → finalized (capped — new behavior)
//   • lastQueriedBlock == fromBlock (failure) → fromBlock (no progress)
// ----------------------

// TestSRS_PartialRead_EventsFromSuccessfulChunksQueued verifies that when a
// multi-chunk fetch fails partway through, the events already retrieved from
// the completed chunks are still queued as pending tasks — not discarded.
func TestSRS_PartialRead_EventsFromSuccessfulChunksQueued(t *testing.T) {
	ctx := context.Background()
	chain := protocol.ChainSelector(1337)

	reader := mocks.NewMockSourceReader(t)

	// maxBlockRange=500 splits [100, 700) into two chunks: [100,600] and [601,nil].
	latest := &protocol.BlockHeader{Number: 700}
	finalized := &protocol.BlockHeader{Number: 600}
	reader.EXPECT().LatestAndFinalizedBlock(mock.Anything).Return(latest, finalized, nil).Maybe()

	eventsChunk1 := createTestMessageSentEvents(t, 1, chain, defaultDestChain, []uint64{200, 400})
	reader.EXPECT().
		FetchMessageSentEvents(mock.Anything, big.NewInt(100), big.NewInt(600)).
		Return(eventsChunk1, nil).
		Once()

	nilBigInt := mock.MatchedBy(func(b *big.Int) bool { return b == nil })
	reader.EXPECT().
		FetchMessageSentEvents(mock.Anything, big.NewInt(601), nilBigInt).
		Return(nil, assert.AnError).
		Once()

	chainStatusMgr := mocks.NewMockChainStatusManager(t)
	chainStatusMgr.EXPECT().ReadChainStatuses(mock.Anything, mock.Anything).
		Return(map[protocol.ChainSelector]*protocol.ChainStatusInfo{}, nil).Maybe()

	curseDetector := mocks.NewMockCurseCheckerService(t)
	curseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()
	curseDetector.EXPECT().Start(mock.Anything).Return(nil).Maybe()
	curseDetector.EXPECT().Close().Return(nil).Maybe()

	srs, _, _ := newTestSRS(t, chain, reader, chainStatusMgr, curseDetector, 10*time.Millisecond, 500)
	srs.lastProcessedFinalizedBlock.Store(big.NewInt(100))

	srs.processEventCycle(ctx, latest, finalized)

	srs.mu.RLock()
	defer srs.mu.RUnlock()

	require.Len(t, srs.pendingTasks, len(eventsChunk1),
		"events from the successful chunk should be queued despite the later chunk failure")
	for _, ev := range eventsChunk1 {
		_, ok := srs.pendingTasks[ev.MessageID.String()]
		require.True(t, ok, "task for message %s should be in pending queue", ev.MessageID.String())
	}
}

// TestSRS_PartialRead_ProgressAdvancesToLastSuccessfulChunkBound verifies that
// when a multi-chunk fetch partially fails, progress advances to the toBlock of
// the last successfully completed chunk — not the finalized block and not the
// block of the final event within the chunk.
func TestSRS_PartialRead_ProgressAdvancesToLastSuccessfulChunkBound(t *testing.T) {
	ctx := context.Background()
	chain := protocol.ChainSelector(1337)

	reader := mocks.NewMockSourceReader(t)

	// maxBlockRange=500 splits [100, 700) into [100,600] and [601,nil].
	latest := &protocol.BlockHeader{Number: 700}
	finalized := &protocol.BlockHeader{Number: 600}
	reader.EXPECT().LatestAndFinalizedBlock(mock.Anything).Return(latest, finalized, nil).Maybe()

	// Events at blocks 200 and 400 — the chunk boundary (toBlock) is 600.
	eventsChunk1 := createTestMessageSentEvents(t, 1, chain, defaultDestChain, []uint64{200, 400})
	reader.EXPECT().
		FetchMessageSentEvents(mock.Anything, big.NewInt(100), big.NewInt(600)).
		Return(eventsChunk1, nil).
		Once()

	nilBigInt := mock.MatchedBy(func(b *big.Int) bool { return b == nil })
	reader.EXPECT().
		FetchMessageSentEvents(mock.Anything, big.NewInt(601), nilBigInt).
		Return(nil, assert.AnError).
		Once()

	chainStatusMgr := mocks.NewMockChainStatusManager(t)
	chainStatusMgr.EXPECT().ReadChainStatuses(mock.Anything, mock.Anything).
		Return(map[protocol.ChainSelector]*protocol.ChainStatusInfo{}, nil).Maybe()

	curseDetector := mocks.NewMockCurseCheckerService(t)
	curseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()
	curseDetector.EXPECT().Start(mock.Anything).Return(nil).Maybe()
	curseDetector.EXPECT().Close().Return(nil).Maybe()

	srs, _, _ := newTestSRS(t, chain, reader, chainStatusMgr, curseDetector, 10*time.Millisecond, 500)
	srs.lastProcessedFinalizedBlock.Store(big.NewInt(100))

	srs.processEventCycle(ctx, latest, finalized)

	// err != nil, finalQueriedBlock (chunk 1 toBlock = 600) >= fromBlock (100)
	// → partial-read branch → progress = 600.
	// Progress must NOT stay at fromBlock (100) as if it were a total failure.
	require.Equal(t, int64(600), srs.lastProcessedFinalizedBlock.Load().Int64(),
		"progress should advance to the toBlock of the last successful chunk, not stay at fromBlock")
}

// TestSRS_PartialRead_MultipleChunksSucceedBeforeFailure verifies that events from
// all chunks that complete before the first failure are accumulated and queued,
// and that progress advances to the highest block from those combined results.
func TestSRS_PartialRead_MultipleChunksSucceedBeforeFailure(t *testing.T) {
	ctx := context.Background()
	chain := protocol.ChainSelector(1337)

	reader := mocks.NewMockSourceReader(t)

	// maxBlockRange=300 splits [100, 1000) into three chunks:
	// [100,400], [401,701], [702,nil].
	latest := &protocol.BlockHeader{Number: 1000}
	finalized := &protocol.BlockHeader{Number: 800}
	reader.EXPECT().LatestAndFinalizedBlock(mock.Anything).Return(latest, finalized, nil).Maybe()

	eventsChunk1 := createTestMessageSentEvents(t, 1, chain, defaultDestChain, []uint64{150, 300})
	eventsChunk2 := createTestMessageSentEvents(t, 10, chain, defaultDestChain, []uint64{500, 650})
	nilBigInt := mock.MatchedBy(func(b *big.Int) bool { return b == nil })

	reader.EXPECT().
		FetchMessageSentEvents(mock.Anything, big.NewInt(100), big.NewInt(400)).
		Return(eventsChunk1, nil).
		Once()
	reader.EXPECT().
		FetchMessageSentEvents(mock.Anything, big.NewInt(401), big.NewInt(701)).
		Return(eventsChunk2, nil).
		Once()
	// Third chunk fails — no further chunks should be fetched.
	reader.EXPECT().
		FetchMessageSentEvents(mock.Anything, big.NewInt(702), nilBigInt).
		Return(nil, assert.AnError).
		Once()

	chainStatusMgr := mocks.NewMockChainStatusManager(t)
	chainStatusMgr.EXPECT().ReadChainStatuses(mock.Anything, mock.Anything).
		Return(map[protocol.ChainSelector]*protocol.ChainStatusInfo{}, nil).Maybe()

	curseDetector := mocks.NewMockCurseCheckerService(t)
	curseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()
	curseDetector.EXPECT().Start(mock.Anything).Return(nil).Maybe()
	curseDetector.EXPECT().Close().Return(nil).Maybe()

	srs, _, _ := newTestSRS(t, chain, reader, chainStatusMgr, curseDetector, 10*time.Millisecond, 300)
	srs.lastProcessedFinalizedBlock.Store(big.NewInt(100))

	srs.processEventCycle(ctx, latest, finalized)

	srs.mu.RLock()
	defer srs.mu.RUnlock()

	allExpected := append(eventsChunk1, eventsChunk2...)
	require.Len(t, srs.pendingTasks, len(allExpected),
		"events from all chunks that completed before the failure should be queued")
	for _, ev := range allExpected {
		_, ok := srs.pendingTasks[ev.MessageID.String()]
		require.True(t, ok, "task for message %s should be in pending queue", ev.MessageID.String())
	}

	// finalQueriedBlock = toBlock of last successful chunk = 701 (chunk 2 boundary).
	// err != nil, 701 >= fromBlock(100) → partial-read branch → progress=701.
	require.Equal(t, int64(701), srs.lastProcessedFinalizedBlock.Load().Int64(),
		"progress should advance to the toBlock of the last successful chunk, not to finalized or last event block")
}

// TestSRS_PartialRead_TotalFailureDoesNotAdvanceProgress verifies that when the
// very first chunk fails (returning no events), progress stays at fromBlock so
// the identical range is retried on the next tick without losing any ground.
func TestSRS_PartialRead_TotalFailureDoesNotAdvanceProgress(t *testing.T) {
	ctx := context.Background()
	chain := protocol.ChainSelector(1337)

	reader := mocks.NewMockSourceReader(t)

	latest := &protocol.BlockHeader{Number: 700}
	finalized := &protocol.BlockHeader{Number: 600}
	reader.EXPECT().LatestAndFinalizedBlock(mock.Anything).Return(latest, finalized, nil).Maybe()

	// Chunk 1 fails immediately — no events, no subsequent chunk calls.
	reader.EXPECT().
		FetchMessageSentEvents(mock.Anything, big.NewInt(100), big.NewInt(600)).
		Return(nil, assert.AnError).
		Once()
	// Chunk 2 must NOT be called: testify will fail the test on any unexpected call.

	chainStatusMgr := mocks.NewMockChainStatusManager(t)
	chainStatusMgr.EXPECT().ReadChainStatuses(mock.Anything, mock.Anything).
		Return(map[protocol.ChainSelector]*protocol.ChainStatusInfo{}, nil).Maybe()

	curseDetector := mocks.NewMockCurseCheckerService(t)
	curseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()
	curseDetector.EXPECT().Start(mock.Anything).Return(nil).Maybe()
	curseDetector.EXPECT().Close().Return(nil).Maybe()

	srs, _, _ := newTestSRS(t, chain, reader, chainStatusMgr, curseDetector, 10*time.Millisecond, 500)
	srs.lastProcessedFinalizedBlock.Store(big.NewInt(100))

	srs.processEventCycle(ctx, latest, finalized)

	srs.mu.RLock()
	defer srs.mu.RUnlock()

	require.Len(t, srs.pendingTasks, 0, "no tasks should be queued when the first chunk fails")
	require.Equal(t, int64(100), srs.lastProcessedFinalizedBlock.Load().Int64(),
		"progress must not advance when the fetch fails with no events; same range retried next tick")
}

// TestSRS_PartialRead_SuccessfulReadAlwaysAdvancesToFinalized verifies that when
// all chunks complete without error, progress advances to finalized even if the
// last event block is lower than finalized (e.g. quiet period on a chain).
func TestSRS_PartialRead_SuccessfulReadAlwaysAdvancesToFinalized(t *testing.T) {
	ctx := context.Background()
	chain := protocol.ChainSelector(1337)

	reader := mocks.NewMockSourceReader(t)

	latest := &protocol.BlockHeader{Number: 300}
	finalized := &protocol.BlockHeader{Number: 200}
	reader.EXPECT().LatestAndFinalizedBlock(mock.Anything).Return(latest, finalized, nil).Maybe()

	// Single chunk [100, nil]; event at block 120 — well below finalized (200).
	events := createTestMessageSentEvents(t, 1, chain, defaultDestChain, []uint64{120})
	nilBigInt := mock.MatchedBy(func(b *big.Int) bool { return b == nil })
	reader.EXPECT().
		FetchMessageSentEvents(mock.Anything, big.NewInt(100), nilBigInt).
		Return(events, nil).
		Once()

	chainStatusMgr := mocks.NewMockChainStatusManager(t)
	chainStatusMgr.EXPECT().ReadChainStatuses(mock.Anything, mock.Anything).
		Return(map[protocol.ChainSelector]*protocol.ChainStatusInfo{}, nil).Maybe()

	curseDetector := mocks.NewMockCurseCheckerService(t)
	curseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()
	curseDetector.EXPECT().Start(mock.Anything).Return(nil).Maybe()
	curseDetector.EXPECT().Close().Return(nil).Maybe()

	srs, _, _ := newTestSRS(t, chain, reader, chainStatusMgr, curseDetector, 10*time.Millisecond, 5000)
	srs.lastProcessedFinalizedBlock.Store(big.NewInt(100))

	srs.processEventCycle(ctx, latest, finalized)

	// No error → always advance to finalized, regardless of where events landed.
	require.Equal(t, int64(200), srs.lastProcessedFinalizedBlock.Load().Int64(),
		"successful read must advance progress to finalized, not just to the last event block")

	srs.mu.RLock()
	defer srs.mu.RUnlock()
	require.Len(t, srs.pendingTasks, 1, "the single event should be queued")
}

// TestSRS_PartialRead_ProgressCapsAtFinalizedWhenChunkBoundExceedsIt verifies that
// when a partial read's last successful chunk ends above the finalized block, progress
// is capped at finalized — not advanced past it. This prevents lastProcessedFinalizedBlock
// from leaping into non-finalized territory.
func TestSRS_PartialRead_ProgressCapsAtFinalizedWhenChunkBoundExceedsIt(t *testing.T) {
	ctx := context.Background()
	chain := protocol.ChainSelector(1337)

	reader := mocks.NewMockSourceReader(t)

	// maxBlockRange=400 splits [100, 1000) into chunks [100,500], [501,901], [902,nil].
	// finalized is 600, so the successful chunk 2 boundary (901) exceeds finalized.
	latest := &protocol.BlockHeader{Number: 1000}
	finalized := &protocol.BlockHeader{Number: 600}
	reader.EXPECT().LatestAndFinalizedBlock(mock.Anything).Return(latest, finalized, nil).Maybe()

	eventsChunk1 := createTestMessageSentEvents(t, 1, chain, defaultDestChain, []uint64{200})
	eventsChunk2 := createTestMessageSentEvents(t, 10, chain, defaultDestChain, []uint64{700})
	nilBigInt := mock.MatchedBy(func(b *big.Int) bool { return b == nil })

	reader.EXPECT().
		FetchMessageSentEvents(mock.Anything, big.NewInt(100), big.NewInt(500)).
		Return(eventsChunk1, nil).Once()
	reader.EXPECT().
		FetchMessageSentEvents(mock.Anything, big.NewInt(501), big.NewInt(901)).
		Return(eventsChunk2, nil).Once()
	// Third chunk fails — lastQueriedBlock lands at 901, which is > finalized (600).
	reader.EXPECT().
		FetchMessageSentEvents(mock.Anything, big.NewInt(902), nilBigInt).
		Return(nil, assert.AnError).Once()

	chainStatusMgr := mocks.NewMockChainStatusManager(t)
	chainStatusMgr.EXPECT().ReadChainStatuses(mock.Anything, mock.Anything).
		Return(map[protocol.ChainSelector]*protocol.ChainStatusInfo{}, nil).Maybe()

	curseDetector := mocks.NewMockCurseCheckerService(t)
	curseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()
	curseDetector.EXPECT().Start(mock.Anything).Return(nil).Maybe()
	curseDetector.EXPECT().Close().Return(nil).Maybe()

	srs, _, _ := newTestSRS(t, chain, reader, chainStatusMgr, curseDetector, 10*time.Millisecond, 400)
	srs.lastProcessedFinalizedBlock.Store(big.NewInt(100))

	srs.processEventCycle(ctx, latest, finalized)

	// lastQueriedBlock = 901 > finalized = 600 → min(901, 600) = 600.
	// Progress must NOT advance past finalized even though we successfully fetched beyond it.
	require.Equal(t, int64(600), srs.lastProcessedFinalizedBlock.Load().Int64(),
		"progress must be capped at finalized when the last successful chunk boundary exceeds it")

	srs.mu.RLock()
	defer srs.mu.RUnlock()

	allExpected := append(eventsChunk1, eventsChunk2...)
	require.Len(t, srs.pendingTasks, len(allExpected),
		"events from both successful chunks should still be queued despite capping progress at finalized")
}

// ----------------------
// Bounded Reorg Window Tests
//
// These tests cover the toBlock guard introduced in addToPendingQueueHandleReorg:
// a task is only considered for reorg removal when its block falls within
// [fromBlock, toBlock]. Tasks at blocks strictly above toBlock are left untouched,
// and a nil toBlock is treated as unbounded (covers any block ≥ fromBlock).
// ----------------------

// TestSRS_Reorg_TasksBeyondToBlockNotDropped verifies that an existing pending
// task whose block is strictly above toBlock is preserved even though it does not
// appear in the new event set, because it lies outside the queried window.
func TestSRS_Reorg_TasksBeyondToBlockNotDropped(t *testing.T) {
	chain := protocol.ChainSelector(1337)
	reader := mocks.NewMockSourceReader(t)
	chainStatusMgr := mocks.NewMockChainStatusManager(t)

	curseDetector := mocks.NewMockCurseCheckerService(t)
	curseDetector.EXPECT().Start(mock.Anything).Return(nil).Maybe()
	curseDetector.EXPECT().Close().Return(nil).Maybe()

	srs, _, _ := newTestSRS(t, chain, reader, chainStatusMgr, curseDetector, 10*time.Millisecond, 5000)

	// Task at block 200 sits beyond the queried range [100, 150].
	msgs := createTestMessageSentEvents(t, 1, chain, defaultDestChain, []uint64{200})
	taskFuture := verifier.VerificationTask{
		Message:     msgs[0].Message,
		BlockNumber: msgs[0].BlockNumber,
		MessageID:   msgs[0].MessageID.String(),
	}

	srs.mu.Lock()
	srs.pendingTasks = map[string]verifier.VerificationTask{taskFuture.MessageID: taskFuture}
	srs.mu.Unlock()

	// New query over [100, 150] returns nothing — taskFuture was NOT in this range.
	srs.addToPendingQueueHandleReorg([]verifier.VerificationTask{}, big.NewInt(100), big.NewInt(150))

	srs.mu.RLock()
	defer srs.mu.RUnlock()

	require.Len(t, srs.pendingTasks, 1,
		"task at block 200 must not be dropped when queried window only covers [100, 150]")
	_, ok := srs.pendingTasks[taskFuture.MessageID]
	require.True(t, ok, "task at block 200 should still be in pending queue")
}

// TestSRS_Reorg_NilToBlock_UnboundedWindow verifies that passing nil as toBlock
// is treated as an unbounded upper end: any existing task at block ≥ fromBlock
// that is absent from the new event set is removed, matching the pre-bound behavior.
func TestSRS_Reorg_NilToBlock_UnboundedWindow(t *testing.T) {
	chain := protocol.ChainSelector(1337)
	reader := mocks.NewMockSourceReader(t)
	chainStatusMgr := mocks.NewMockChainStatusManager(t)

	curseDetector := mocks.NewMockCurseCheckerService(t)
	curseDetector.EXPECT().Start(mock.Anything).Return(nil).Maybe()
	curseDetector.EXPECT().Close().Return(nil).Maybe()

	srs, _, _ := newTestSRS(t, chain, reader, chainStatusMgr, curseDetector, 10*time.Millisecond, 5000)

	// Task at block 200 — far above fromBlock (100), but toBlock is nil (unbounded).
	msgs := createTestMessageSentEvents(t, 1, chain, defaultDestChain, []uint64{200})
	taskFuture := verifier.VerificationTask{
		Message:     msgs[0].Message,
		BlockNumber: msgs[0].BlockNumber,
		MessageID:   msgs[0].MessageID.String(),
	}

	srs.mu.Lock()
	srs.pendingTasks = map[string]verifier.VerificationTask{taskFuture.MessageID: taskFuture}
	srs.mu.Unlock()

	// nil toBlock → window is [100, ∞) → taskFuture (200) is inside → should be dropped.
	srs.addToPendingQueueHandleReorg([]verifier.VerificationTask{}, big.NewInt(100), nil)

	srs.mu.RLock()
	defer srs.mu.RUnlock()

	require.Len(t, srs.pendingTasks, 0,
		"task at block 200 must be dropped when toBlock is nil (unbounded window)")
	require.True(t, srs.reorgTracker.RequiresFinalization(defaultDestChain, taskFuture.Message.SequenceNumber),
		"reorged task's seqNum should be tracked for finalization when using nil toBlock")
}
