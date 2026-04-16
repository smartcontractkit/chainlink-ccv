package sourcereader

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/jobqueue"
	verifier "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vtypes"
	"github.com/smartcontractkit/chainlink-ccv/verifier/testutil"
)

// failableTaskQueue extends fakeTaskQueue with configurable failure mode for testing.
type failableTaskQueue struct {
	mu             sync.Mutex
	published      []verifier.VerificationTask
	failOnPublish  bool
	publishCount   int
	failureMessage string
}

func newFailableTaskQueue() *failableTaskQueue {
	return &failableTaskQueue{
		published:      make([]verifier.VerificationTask, 0),
		failureMessage: "simulated DB connection error",
	}
}

func (f *failableTaskQueue) Publish(_ context.Context, tasks ...verifier.VerificationTask) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.publishCount++
	if f.failOnPublish {
		return errors.New(f.failureMessage)
	}
	f.published = append(f.published, tasks...)
	return nil
}

func (f *failableTaskQueue) SetFailOnPublish(fail bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failOnPublish = fail
}

func (f *failableTaskQueue) Published() []verifier.VerificationTask {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]verifier.VerificationTask, len(f.published))
	copy(out, f.published)
	return out
}

func (f *failableTaskQueue) PublishCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.publishCount
}

func (f *failableTaskQueue) PublishWithDelay(_ context.Context, _ time.Duration, tasks ...verifier.VerificationTask) error {
	return f.Publish(context.Background(), tasks...)
}

func (f *failableTaskQueue) Consume(_ context.Context, _ int) ([]jobqueue.Job[verifier.VerificationTask], error) {
	return nil, nil
}

func (f *failableTaskQueue) Complete(_ context.Context, _ ...string) error {
	return nil
}

func (f *failableTaskQueue) Retry(_ context.Context, _ time.Duration, _ map[string]error, _ ...string) error {
	return nil
}

func (f *failableTaskQueue) Fail(_ context.Context, _ map[string]error, _ ...string) error {
	return nil
}

func (f *failableTaskQueue) Cleanup(_ context.Context, _ time.Duration) (int, error) {
	return 0, nil
}

func (f *failableTaskQueue) Size(_ context.Context) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.published), nil
}

func (f *failableTaskQueue) Name() string {
	return "failable-queue"
}

// TestSRS_PublishFailure_TasksRemainsInPendingQueue tests the critical data loss scenario:
// If taskQueue.Publish() fails (e.g., DB goes offline temporarily), tasks should remain
// in pendingTasks and be retried on the next cycle rather than being lost forever.
func TestSRS_PublishFailure_TasksRemainInPendingQueue(t *testing.T) {
	ctx := context.Background()
	chain := protocol.ChainSelector(1337)
	reader := mocks.NewMockSourceReader(t)
	chainStatusMgr := mocks.NewMockChainStatusManager(t)
	curseDetector := mocks.NewMockCurseCheckerService(t)

	latest := &protocol.BlockHeader{Number: 1000, Timestamp: time.Now()}
	finalized := &protocol.BlockHeader{Number: 950, Timestamp: time.Now()}

	srs, mockFC, queue := newTestSRSWithFailableQueue(t, chain, reader, chainStatusMgr, curseDetector, 10*time.Millisecond, 5000)
	mockFC.EXPECT().UpdateFinalized(mock.Anything, finalized.Number).Return(nil).Maybe()
	mockFC.EXPECT().IsFinalityViolated().Return(false).Maybe()

	// Mock curse detector to return not cursed for normal operation
	curseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, chain, defaultDestChain).
		Return(false, nil).Maybe()

	// Task with Finality=0 at block <= finalized — should be ready immediately
	msg := testutil.CreateTestMessage(t, 1, chain, defaultDestChain, 0, 300_000)
	msgID, _ := msg.MessageID()
	task := verifier.VerificationTask{Message: msg, BlockNumber: 940, MessageID: msgID.String()}

	// Add task to pending queue
	srs.mu.Lock()
	srs.pendingTasks[msgID.String()] = task
	srs.mu.Unlock()

	// Configure the queue to fail on first publish attempt
	queue.SetFailOnPublish(true)

	// First attempt - should fail but keep task in pendingTasks
	srs.sendReadyMessages(ctx, latest, nil, finalized)

	srs.mu.RLock()
	pendingCount := len(srs.pendingTasks)
	sentCount := len(srs.sentTasks)
	_, stillInPending := srs.pendingTasks[msgID.String()]
	_, movedToSent := srs.sentTasks[msgID.String()]
	srs.mu.RUnlock()

	// CRITICAL: Task should still be in pendingTasks, NOT in sentTasks
	assert.Equal(t, 1, pendingCount, "task should remain in pending queue after publish failure")
	assert.Equal(t, 0, sentCount, "task should NOT be in sent queue after publish failure")
	assert.True(t, stillInPending, "task should still be in pendingTasks")
	assert.False(t, movedToSent, "task should NOT have moved to sentTasks")
	assert.Equal(t, 0, len(queue.Published()), "no tasks should be in queue after failure")

	// Now fix the queue - subsequent publish should succeed
	queue.SetFailOnPublish(false)

	// Second attempt - should succeed
	srs.sendReadyMessages(ctx, latest, nil, finalized)

	srs.mu.RLock()
	pendingCount = len(srs.pendingTasks)
	sentCount = len(srs.sentTasks)
	_, stillInPending = srs.pendingTasks[msgID.String()]
	_, movedToSent = srs.sentTasks[msgID.String()]
	srs.mu.RUnlock()

	// Now task should be properly moved
	assert.Equal(t, 0, pendingCount, "task should be removed from pending queue after successful publish")
	assert.Equal(t, 1, sentCount, "task should be in sent queue after successful publish")
	assert.False(t, stillInPending, "task should NOT be in pendingTasks")
	assert.True(t, movedToSent, "task should have moved to sentTasks")
	assert.Equal(t, 1, len(queue.Published()), "task should be in queue after success")
}

// TestSRS_PublishFailure_CursedTasksDroppedImmediately tests that cursed tasks
// are dropped immediately (deleted from pendingTasks) even if we don't reach the publish step.
func TestSRS_PublishFailure_CursedTasksDroppedImmediately(t *testing.T) {
	ctx := context.Background()
	chain := protocol.ChainSelector(1337)
	reader := mocks.NewMockSourceReader(t)
	chainStatusMgr := mocks.NewMockChainStatusManager(t)
	curseDetector := mocks.NewMockCurseCheckerService(t)

	latest := &protocol.BlockHeader{Number: 1000, Timestamp: time.Now()}
	finalized := &protocol.BlockHeader{Number: 950, Timestamp: time.Now()}

	srs, mockFC, _ := newTestSRSWithFailableQueue(t, chain, reader, chainStatusMgr, curseDetector, 10*time.Millisecond, 5000)
	mockFC.EXPECT().UpdateFinalized(mock.Anything, finalized.Number).Return(nil).Maybe()
	mockFC.EXPECT().IsFinalityViolated().Return(false).Maybe()

	// Create a ready task
	msg := testutil.CreateTestMessage(t, 1, chain, defaultDestChain, 0, 300_000)
	msgID, _ := msg.MessageID()
	task := verifier.VerificationTask{Message: msg, BlockNumber: 940, MessageID: msgID.String()}

	srs.mu.Lock()
	srs.pendingTasks[msgID.String()] = task
	srs.mu.Unlock()

	// Mark the lane as cursed
	curseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, chain, defaultDestChain).
		Return(true, nil).Once()

	// Send ready messages - cursed task should be dropped immediately
	srs.sendReadyMessages(ctx, latest, nil, finalized)

	srs.mu.RLock()
	pendingCount := len(srs.pendingTasks)
	sentCount := len(srs.sentTasks)
	srs.mu.RUnlock()

	// Cursed tasks should be dropped immediately, not kept in pending
	assert.Equal(t, 0, pendingCount, "cursed task should be dropped from pending queue")
	assert.Equal(t, 0, sentCount, "cursed task should not be in sent queue")
}

// TestSRS_PublishFailure_PartialBatch tests that if some tasks are ready and publish fails,
// ALL ready tasks remain in pendingTasks for the next attempt.
func TestSRS_PublishFailure_PartialBatch(t *testing.T) {
	ctx := context.Background()
	chain := protocol.ChainSelector(1337)
	reader := mocks.NewMockSourceReader(t)
	chainStatusMgr := mocks.NewMockChainStatusManager(t)
	curseDetector := mocks.NewMockCurseCheckerService(t)

	latest := &protocol.BlockHeader{Number: 1000, Timestamp: time.Now()}
	finalized := &protocol.BlockHeader{Number: 950, Timestamp: time.Now()}

	srs, mockFC, queue := newTestSRSWithFailableQueue(t, chain, reader, chainStatusMgr, curseDetector, 10*time.Millisecond, 5000)
	mockFC.EXPECT().UpdateFinalized(mock.Anything, finalized.Number).Return(nil).Maybe()
	mockFC.EXPECT().IsFinalityViolated().Return(false).Maybe()

	// Mock curse detector to return not cursed for normal operation
	curseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, chain, defaultDestChain).
		Return(false, nil).Maybe()

	// Create multiple ready tasks
	msg1 := testutil.CreateTestMessage(t, 1, chain, defaultDestChain, 0, 300_000)
	msgID1, _ := msg1.MessageID()
	task1 := verifier.VerificationTask{Message: msg1, BlockNumber: 940, MessageID: msgID1.String()}

	msg2 := testutil.CreateTestMessage(t, 2, chain, defaultDestChain, 0, 300_000)
	msgID2, _ := msg2.MessageID()
	task2 := verifier.VerificationTask{Message: msg2, BlockNumber: 945, MessageID: msgID2.String()}

	msg3 := testutil.CreateTestMessage(t, 3, chain, defaultDestChain, 0, 300_000)
	msgID3, _ := msg3.MessageID()
	task3 := verifier.VerificationTask{Message: msg3, BlockNumber: 930, MessageID: msgID3.String()}

	srs.mu.Lock()
	srs.pendingTasks[msgID1.String()] = task1
	srs.pendingTasks[msgID2.String()] = task2
	srs.pendingTasks[msgID3.String()] = task3
	srs.mu.Unlock()

	// Configure the queue to fail on publish
	queue.SetFailOnPublish(true)

	// First attempt - should fail
	srs.sendReadyMessages(ctx, latest, nil, finalized)

	srs.mu.RLock()
	pendingCount := len(srs.pendingTasks)
	srs.mu.RUnlock()

	// All 3 tasks should still be in pending
	assert.Equal(t, 3, pendingCount, "all tasks should remain in pending queue after publish failure")
	assert.Equal(t, 0, len(queue.Published()), "no tasks should be published")

	// Now allow publish to succeed
	queue.SetFailOnPublish(false)

	// Second attempt - should succeed for all tasks
	srs.sendReadyMessages(ctx, latest, nil, finalized)

	srs.mu.RLock()
	pendingCount = len(srs.pendingTasks)
	sentCount := len(srs.sentTasks)
	srs.mu.RUnlock()

	// All tasks should now be processed
	assert.Equal(t, 0, pendingCount, "all tasks should be removed from pending queue")
	assert.Equal(t, 3, sentCount, "all tasks should be in sent queue")
	assert.Equal(t, 3, len(queue.Published()), "all tasks should be published")
}

// TestSRS_PublishFailure_ReorgTrackerNotAffected tests that the reorg tracker
// is not modified when publish fails (tasks remain tracked as reorged).
func TestSRS_PublishFailure_ReorgTrackerNotAffected(t *testing.T) {
	ctx := context.Background()
	chain := protocol.ChainSelector(1337)
	reader := mocks.NewMockSourceReader(t)
	chainStatusMgr := mocks.NewMockChainStatusManager(t)
	curseDetector := mocks.NewMockCurseCheckerService(t)

	latest := &protocol.BlockHeader{Number: 1000, Timestamp: time.Now()}
	finalized := &protocol.BlockHeader{Number: 950, Timestamp: time.Now()}

	srs, mockFC, queue := newTestSRSWithFailableQueue(t, chain, reader, chainStatusMgr, curseDetector, 10*time.Millisecond, 5000)
	mockFC.EXPECT().UpdateFinalized(mock.Anything, finalized.Number).Return(nil).Maybe()
	mockFC.EXPECT().IsFinalityViolated().Return(false).Maybe()

	// Mock curse detector to return not cursed for normal operation
	curseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, chain, defaultDestChain).
		Return(false, nil).Maybe()

	// Create a task that was previously affected by reorg
	msg := testutil.CreateTestMessage(t, 1, chain, defaultDestChain, 0, 300_000)
	msgID, _ := msg.MessageID()
	task := verifier.VerificationTask{Message: msg, BlockNumber: 940, MessageID: msgID.String()}

	// Track it as reorged
	srs.reorgTracker.Track(task.Message.DestChainSelector, task.Message.SequenceNumber)
	require.True(t, srs.reorgTracker.RequiresFinalization(task.Message.DestChainSelector, task.Message.SequenceNumber))

	srs.mu.Lock()
	srs.pendingTasks[msgID.String()] = task
	srs.mu.Unlock()

	// Configure the queue to fail
	queue.SetFailOnPublish(true)

	// Attempt to publish - should fail
	srs.sendReadyMessages(ctx, latest, nil, finalized)

	// CRITICAL: Reorg tracker should NOT be modified when publish fails
	require.True(t, srs.reorgTracker.RequiresFinalization(task.Message.DestChainSelector, task.Message.SequenceNumber),
		"reorg tracker should not be modified when publish fails")

	// Now allow publish to succeed
	queue.SetFailOnPublish(false)

	// Second attempt - should succeed
	srs.sendReadyMessages(ctx, latest, nil, finalized)

	// Now reorg tracker should be cleared
	require.False(t, srs.reorgTracker.RequiresFinalization(task.Message.DestChainSelector, task.Message.SequenceNumber),
		"reorg tracker should be cleared when publish succeeds")
}

// Helper to create test SRS with a failableTaskQueue.
func newTestSRSWithFailableQueue(
	t *testing.T,
	chainSelector protocol.ChainSelector,
	reader *mocks.MockSourceReader,
	chainStatusMgr protocol.ChainStatusManager,
	curseDetector *mocks.MockCurseCheckerService,
	pollInterval time.Duration,
	maxBlockRange uint64,
) (*Service, *mocks.MockFinalityViolationChecker, *failableTaskQueue) {
	t.Helper()

	queue := newFailableTaskQueue()

	// Use the existing test helper but replace the queue after creation
	srs, mockFC, _ := newTestSRS(t, chainSelector, reader, chainStatusMgr, curseDetector, pollInterval, maxBlockRange)

	// Replace the queue with our failable version
	srs.taskQueue = queue

	return srs, mockFC, queue
}
