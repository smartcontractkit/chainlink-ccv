package verifier

import (
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	ccv_common "github.com/smartcontractkit/chainlink-ccv/common"
	"github.com/smartcontractkit/chainlink-ccv/protocol"

	protocol_mocks "github.com/smartcontractkit/chainlink-ccv/protocol/common/mocks"
)

// ----------------------
// Fetching / queuing
// ----------------------

func TestSRS_FetchesAndQueuesMessages(t *testing.T) {
	ctx := context.Background()
	chain := protocol.ChainSelector(1337)

	// Mock source reader
	reader := protocol_mocks.NewMockSourceReader(t)

	latest := &protocol.BlockHeader{
		Number:     110,
		Hash:       hashFromNumber(110),
		ParentHash: hashFromNumber(109),
		Timestamp:  time.Now(),
	}
	finalized := &protocol.BlockHeader{
		Number:     100,
		Hash:       hashFromNumber(100),
		ParentHash: hashFromNumber(99),
		Timestamp:  time.Now(),
	}

	reader.EXPECT().
		LatestAndFinalizedBlock(mock.Anything).
		Return(latest, finalized, nil).
		Maybe()

	// 3 events at 101, 102, 105
	blockNums := []uint64{101, 102, 105}
	events := createTestMessageSentEvents(t, 1, chain, defaultDestChain, blockNums)

	reader.EXPECT().
		FetchMessageSentEvents(mock.Anything, mock.Anything, mock.Anything).
		Return(events, nil)

	// ChainStatusManager: we don't care here, just satisfy constructor + write calls.
	chainStatusMgr := protocol_mocks.NewMockChainStatusManager(t)
	// For initializeStartBlock: no prior status => fallback, but we override lastProcessed manually
	chainStatusMgr.EXPECT().
		ReadChainStatuses(mock.Anything, mock.Anything).
		Return(map[protocol.ChainSelector]*protocol.ChainStatusInfo{}, nil).
		Maybe()
	chainStatusMgr.EXPECT().
		WriteChainStatuses(mock.Anything, mock.Anything).
		Return(nil).
		Maybe()

	// Curse detector: no curses
	curseDetector := ccv_common.NewMockCurseCheckerService(t)
	curseDetector.EXPECT().
		IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).
		Return(false).
		Maybe()
	curseDetector.EXPECT().Start(mock.Anything).Return(nil).Maybe()
	curseDetector.EXPECT().Close().Return(nil).Maybe()

	srs, _ := newTestSRS(
		t,
		chain,
		reader,
		chainStatusMgr,
		curseDetector,
		10*time.Millisecond,
	)

	// Set starting lastProcessed before first event
	srs.mu.Lock()
	srs.lastProcessedBlock = big.NewInt(95)
	srs.mu.Unlock()

	// Call cycle once
	srs.processEventCycle(ctx)

	// Check pending queue
	srs.mu.RLock()
	defer srs.mu.RUnlock()

	require.Len(t, srs.pendingTasks, len(events), "all fetched events should be queued")
	for _, ev := range events {
		id := ev.MessageID.String()
		task, ok := srs.pendingTasks[id]
		require.True(t, ok, "task with MessageID %s should be present", id)
		require.Equal(t, ev.BlockNumber, task.BlockNumber)
	}
}

// ----------------------
// Deduplication
// ----------------------

func TestSRS_DeduplicatesByMessageID(t *testing.T) {
	ctx := context.Background()
	chain := protocol.ChainSelector(1337)

	reader := protocol_mocks.NewMockSourceReader(t)

	latest := &protocol.BlockHeader{Number: 105}
	finalized := &protocol.BlockHeader{Number: 100}
	reader.EXPECT().
		LatestAndFinalizedBlock(mock.Anything).
		Return(latest, finalized, nil).
		Maybe()

	// Two events with the same MessageID
	events := createTestMessageSentEvents(t, 1, chain, defaultDestChain, []uint64{101})
	dupEvent := events[0]
	events = append(events, dupEvent)

	reader.EXPECT().
		FetchMessageSentEvents(mock.Anything, mock.Anything, mock.Anything).
		Return(events, nil)

	chainStatusMgr := protocol_mocks.NewMockChainStatusManager(t)
	chainStatusMgr.EXPECT().
		ReadChainStatuses(mock.Anything, mock.Anything).
		Return(map[protocol.ChainSelector]*protocol.ChainStatusInfo{}, nil).
		Maybe()
	chainStatusMgr.EXPECT().
		WriteChainStatuses(mock.Anything, mock.Anything).
		Return(nil).
		Maybe()

	curseDetector := ccv_common.NewMockCurseCheckerService(t)
	curseDetector.EXPECT().
		IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).
		Return(false).
		Maybe()
	curseDetector.EXPECT().Start(mock.Anything).Return(nil).Maybe()
	curseDetector.EXPECT().Close().Return(nil).Maybe()

	srs, _ := newTestSRS(
		t,
		chain,
		reader,
		chainStatusMgr,
		curseDetector,
		10*time.Millisecond,
	)

	srs.mu.Lock()
	srs.lastProcessedBlock = big.NewInt(95)
	srs.mu.Unlock()

	srs.processEventCycle(ctx)

	srs.mu.RLock()
	defer srs.mu.RUnlock()

	require.Len(t, srs.pendingTasks, 1, "duplicate events by MessageID should be deduped in pendingTasks")
}

// ----------------------
// Reorg handling in addToPendingQueueHandleReorg
// ----------------------

func TestSRS_Reorg_DropsMissingPendingAndSent(t *testing.T) {
	chain := protocol.ChainSelector(1337)
	reader := protocol_mocks.NewMockSourceReader(t)

	// Minimal mocks – these tests don't call LatestAndFinalizedBlock/Fetch directly.
	chainStatusMgr := protocol_mocks.NewMockChainStatusManager(t)
	curseDetector := ccv_common.NewMockCurseCheckerService(t)
	curseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).Return(false).Maybe()
	curseDetector.EXPECT().Start(mock.Anything).Return(nil).Maybe()
	curseDetector.EXPECT().Close().Return(nil).Maybe()

	srs, _ := newTestSRS(
		t,
		chain,
		reader,
		chainStatusMgr,
		curseDetector,
		10*time.Millisecond,
	)

	// Build three tasks: A, B, C (C only in sentTasks)
	msgs := createTestMessageSentEvents(t, 1, chain, defaultDestChain, []uint64{100, 101, 102})
	taskA := VerificationTask{Message: msgs[0].Message, BlockNumber: msgs[0].BlockNumber, MessageID: msgs[0].MessageID.String()}
	taskB := VerificationTask{Message: msgs[1].Message, BlockNumber: msgs[1].BlockNumber, MessageID: msgs[1].MessageID.String()}
	taskC := VerificationTask{Message: msgs[2].Message, BlockNumber: msgs[2].BlockNumber, MessageID: msgs[2].MessageID.String()}

	srs.mu.Lock()
	srs.pendingTasks = map[string]VerificationTask{
		taskA.MessageID: taskA,
		taskB.MessageID: taskB,
	}
	srs.sentTasks = map[string]VerificationTask{
		taskC.MessageID: taskC,
	}
	srs.mu.Unlock()

	// New canonical events contain A and a new D; B and C are gone ⇒ should be dropped.
	msgsD := createTestMessageSentEvents(t, 10, chain, defaultDestChain, []uint64{103})
	taskD := VerificationTask{Message: msgsD[0].Message, BlockNumber: msgsD[0].BlockNumber, MessageID: msgsD[0].MessageID.String()}
	newTasks := []VerificationTask{taskA, taskD}

	srs.addToPendingQueueHandleReorg(newTasks, big.NewInt(100))

	srs.mu.RLock()
	defer srs.mu.RUnlock()

	// Pending should have A and D only
	require.Len(t, srs.pendingTasks, 2)
	_, hasA := srs.pendingTasks[taskA.MessageID]
	_, hasD := srs.pendingTasks[taskD.MessageID]
	require.True(t, hasA)
	require.True(t, hasD)

	// sentTasks should be empty (B, C removed)
	require.Len(t, srs.sentTasks, 0)
}

// ----------------------
// Curses
// ----------------------

func TestSRS_Curse_DropsAtEnqueue(t *testing.T) {
	chain := protocol.ChainSelector(1337)
	reader := protocol_mocks.NewMockSourceReader(t)
	chainStatusMgr := protocol_mocks.NewMockChainStatusManager(t)

	curseDetector := ccv_common.NewMockCurseCheckerService(t)
	// All lanes cursed for this test
	curseDetector.EXPECT().
		IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).
		Return(true).
		Maybe()
	curseDetector.EXPECT().Start(mock.Anything).Return(nil).Maybe()
	curseDetector.EXPECT().Close().Return(nil).Maybe()

	srs, _ := newTestSRS(
		t,
		chain,
		reader,
		chainStatusMgr,
		curseDetector,
		10*time.Millisecond,
	)

	events := createTestMessageSentEvents(t, 1, chain, defaultDestChain, []uint64{100, 101})
	tasks := []VerificationTask{
		{Message: events[0].Message, BlockNumber: events[0].BlockNumber, MessageID: events[0].MessageID.String()},
		{Message: events[1].Message, BlockNumber: events[1].BlockNumber, MessageID: events[1].MessageID.String()},
	}

	// Because lane is cursed, addToPendingQueueHandleReorg should drop everything.
	srs.addToPendingQueueHandleReorg(tasks, big.NewInt(100))

	srs.mu.RLock()
	defer srs.mu.RUnlock()

	require.Len(t, srs.pendingTasks, 0, "no tasks should be enqueued when lane is cursed at enqueue time")
}

// ----------------------
// Readiness checks (default + custom finality)
// ----------------------

func TestSRS_Readiness_DefaultFinality_ReadyWhenBelowFinalized(t *testing.T) {
	ctx := context.Background()
	chain := protocol.ChainSelector(1337)
	reader := protocol_mocks.NewMockSourceReader(t)

	latest := &protocol.BlockHeader{Number: 1000}
	finalized := &protocol.BlockHeader{Number: 950}

	reader.EXPECT().
		LatestAndFinalizedBlock(mock.Anything).
		Return(latest, finalized, nil).
		Maybe()

	chainStatusMgr := protocol_mocks.NewMockChainStatusManager(t)
	chainStatusMgr.EXPECT().
		ReadChainStatuses(mock.Anything, mock.Anything).
		Return(map[protocol.ChainSelector]*protocol.ChainStatusInfo{}, nil).
		Maybe()
	chainStatusMgr.EXPECT().
		WriteChainStatuses(mock.Anything, mock.Anything).
		Return(nil).
		Maybe()

	curseDetector := ccv_common.NewMockCurseCheckerService(t)
	curseDetector.EXPECT().
		IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).
		Return(false).
		Maybe()
	curseDetector.EXPECT().Start(mock.Anything).Return(nil).Maybe()
	curseDetector.EXPECT().Close().Return(nil).Maybe()

	srs, fc := newTestSRS(
		t,
		chain,
		reader,
		chainStatusMgr,
		curseDetector,
		10*time.Millisecond,
	)

	// Task with Finality=0 and block <= finalized should be ready.
	msg := CreateTestMessage(t, 1, chain, defaultDestChain, 0, 300_000)
	msgID, _ := msg.MessageID()
	task := VerificationTask{
		Message:     msg,
		BlockNumber: 940,
		MessageID:   msgID.String(),
	}

	srs.mu.Lock()
	srs.pendingTasks[msgID.String()] = task
	srs.mu.Unlock()

	// Call sendReadyMessages once
	go srs.sendReadyMessages(ctx)

	// Assert finality checker got update
	time.Sleep(20 * time.Millisecond)
	lastUpdate, ok := fc.lastUpdate()
	require.True(t, ok)
	require.Equal(t, finalized.Number, lastUpdate)

	// Receive ready batch
	select {
	case batch := <-srs.readyTasksCh:
		require.NoError(t, batch.Error)
		require.Len(t, batch.Items, 1)
		require.Equal(t, task.MessageID, batch.Items[0].MessageID)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for readyTasks batch")
	}

	// Task should be removed from pending and added to sent
	srs.mu.RLock()
	defer srs.mu.RUnlock()
	require.Len(t, srs.pendingTasks, 0)
	require.Len(t, srs.sentTasks, 1)
}

func TestSRS_Readiness_CustomFinality_ReadyAgainstLatest(t *testing.T) {
	ctx := context.Background()
	chain := protocol.ChainSelector(1337)
	reader := protocol_mocks.NewMockSourceReader(t)

	latest := &protocol.BlockHeader{Number: 1000}
	finalized := &protocol.BlockHeader{Number: 950}

	reader.EXPECT().
		LatestAndFinalizedBlock(mock.Anything).
		Return(latest, finalized, nil).
		Maybe()

	chainStatusMgr := protocol_mocks.NewMockChainStatusManager(t)
	chainStatusMgr.EXPECT().
		ReadChainStatuses(mock.Anything, mock.Anything).
		Return(map[protocol.ChainSelector]*protocol.ChainStatusInfo{}, nil).
		Maybe()
	chainStatusMgr.EXPECT().
		WriteChainStatuses(mock.Anything, mock.Anything).
		Return(nil).
		Maybe()

	curseDetector := ccv_common.NewMockCurseCheckerService(t)
	curseDetector.EXPECT().
		IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).
		Return(false).
		Maybe()
	curseDetector.EXPECT().Start(mock.Anything).Return(nil).Maybe()
	curseDetector.EXPECT().Close().Return(nil).Maybe()

	srs, _ := newTestSRS(
		t,
		chain,
		reader,
		chainStatusMgr,
		curseDetector,
		10*time.Millisecond,
	)

	// Custom finality f=10; block = latest - 10 => ready.
	const f uint16 = 10
	msg := CreateTestMessage(t, 1, chain, defaultDestChain, f, 300_000)
	msgID, _ := msg.MessageID()
	block := latest.Number - uint64(f)

	task := VerificationTask{
		Message:     msg,
		BlockNumber: block,
		MessageID:   msgID.String(),
	}

	srs.mu.Lock()
	srs.pendingTasks[msgID.String()] = task
	srs.mu.Unlock()

	go srs.sendReadyMessages(ctx)

	select {
	case batch := <-srs.readyTasksCh:
		require.NoError(t, batch.Error)
		require.Len(t, batch.Items, 1)
		require.Equal(t, task.MessageID, batch.Items[0].MessageID)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for readyTasks batch")
	}
}

// ----------------------
// Finality violations
// ----------------------

func TestSRS_FinalityViolation_DisablesChainAndFlushesTasks(t *testing.T) {
	ctx := context.Background()
	chain := protocol.ChainSelector(1337)
	reader := protocol_mocks.NewMockSourceReader(t)

	latest := &protocol.BlockHeader{Number: 1000}
	finalized := &protocol.BlockHeader{Number: 950}

	reader.EXPECT().
		LatestAndFinalizedBlock(mock.Anything).
		Return(latest, finalized, nil).
		Maybe()

	chainStatusMgr := protocol_mocks.NewMockChainStatusManager(t)
	chainStatusMgr.EXPECT().
		ReadChainStatuses(mock.Anything, mock.Anything).
		Return(map[protocol.ChainSelector]*protocol.ChainStatusInfo{}, nil).
		Maybe()

	// Expect WriteChainStatuses with Disabled=true
	chainStatusMgr.EXPECT().
		WriteChainStatuses(mock.Anything, mock.Anything).
		RunAndReturn(func(_ context.Context, infos []protocol.ChainStatusInfo) error {
			require.Len(t, infos, 1)
			require.True(t, infos[0].Disabled)
			return nil
		}).
		Maybe()

	curseDetector := ccv_common.NewMockCurseCheckerService(t)
	curseDetector.EXPECT().
		IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).
		Return(false).
		Maybe()
	curseDetector.EXPECT().Start(mock.Anything).Return(nil).Maybe()
	curseDetector.EXPECT().Close().Return(nil).Maybe()

	srs, fc := newTestSRS(
		t,
		chain,
		reader,
		chainStatusMgr,
		curseDetector,
		10*time.Millisecond,
	)

	// Seed some pending & sent tasks
	msgs := createTestMessageSentEvents(t, 1, chain, defaultDestChain, []uint64{940, 960})
	task1 := VerificationTask{Message: msgs[0].Message, BlockNumber: msgs[0].BlockNumber, MessageID: msgs[0].MessageID.String()}
	task2 := VerificationTask{Message: msgs[1].Message, BlockNumber: msgs[1].BlockNumber, MessageID: msgs[1].MessageID.String()}

	srs.mu.Lock()
	srs.pendingTasks[task1.MessageID] = task1
	srs.sentTasks[task2.MessageID] = task2
	srs.mu.Unlock()

	// Configure fakeFinalityChecker to flag violation on first update
	fc.violatedNow = true

	go srs.sendReadyMessages(ctx)

	// Give it a moment
	time.Sleep(50 * time.Millisecond)

	srs.mu.RLock()
	defer srs.mu.RUnlock()

	require.True(t, srs.disabled.Load(), "chain should be disabled after finality violation")
	require.Len(t, srs.pendingTasks, 0, "pending tasks should be flushed on finality violation")
	require.Len(t, srs.sentTasks, 0, "sentTasks should be flushed on finality violation")
}

// ----------------------
// ChainStatus: monotonic updates
// ----------------------

func TestSRS_ChainStatus_MonotonicUpdates(t *testing.T) {
	ctx := context.Background()
	chain := protocol.ChainSelector(1337)
	reader := protocol_mocks.NewMockSourceReader(t)

	// We won't use reader here
	chainStatusMgr := protocol_mocks.NewMockChainStatusManager(t)

	// ReadChainStatuses for initializeStartBlock
	chainStatusMgr.EXPECT().
		ReadChainStatuses(mock.Anything, mock.Anything).
		Return(map[protocol.ChainSelector]*protocol.ChainStatusInfo{}, nil).
		Maybe()

	// We expect exactly two writes with increasing FinalizedBlockHeight
	callCount := 0
	chainStatusMgr.EXPECT().
		WriteChainStatuses(mock.Anything, mock.Anything).
		RunAndReturn(func(_ context.Context, infos []protocol.ChainStatusInfo) error {
			require.Len(t, infos, 1)
			callCount++
			switch callCount {
			case 1:
				require.Equal(t, big.NewInt(100), infos[0].FinalizedBlockHeight)
			case 2:
				require.Equal(t, big.NewInt(200), infos[0].FinalizedBlockHeight)
			default:
				t.Fatalf("unexpected number of WriteChainStatuses calls: %d", callCount)
			}
			return nil
		}).
		Times(2)

	curseDetector := ccv_common.NewMockCurseCheckerService(t)
	curseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).Return(false).Maybe()
	curseDetector.EXPECT().Start(mock.Anything).Return(nil).Maybe()
	curseDetector.EXPECT().Close().Return(nil).Maybe()

	srs, _ := newTestSRS(
		t,
		chain,
		reader,
		chainStatusMgr,
		curseDetector,
		10*time.Millisecond,
	)

	// Force lastChainStatusTime very old to bypass ChainStatusInterval check
	srs.lastChainStatusTime = time.Now().Add(-2 * ChainStatusInterval)

	// First update at 100
	srs.updateChainStatus(ctx, big.NewInt(100))
	// Force another time shift to avoid interval throttle
	srs.lastChainStatusTime = time.Now().Add(-2 * ChainStatusInterval)
	srs.updateChainStatus(ctx, big.NewInt(200))

	require.Equal(t, 2, callCount, "expected exactly 2 chain status writes")
}
