package verifier

import (
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/protocol"

	protocol_mocks "github.com/smartcontractkit/chainlink-ccv/protocol/common/mocks"
)

// ----------------------
// Fetching / queuing
// ----------------------

func TestSRS_FetchesAndQueuesMessages(t *testing.T) {
	ctx := context.Background()
	chain := protocol.ChainSelector(1337)

	// Mock source readerService
	reader := mocks.NewMockSourceReader(t)

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
	curseDetector := mocks.NewMockCurseCheckerService(t)
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
	srs.lastProcessedFinalizedBlock.Store(big.NewInt(95))

	// Call cycle once
	srs.processEventCycle(ctx, latest, finalized)

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

	reader := mocks.NewMockSourceReader(t)

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

	curseDetector := mocks.NewMockCurseCheckerService(t)
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

	srs.lastProcessedFinalizedBlock.Store(big.NewInt(95))

	srs.processEventCycle(ctx, latest, finalized)

	srs.mu.RLock()
	defer srs.mu.RUnlock()

	require.Len(t, srs.pendingTasks, 1, "duplicate events by MessageID should be deduped in pendingTasks")
}

// ----------------------
// Reorg handling in addToPendingQueueHandleReorg
// ----------------------

func TestSRS_Reorg_DropsMissingPendingAndSent(t *testing.T) {
	chain := protocol.ChainSelector(1337)
	reader := mocks.NewMockSourceReader(t)

	// Minimal mocks – these tests don't call LatestAndFinalizedBlock/Fetch directly.
	chainStatusMgr := protocol_mocks.NewMockChainStatusManager(t)
	curseDetector := mocks.NewMockCurseCheckerService(t)
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

func TestSRS_Curse_DropsAtSendTime(t *testing.T) {
	ctx := context.Background()
	chain := protocol.ChainSelector(1337)
	reader := mocks.NewMockSourceReader(t)
	chainStatusMgr := protocol_mocks.NewMockChainStatusManager(t)

	curseDetector := mocks.NewMockCurseCheckerService(t)
	// All lanes cursed for this test
	curseDetector.EXPECT().
		IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).
		Return(true).
		Maybe()
	curseDetector.EXPECT().Start(mock.Anything).Return(nil).Maybe()
	curseDetector.EXPECT().Close().Return(nil).Maybe()

	srs, mockFC := newTestSRS(
		t,
		chain,
		reader,
		chainStatusMgr,
		curseDetector,
		10*time.Millisecond,
	)

	// Setup finality checker mock
	mockFC.EXPECT().UpdateFinalized(mock.Anything, mock.Anything).Return(nil).Maybe()
	mockFC.EXPECT().IsFinalityViolated().Return(false).Maybe()

	events := createTestMessageSentEvents(t, 1, chain, defaultDestChain, []uint64{100, 101})
	tasks := []VerificationTask{
		{Message: events[0].Message, BlockNumber: events[0].BlockNumber, MessageID: events[0].MessageID.String()},
		{Message: events[1].Message, BlockNumber: events[1].BlockNumber, MessageID: events[1].MessageID.String()},
	}

	// Tasks are added to pending queue (no curse check at enqueue time)
	srs.addToPendingQueueHandleReorg(tasks, big.NewInt(100))

	srs.mu.RLock()
	require.Len(t, srs.pendingTasks, 2, "tasks should be enqueued initially")
	srs.mu.RUnlock()

	// When sendReadyMessages is called, cursed tasks are dropped
	latest := &protocol.BlockHeader{Number: 150}
	finalized := &protocol.BlockHeader{Number: 120}
	srs.sendReadyMessages(ctx, latest, finalized)

	srs.mu.RLock()
	defer srs.mu.RUnlock()
	require.Len(t, srs.pendingTasks, 0, "cursed tasks should be dropped at send time")
}

// ----------------------
// Readiness checks (default + custom finality)
// ----------------------

func TestSRS_Readiness_DefaultFinality_ReadyWhenBelowFinalized(t *testing.T) {
	ctx := context.Background()
	chain := protocol.ChainSelector(1337)
	reader := mocks.NewMockSourceReader(t)

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

	curseDetector := mocks.NewMockCurseCheckerService(t)
	curseDetector.EXPECT().
		IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).
		Return(false).
		Maybe()
	curseDetector.EXPECT().Start(mock.Anything).Return(nil).Maybe()
	curseDetector.EXPECT().Close().Return(nil).Maybe()

	srs, mockFC := newTestSRS(
		t,
		chain,
		reader,
		chainStatusMgr,
		curseDetector,
		10*time.Millisecond,
	)

	// Mock finality checker expectations
	mockFC.EXPECT().
		UpdateFinalized(mock.Anything, finalized.Number).
		Return(nil).
		Maybe()
	mockFC.EXPECT().
		IsFinalityViolated().
		Return(false).
		Maybe()

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
	go srs.sendReadyMessages(ctx, latest, finalized)

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
	reader := mocks.NewMockSourceReader(t)

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

	curseDetector := mocks.NewMockCurseCheckerService(t)
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

	go srs.sendReadyMessages(ctx, latest, finalized)

	select {
	case batch := <-srs.readyTasksCh:
		require.NoError(t, batch.Error)
		require.Len(t, batch.Items, 1)
		require.Equal(t, task.MessageID, batch.Items[0].MessageID)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for readyTasks batch")
	}
}

func TestSRS_isMessageReadyForVerification(t *testing.T) {
	chain := protocol.ChainSelector(1337)
	reader := mocks.NewMockSourceReader(t)
	chainStatusMgr := protocol_mocks.NewMockChainStatusManager(t)
	curseDetector := mocks.NewMockCurseCheckerService(t)
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

	tests := []struct {
		name           string
		blockDepth     uint16
		msgBlock       uint64
		latestBlock    uint64
		finalizedBlock uint64
		expectedReady  bool
		description    string
	}{
		{
			name:           "DefaultFinality_Ready_BelowFinalized",
			blockDepth:     0, // wait finality
			msgBlock:       100,
			latestBlock:    200,
			finalizedBlock: 150,
			expectedReady:  true,
			description:    "Default finality (0): message block <= finalized block",
		},
		{
			name:           "DefaultFinality_NotReady_AboveFinalized",
			blockDepth:     0, // wait finality
			msgBlock:       160,
			latestBlock:    200,
			finalizedBlock: 150,
			expectedReady:  false,
			description:    "Default finality (0): message block > finalized block",
		},
		{
			name:           "CustomFinality_Ready_MetCustomRequirement",
			blockDepth:     10,
			msgBlock:       180,
			latestBlock:    200,
			finalizedBlock: 150,
			expectedReady:  true,
			description:    "Custom finality: msgBlock (180) + blockDepth (10) = 190 <= latest (200)",
		},
		{
			name:           "CustomFinality_Ready_CappedAtFinality",
			blockDepth:     100,
			msgBlock:       140,
			latestBlock:    200,
			finalizedBlock: 150,
			expectedReady:  true,
			description:    "Custom finality: msgBlock (140) + blockDepth (100) = 240 > latest (200), BUT msgBlock <= finalized (150)",
		},
		{
			name:           "CustomFinality_NotReady_NeitherConditionMet",
			blockDepth:     20,
			msgBlock:       190,
			latestBlock:    200,
			finalizedBlock: 180,
			expectedReady:  false,
			description:    "Custom finality: msgBlock (190) + blockDepth (20) = 210 > latest (200) AND msgBlock (190) > finalized (180)",
		},
		{
			name:           "DOSAttack_MAXUint16_Ready_CappedAtFinality",
			blockDepth:     65535,
			msgBlock:       100,
			latestBlock:    200,
			finalizedBlock: 150,
			expectedReady:  true,
			description:    "DoS attack with MAX_UINT16: should be ready once finalized, not wait 65k blocks",
		},
		{
			name:           "DOSAttack_MAXUint16_NotReady_NotFinalized",
			blockDepth:     65535,
			msgBlock:       160,
			latestBlock:    200,
			finalizedBlock: 150,
			expectedReady:  false,
			description:    "DoS attack with MAX_UINT16: not ready if block not finalized",
		},
		{
			name:           "FasterThanFinality_Ready_ShortFinality",
			blockDepth:     5,
			msgBlock:       195,
			latestBlock:    200,
			finalizedBlock: 190,
			expectedReady:  true,
			description:    "Faster-than-finality: msgBlock (195) + blockDepth (5) = 200 <= latest (200)",
		},
		{
			name:           "EdgeCase_ExactlyAtFinalized",
			blockDepth:     50,
			msgBlock:       150,
			latestBlock:    200,
			finalizedBlock: 150,
			expectedReady:  true,
			description:    "Edge case: message block exactly at finalized block boundary",
		},
		{
			name:           "EdgeCase_ExactlyAtCustomRequirement",
			blockDepth:     10,
			msgBlock:       190,
			latestBlock:    200,
			finalizedBlock: 180,
			expectedReady:  true,
			description:    "Edge case: msgBlock (190) + finality (10) = 200 == latest (200)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := CreateTestMessage(t, 1, chain, defaultDestChain, tt.blockDepth, 300_000)
			msgID, _ := msg.MessageID()

			task := VerificationTask{
				Message:     msg,
				BlockNumber: tt.msgBlock,
				MessageID:   msgID.String(),
			}

			ready := srs.isMessageReadyForVerification(
				task,
				big.NewInt(int64(tt.latestBlock)),
				big.NewInt(int64(tt.finalizedBlock)),
			)

			require.Equal(t, tt.expectedReady, ready, tt.description)
		})
	}
}

// ----------------------
// Finality violations
// ----------------------

func TestSRS_FinalityViolation_DisablesChainAndFlushesTasks(t *testing.T) {
	ctx := context.Background()
	chain := protocol.ChainSelector(1337)
	reader := mocks.NewMockSourceReader(t)

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

	curseDetector := mocks.NewMockCurseCheckerService(t)
	curseDetector.EXPECT().
		IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).
		Return(false).
		Maybe()
	curseDetector.EXPECT().Start(mock.Anything).Return(nil).Maybe()
	curseDetector.EXPECT().Close().Return(nil).Maybe()

	srs, mockFC := newTestSRS(
		t,
		chain,
		reader,
		chainStatusMgr,
		curseDetector,
		10*time.Millisecond,
	)

	mockFC.EXPECT().IsFinalityViolated().Unset()
	mockFC.EXPECT().
		IsFinalityViolated().
		Return(true).
		Maybe()

	// Seed some pending & sent tasks
	msgs := createTestMessageSentEvents(t, 1, chain, defaultDestChain, []uint64{940, 960})
	task1 := VerificationTask{Message: msgs[0].Message, BlockNumber: msgs[0].BlockNumber, MessageID: msgs[0].MessageID.String()}
	task2 := VerificationTask{Message: msgs[1].Message, BlockNumber: msgs[1].BlockNumber, MessageID: msgs[1].MessageID.String()}

	srs.mu.Lock()
	srs.pendingTasks[task1.MessageID] = task1
	srs.sentTasks[task2.MessageID] = task2
	srs.mu.Unlock()

	go srs.sendReadyMessages(ctx, latest, finalized)

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
	reader := mocks.NewMockSourceReader(t)

	// We won't use readerService here
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

	curseDetector := mocks.NewMockCurseCheckerService(t)
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

// ----------------------
// Reorg tracking tests
// ----------------------

func TestSRS_Reorg_TracksSequenceNumbers(t *testing.T) {
	chain := protocol.ChainSelector(1337)
	reader := mocks.NewMockSourceReader(t)

	chainStatusMgr := protocol_mocks.NewMockChainStatusManager(t)
	curseDetector := mocks.NewMockCurseCheckerService(t)
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

	// Create initial tasks A and B
	msgs := createTestMessageSentEvents(t, 1, chain, defaultDestChain, []uint64{100, 101})
	taskA := VerificationTask{Message: msgs[0].Message, BlockNumber: msgs[0].BlockNumber, MessageID: msgs[0].MessageID.String()}
	taskB := VerificationTask{Message: msgs[1].Message, BlockNumber: msgs[1].BlockNumber, MessageID: msgs[1].MessageID.String()}

	// Add to pending
	srs.mu.Lock()
	srs.pendingTasks = map[string]VerificationTask{
		taskA.MessageID: taskA,
		taskB.MessageID: taskB,
	}
	srs.mu.Unlock()

	// New query results: B is gone (reorged), new task C appears
	msgsC := createTestMessageSentEvents(t, 10, chain, defaultDestChain, []uint64{102})
	taskC := VerificationTask{Message: msgsC[0].Message, BlockNumber: msgsC[0].BlockNumber, MessageID: msgsC[0].MessageID.String()}
	newTasks := []VerificationTask{taskA, taskC}

	srs.addToPendingQueueHandleReorg(newTasks, big.NewInt(100))

	srs.mu.RLock()
	defer srs.mu.RUnlock()

	// B's seqNum (2) should be tracked as reorged
	require.True(t, srs.reorgTracker.RequiresFinalization(defaultDestChain, taskB.Message.SequenceNumber),
		"reorged task B's seqNum should be tracked")

	// A's seqNum should NOT be tracked
	require.False(t, srs.reorgTracker.RequiresFinalization(defaultDestChain, taskA.Message.SequenceNumber),
		"non-reorged task A's seqNum should not be tracked")
}

func TestSRS_Reorg_TracksSentTasksSequenceNumbers(t *testing.T) {
	chain := protocol.ChainSelector(1337)
	reader := mocks.NewMockSourceReader(t)

	chainStatusMgr := protocol_mocks.NewMockChainStatusManager(t)
	curseDetector := mocks.NewMockCurseCheckerService(t)
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

	// Task A was already sent (in sentTasks)
	msgs := createTestMessageSentEvents(t, 1, chain, defaultDestChain, []uint64{100})
	taskA := VerificationTask{Message: msgs[0].Message, BlockNumber: msgs[0].BlockNumber, MessageID: msgs[0].MessageID.String()}

	srs.mu.Lock()
	srs.sentTasks = map[string]VerificationTask{
		taskA.MessageID: taskA,
	}
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
	chainStatusMgr := protocol_mocks.NewMockChainStatusManager(t)
	curseDetector := mocks.NewMockCurseCheckerService(t)
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

	latestBlock := big.NewInt(200) // msgBlock(190) + finality(5) = 195 <= 200, custom finality would be met
	finalizedBlock := big.NewInt(180)

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
	chainStatusMgr := protocol_mocks.NewMockChainStatusManager(t)
	curseDetector := mocks.NewMockCurseCheckerService(t)
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
	chainStatusMgr := protocol_mocks.NewMockChainStatusManager(t)
	curseDetector := mocks.NewMockCurseCheckerService(t)
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
	chainStatusMgr := protocol_mocks.NewMockChainStatusManager(t)
	curseDetector := mocks.NewMockCurseCheckerService(t)
	curseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).Return(false).Maybe()
	curseDetector.EXPECT().Start(mock.Anything).Return(nil).Maybe()
	curseDetector.EXPECT().Close().Return(nil).Maybe()

	srs, mockFC := newTestSRS(
		t,
		chain,
		reader,
		chainStatusMgr,
		curseDetector,
		10*time.Millisecond,
	)

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

	go srs.sendReadyMessages(ctx, latest, finalized)

	// Receive ready batch
	select {
	case batch := <-srs.readyTasksCh:
		require.NoError(t, batch.Error)
		require.Len(t, batch.Items, 1)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for readyTasks batch")
	}

	// SeqNum should be removed from reorg tracker after finalization
	require.False(t, srs.reorgTracker.RequiresFinalization(defaultDestChain, msg.SequenceNumber),
		"seqNum should be removed from reorg tracker after finalization")
	require.False(t, len(srs.reorgTracker.reorgedSeqNums) > 0)
}
