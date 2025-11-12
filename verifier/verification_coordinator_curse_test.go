package verifier

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/common/pkg/cursedetector"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/common"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	protocol_mocks "github.com/smartcontractkit/chainlink-ccv/protocol/common/mocks"
)

// curseTestSetup contains the test fixtures for curse integration tests.
type curseTestSetup struct {
	t                  *testing.T
	ctx                context.Context
	cancel             context.CancelFunc
	coordinator        *Coordinator
	mockSourceReader   *MockSourceReader
	mockHeadTracker    *protocol_mocks.MockHeadTracker
	mockCurseDetector  *cursedetector.MockCurseDetector
	chainStatusManager *InMemoryChainStatusManager
	testVerifier       *TestVerifier
	storage            *common.InMemoryOffchainStorage
	sourceChain        protocol.ChainSelector
	destChain          protocol.ChainSelector
	lggr               logger.Logger
	taskChannel        chan VerificationTask

	// Block state for simulating chain progression
	currentLatest    *protocol.BlockHeader
	currentFinalized *protocol.BlockHeader
	blocksMu         sync.RWMutex
}

// setupCurseTest creates a complete test setup with coordinator and curse detector.
func setupCurseTest(t *testing.T, sourceChain, destChain protocol.ChainSelector, finalityCheckInterval time.Duration) *curseTestSetup {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	lggr := logger.Test(t)

	// Create mocks using the test helper pattern
	mockSetup := SetupMockSourceReader(t)
	mockSetup.ExpectVerificationTask(false)

	mockHeadTracker := protocol_mocks.NewMockHeadTracker(t)

	// Initialize block state
	initialLatest := &protocol.BlockHeader{
		Number:     105,
		Hash:       hashFromNumber(105),
		ParentHash: hashFromNumber(104),
		Timestamp:  time.Now(),
	}
	initialFinalized := &protocol.BlockHeader{
		Number:     100,
		Hash:       hashFromNumber(100),
		ParentHash: hashFromNumber(99),
		Timestamp:  time.Now(),
	}

	// Create test verifier
	testVer := NewTestVerifier()

	// Create mock curse detector
	mockCurseDetector := cursedetector.NewMockCurseDetector(t)

	// Setup default behavior: no curses initially
	mockCurseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything).Return(false).Maybe()
	mockCurseDetector.EXPECT().Start(mock.Anything).Return(nil).Maybe()
	mockCurseDetector.EXPECT().Close().Return(nil).Maybe()

	setup := &curseTestSetup{
		t:                  t,
		ctx:                ctx,
		cancel:             cancel,
		mockSourceReader:   mockSetup.Reader,
		mockHeadTracker:    mockHeadTracker,
		mockCurseDetector:  mockCurseDetector,
		chainStatusManager: NewInMemoryChainStatusManager(),
		sourceChain:        sourceChain,
		destChain:          destChain,
		lggr:               lggr,
		currentLatest:      initialLatest,
		currentFinalized:   initialFinalized,
		testVerifier:       testVer,
		storage:            common.NewInMemoryOffchainStorage(lggr),
		taskChannel:        mockSetup.Channel,
	}

	// Setup mock head tracker to return current state
	mockHeadTracker.EXPECT().LatestAndFinalizedBlock(mock.Anything).RunAndReturn(
		func(ctx context.Context) (*protocol.BlockHeader, *protocol.BlockHeader, error) {
			setup.blocksMu.RLock()
			defer setup.blocksMu.RUnlock()
			return setup.currentLatest, setup.currentFinalized, nil
		},
	).Maybe()

	// Create coordinator configuration
	coordinatorConfig := CoordinatorConfig{
		VerifierID: "curse-test-coordinator",
		SourceConfigs: map[protocol.ChainSelector]SourceConfig{
			sourceChain: {
				VerifierAddress: protocol.UnknownAddress("0x1234"),
				PollInterval:    10 * time.Millisecond,
			},
		},
	}

	// Create coordinator with all components, including mock curse detector
	coordinator, err := NewCoordinator(
		WithVerifier(setup.testVerifier),
		WithStorage(setup.storage),
		WithLogger(lggr),
		WithConfig(coordinatorConfig),
		WithChainStatusManager(setup.chainStatusManager),
		WithSourceReaders(map[protocol.ChainSelector]SourceReader{
			sourceChain: setup.mockSourceReader,
		}),
		WithHeadTrackers(map[protocol.ChainSelector]chainaccess.HeadTracker{
			sourceChain: mockHeadTracker,
		}),
		WithCurseDetector(mockCurseDetector), // Inject mock for testing
		WithMonitoring(&noopMonitoring{}),
		WithFinalityCheckInterval(finalityCheckInterval),
	)
	require.NoError(t, err)
	setup.coordinator = coordinator

	return setup
}

// cleanup tears down the test setup.
func (s *curseTestSetup) cleanup() {
	if s.coordinator != nil {
		err := s.coordinator.Close()
		if err != nil {
			s.t.Logf("Error closing coordinator: %v", err)
		}
	}
	s.cancel()
}

func (s *curseTestSetup) mustStartCoordinator() {
	err := s.coordinator.Start(s.ctx)
	require.NoError(s.t, err)
	s.t.Log("✅ Coordinator started")
}

func (s *curseTestSetup) curseLane(destChain protocol.ChainSelector) {
	s.t.Logf("🔒 Cursing lane: %d -> %d", s.sourceChain, destChain)
	// Update mock to return true for this specific lane
	s.mockCurseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything).Unset()
	s.mockCurseDetector.EXPECT().IsRemoteChainCursed(s.sourceChain, destChain).Return(true).Maybe()
	// Keep other lanes uncursed
	s.mockCurseDetector.EXPECT().IsRemoteChainCursed(s.sourceChain, mock.MatchedBy(func(chain protocol.ChainSelector) bool {
		return chain != destChain
	})).Return(false).Maybe()
}

func (s *curseTestSetup) curseGlobally() {
	s.t.Logf("🔒 Applying global curse on source chain: %d", s.sourceChain)
	s.mockCurseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything).Unset()
	// Global curse: all destinations from this source are cursed
	s.mockCurseDetector.EXPECT().IsRemoteChainCursed(s.sourceChain, mock.Anything).Return(true)
}

func (s *curseTestSetup) liftCurse() {
	s.t.Log("🔓 Lifting curse")
	s.mockCurseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything).Unset()
	// Reset to no curses
	s.mockCurseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything).Return(false).Maybe()
}

func (s *curseTestSetup) sendTasks(tasks []VerificationTask) {
	s.t.Log("📋 Sending tasks to verification pipeline")
	go func() {
		for _, task := range tasks {
			s.taskChannel <- task
		}
	}()
	// Give some time for tasks to be queued
	time.Sleep(20 * time.Millisecond)
	s.t.Log("📋 Tasks queued")
}

// TestCurseDetection_LaneSpecificCurse tests that a lane-specific curse drops pending and new tasks.
// This test validates that:
//  1. Tasks are processed normally before curse
//  2. Pending tasks are dropped when lane is cursed
//  3. New tasks are also dropped while lane is cursed
func TestCurseDetection_LaneSpecificCurse(t *testing.T) {
	sourceChain := protocol.ChainSelector(1337)
	destChain := protocol.ChainSelector(2337)
	destChain2 := protocol.ChainSelector(3337)

	setup := setupCurseTest(t, sourceChain, destChain, 10*time.Millisecond)
	defer setup.cleanup()

	// Create tasks that will be finalized (blocks 98, 99 < finalized 100)
	finalizedTasks := createTestVerificationTasks(t, 1, sourceChain, destChain, []uint64{96, 97})
	// Create tasks that will be pending (blocks 101, 102 > finalized 100)
	pendingTasks := createTestVerificationTasks(t, 3, sourceChain, destChain, []uint64{101, 102})

	setup.mustStartCoordinator()

	// Send finalized tasks - should be processed
	setup.sendTasks(finalizedTasks)
	t.Log("⏳ Waiting for finalized tasks to be processed...")
	WaitForMessagesInStorage(t, setup.storage, 2)
	t.Log("✅ Finalized tasks processed before curse")

	// Send pending tasks
	setup.sendTasks(pendingTasks)
	time.Sleep(50 * time.Millisecond) // Let them queue up

	// Now curse the lane
	setup.curseLane(destChain)

	// Wait for finality check interval to process (and drop) the pending tasks
	time.Sleep(50 * time.Millisecond)

	// Verify that only the 2 finalized tasks were processed (before curse)
	processedTasks := setup.testVerifier.GetProcessedTasks()
	t.Logf("📊 Processed task count after curse: %d", len(processedTasks))
	require.Equal(t, 2, len(processedTasks), "Only tasks before curse should be processed")
	require.Equal(t, uint64(96), processedTasks[0].BlockNumber)
	require.Equal(t, uint64(97), processedTasks[1].BlockNumber)

	// Try to send new tasks while cursed - should be dropped immediately
	newTasks := createTestVerificationTasks(t, 5, sourceChain, destChain, []uint64{103, 104})
	setup.sendTasks(newTasks)
	time.Sleep(50 * time.Millisecond)

	// Still should have only 2 processed tasks
	processedTasks = setup.testVerifier.GetProcessedTasks()
	require.Equal(t, 2, len(processedTasks), "New tasks should be dropped while cursed")

	// Try to send new tasks on non-cursed lane
	otherDestTasks := createTestVerificationTasks(t, 5, sourceChain, destChain2, []uint64{97, 98})
	setup.sendTasks(otherDestTasks)
	time.Sleep(50 * time.Millisecond)

	// Still should have only 2 processed tasks
	processedTasks = setup.testVerifier.GetProcessedTasks()
	require.Equal(t, 4, len(processedTasks), "New tasks should be dropped while cursed")

	t.Log("✅ Test completed: Lane-specific curse drops pending and new tasks")
}

// TestCurseDetection_GlobalCurse tests that a global curse affects all lanes.
func TestCurseDetection_GlobalCurse(t *testing.T) {
	sourceChain := protocol.ChainSelector(1337)
	destChain1 := protocol.ChainSelector(2337)
	destChain2 := protocol.ChainSelector(3337)
	setup := setupCurseTest(t, sourceChain, destChain1, 10*time.Millisecond)
	defer setup.cleanup()

	// Create tasks for two different destination chains
	tasksToChain1 := createTestVerificationTasks(t, 1, sourceChain, destChain1, []uint64{98, 99})
	tasksToChain2 := createTestVerificationTasks(t, 3, sourceChain, destChain2, []uint64{98, 99})

	setup.mustStartCoordinator()

	// Process some tasks before global curse
	setup.sendTasks(tasksToChain1)
	WaitForMessagesInStorage(t, setup.storage, 2)
	t.Log("✅ Tasks to chain1 processed before global curse")

	// Apply global curse
	setup.curseGlobally()

	// Try to send tasks to 2 dest chains - all should be dropped
	setup.sendTasks(tasksToChain1)
	setup.sendTasks(tasksToChain2)
	time.Sleep(50 * time.Millisecond)

	// Should still have only 2 processed tasks (before global curse)
	processedTasks := setup.testVerifier.GetProcessedTasks()
	require.Equal(t, 2, len(processedTasks), "Tasks after global curse should be dropped")

	t.Log("✅ Test completed: Global curse affects all lanes from source chain")
}

// TestCurseDetection_CurseLifting tests that processing resumes after curse is lifted.
func TestCurseDetection_CurseLifting(t *testing.T) {
	sourceChain := protocol.ChainSelector(1337)
	destChain := protocol.ChainSelector(2337)
	setup := setupCurseTest(t, sourceChain, destChain, 10*time.Millisecond)
	defer setup.cleanup()

	finalizedTasks1 := createTestVerificationTasks(t, 1, sourceChain, destChain, []uint64{98, 99})

	setup.mustStartCoordinator()

	// Apply curse
	setup.curseLane(destChain)
	// Try to send tasks while cursed - should be dropped
	droppedTasks := createTestVerificationTasks(t, 5, sourceChain, destChain, []uint64{98, 99})
	setup.sendTasks(droppedTasks)
	time.Sleep(50 * time.Millisecond)

	processedCount := setup.testVerifier.GetProcessedTaskCount()
	require.Equal(t, 0, processedCount, "Tasks during curse should be dropped")
	t.Log("✅ Tasks dropped while cursed")

	// Lift the curse
	setup.liftCurse()

	// Send new tasks - should be processed now
	setup.sendTasks(finalizedTasks1)
	WaitForMessagesInStorage(t, setup.storage, 2)

	processedTasks := setup.testVerifier.GetProcessedTasks()
	require.Equal(t, 2, len(processedTasks), "Tasks after curse lifted should be processed")

	t.Log("✅ Test completed: Processing resumes after curse is lifted")
}
