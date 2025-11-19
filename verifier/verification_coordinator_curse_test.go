package verifier

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	ccv_common "github.com/smartcontractkit/chainlink-ccv/common"

	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
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
	mockSourceReader   *protocol_mocks.MockSourceReader
	mockCurseChecker   *ccv_common.MockCurseCheckerService
	chainStatusManager *InMemoryChainStatusManager
	testVerifier       *TestVerifier
	storage            *common.InMemoryOffchainStorage
	sourceChain        protocol.ChainSelector
	destChain          protocol.ChainSelector
	lggr               logger.Logger
	sentEventsChan     chan protocol.MessageSentEvent

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
	mockSetup.ExpectFetchMessageSentEvent(false)

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
	mockCurseDetector := ccv_common.NewMockCurseCheckerService(t)

	// Setup default behavior: no curses initially
	mockCurseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).Return(false).Maybe()
	mockCurseDetector.EXPECT().Start(mock.Anything).Return(nil).Maybe()
	mockCurseDetector.EXPECT().Close().Return(nil).Maybe()

	setup := &curseTestSetup{
		t:                  t,
		ctx:                ctx,
		cancel:             cancel,
		mockSourceReader:   mockSetup.Reader,
		mockCurseChecker:   mockCurseDetector,
		chainStatusManager: NewInMemoryChainStatusManager(),
		sourceChain:        sourceChain,
		destChain:          destChain,
		lggr:               lggr,
		currentLatest:      initialLatest,
		currentFinalized:   initialFinalized,
		testVerifier:       testVer,
		storage:            common.NewInMemoryOffchainStorage(lggr),
		sentEventsChan:     mockSetup.Channel,
	}

	// Setup mock head tracker to return current state
	mockSetup.Reader.EXPECT().LatestAndFinalizedBlock(mock.Anything).RunAndReturn(
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
		WithSourceReaders(map[protocol.ChainSelector]chainaccess.SourceReader{
			sourceChain: setup.mockSourceReader,
		}),
		WithCurseDetector(mockCurseDetector), // Inject mock for testing
		WithMonitoring(&noopMonitoring{}),
		WithMessageTracker(&NoopLatencyTracker{}),
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
	s.mockCurseChecker.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).Unset()
	s.mockCurseChecker.EXPECT().IsRemoteChainCursed(mock.Anything, s.sourceChain, destChain).Return(true).Maybe()
	// Keep other lanes uncursed
	s.mockCurseChecker.EXPECT().IsRemoteChainCursed(mock.Anything, s.sourceChain, mock.MatchedBy(func(chain protocol.ChainSelector) bool {
		return chain != destChain
	})).Return(false).Maybe()
}

func (s *curseTestSetup) curseGlobally() {
	s.t.Logf("🔒 Applying global curse on source chain: %d", s.sourceChain)
	s.mockCurseChecker.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).Unset()
	// Global curse: all destinations from this source are cursed
	s.mockCurseChecker.EXPECT().IsRemoteChainCursed(mock.Anything, s.sourceChain, mock.Anything).Return(true)
}

func (s *curseTestSetup) liftCurse() {
	s.t.Log("🔓 Lifting curse")
	s.mockCurseChecker.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).Unset()
	// Reset to no curses
	s.mockCurseChecker.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).Return(false).Maybe()
}

func (s *curseTestSetup) sendEvents(events []protocol.MessageSentEvent) {
	s.t.Log("📋 Sending events to verification pipeline")
	go func() {
		for _, event := range events {
			s.sentEventsChan <- event
		}
	}()
	// Give some time for events to be queued
	time.Sleep(20 * time.Millisecond)
	s.t.Log("📋 Events queued")
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

	// Create events that will be finalized (blocks 98, 99 < finalized 100)
	finalizedEvents := createTestMessageSentEvents(t, 1, sourceChain, destChain, []uint64{96, 97})
	// Create events that will be pending (blocks 101, 102 > finalized 100)
	pendingEvents := createTestMessageSentEvents(t, 3, sourceChain, destChain, []uint64{101, 102})

	setup.mustStartCoordinator()

	// Send finalized events - should be processed
	setup.sendEvents(finalizedEvents)
	t.Log("⏳ Waiting for finalized events to be processed...")
	WaitForMessagesInStorage(t, setup.storage, 2)
	t.Log("✅ Finalized events processed before curse")

	// Send pending events
	setup.sendEvents(pendingEvents)
	time.Sleep(50 * time.Millisecond) // Let them queue up

	// Now curse the lane
	setup.curseLane(destChain)

	// Wait for finality check interval to process (and drop) the pending events
	time.Sleep(50 * time.Millisecond)

	// Verify that only the 2 finalized events were processed (before curse)
	processedTasks := setup.testVerifier.GetProcessedTasks()
	t.Logf("📊 Processed task count after curse: %d", len(processedTasks))
	require.Equal(t, 2, len(processedTasks), "Only events before curse should be processed")
	require.Equal(t, uint64(96), processedTasks[0].BlockNumber)
	require.Equal(t, uint64(97), processedTasks[1].BlockNumber)

	// Try to send new events while cursed - should be dropped immediately
	newEvents := createTestMessageSentEvents(t, 5, sourceChain, destChain, []uint64{103, 104})
	setup.sendEvents(newEvents)
	time.Sleep(50 * time.Millisecond)

	// Still should have only 2 processed tasks
	processedTasks = setup.testVerifier.GetProcessedTasks()
	require.Equal(t, 2, len(processedTasks), "New events should be dropped while cursed")

	// Try to send new events on non-cursed lane
	otherDestEvents := createTestMessageSentEvents(t, 5, sourceChain, destChain2, []uint64{97, 98})
	setup.sendEvents(otherDestEvents)
	time.Sleep(50 * time.Millisecond)

	// Still should have only 2 processed tasks
	processedTasks = setup.testVerifier.GetProcessedTasks()
	require.Equal(t, 4, len(processedTasks), "New events should be dropped while cursed")

	t.Log("✅ Test completed: Lane-specific curse drops pending and new tasks")
}

// TestCurseDetection_GlobalCurse tests that a global curse affects all lanes.
func TestCurseDetection_GlobalCurse(t *testing.T) {
	sourceChain := protocol.ChainSelector(1337)
	destChain1 := protocol.ChainSelector(2337)
	destChain2 := protocol.ChainSelector(3337)
	setup := setupCurseTest(t, sourceChain, destChain1, 10*time.Millisecond)
	defer setup.cleanup()

	// Create events for two different destination chains
	eventsToChain1 := createTestMessageSentEvents(t, 1, sourceChain, destChain1, []uint64{98, 99})
	eventsToChain2 := createTestMessageSentEvents(t, 3, sourceChain, destChain2, []uint64{98, 99})

	setup.mustStartCoordinator()

	// Process some events before global curse
	setup.sendEvents(eventsToChain1)
	WaitForMessagesInStorage(t, setup.storage, 2)
	t.Log("✅ Events to chain1 processed before global curse")

	// Apply global curse
	setup.curseGlobally()

	// Try to send events to 2 dest chains - all should be dropped
	setup.sendEvents(eventsToChain1)
	setup.sendEvents(eventsToChain2)
	time.Sleep(50 * time.Millisecond)

	// Should still have only 2 processed tasks (before global curse)
	processedTasks := setup.testVerifier.GetProcessedTasks()
	require.Equal(t, 2, len(processedTasks), "Events after global curse should be dropped")

	t.Log("✅ Test completed: Global curse affects all lanes from source chain")
}

// TestCurseDetection_CurseLifting tests that processing resumes after curse is lifted.
func TestCurseDetection_CurseLifting(t *testing.T) {
	sourceChain := protocol.ChainSelector(1337)
	destChain := protocol.ChainSelector(2337)
	setup := setupCurseTest(t, sourceChain, destChain, 10*time.Millisecond)
	defer setup.cleanup()

	finalizedEvents1 := createTestMessageSentEvents(t, 1, sourceChain, destChain, []uint64{98, 99})

	setup.mustStartCoordinator()

	// Apply curse
	setup.curseLane(destChain)
	// Try to send events while cursed - should be dropped
	droppedEvents := createTestMessageSentEvents(t, 5, sourceChain, destChain, []uint64{98, 99})
	setup.sendEvents(droppedEvents)
	time.Sleep(50 * time.Millisecond)

	processedCount := setup.testVerifier.GetProcessedTaskCount()
	require.Equal(t, 0, processedCount, "Events during curse should be dropped")
	t.Log("✅ Events dropped while cursed")

	// Lift the curse
	setup.liftCurse()

	// Send new events - should be processed now
	setup.sendEvents(finalizedEvents1)
	WaitForMessagesInStorage(t, setup.storage, 2)

	processedTasks := setup.testVerifier.GetProcessedTasks()
	require.Equal(t, 2, len(processedTasks), "Events after curse lifted should be processed")

	t.Log("✅ Test completed: Processing resumes after curse is lifted")
}
