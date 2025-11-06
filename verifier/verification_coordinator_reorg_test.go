package verifier

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/common"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	protocol_mocks "github.com/smartcontractkit/chainlink-ccv/protocol/common/mocks"
)

// reorgTestSetup contains the test fixtures for reorg integration tests.
type reorgTestSetup struct {
	t                  *testing.T
	ctx                context.Context
	cancel             context.CancelFunc
	coordinator        *Coordinator
	mockSourceReader   *MockSourceReader
	mockHeadTracker    *protocol_mocks.MockHeadTracker
	mockReorgDetector  *mockReorgDetector
	chainStatusManager *InMemoryChainStatusManager
	testVerifier       *TestVerifier
	storage            *common.InMemoryOffchainStorage
	chainSelector      protocol.ChainSelector
	lggr               logger.Logger
	taskChannel        chan VerificationTask

	// Block state for simulating chain progression
	currentLatest    *protocol.BlockHeader
	currentFinalized *protocol.BlockHeader
	blocksMu         sync.RWMutex
}

// setupReorgTest creates a complete test setup with coordinator and reorg detector.
func setupReorgTest(t *testing.T, chainSelector protocol.ChainSelector, finalityCheckInterval time.Duration) *reorgTestSetup {
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

	setup := &reorgTestSetup{
		t:                  t,
		ctx:                ctx,
		cancel:             cancel,
		mockSourceReader:   mockSetup.Reader,
		mockHeadTracker:    mockHeadTracker,
		chainStatusManager: NewInMemoryChainStatusManager(),
		chainSelector:      chainSelector,
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

	// Create mock reorg detector that we can control in tests
	mrd := newMockReorgDetector()
	setup.mockReorgDetector = mrd

	// Create coordinator configuration
	coordinatorConfig := CoordinatorConfig{
		VerifierID: "reorg-test-coordinator",
		SourceConfigs: map[protocol.ChainSelector]SourceConfig{
			chainSelector: {
				VerifierAddress: protocol.UnknownAddress("0x1234"),
				PollInterval:    10 * time.Millisecond,
			},
		},
	}

	// Create coordinator with all components
	coordinator, err := NewCoordinator(
		WithVerifier(setup.testVerifier),
		WithStorage(setup.storage),
		WithLogger(lggr),
		WithConfig(coordinatorConfig),
		WithChainStatusManager(setup.chainStatusManager),
		WithSourceReaders(map[protocol.ChainSelector]SourceReader{
			chainSelector: setup.mockSourceReader,
		}),
		WithHeadTrackers(map[protocol.ChainSelector]chainaccess.HeadTracker{
			chainSelector: mockHeadTracker,
		}),
		WithReorgDetectors(map[protocol.ChainSelector]protocol.ReorgDetector{
			chainSelector: mrd,
		}),
		WithMonitoring(&noopMonitoring{}),
		WithFinalityCheckInterval(finalityCheckInterval),
	)
	require.NoError(t, err)
	setup.coordinator = coordinator

	return setup
}

// cleanup tears down the test setup.
func (s *reorgTestSetup) cleanup() {
	if s.coordinator != nil {
		err := s.coordinator.Close()
		if err != nil {
			s.t.Logf("Error closing coordinator: %v", err)
		}
	}
	s.cancel()
}

func (s *reorgTestSetup) mustStartCoordinator() {
	err := s.coordinator.Start(s.ctx)
	require.NoError(s.t, err)
	s.t.Log("✅ Coordinator started")
}

func (s *reorgTestSetup) mustRestartCoordinator() {
	err := s.coordinator.Close()
	require.NoError(s.t, err)
	s.t.Log("✅ Coordinator closed")

	// Restart the same coordinator - disabled chain should be skipped
	err = s.coordinator.Start(s.ctx)
	require.NoError(s.t, err)
	s.t.Log("✅ Coordinator restarted")
}

// assertSourceReaderChannelState verifies the state of the source reader's verification task channel.
// When expectOpen is true, it asserts the channel is open (not closed).
// When expectOpen is false, it asserts the channel is closed.
func assertSourceReaderChannelState(t *testing.T, coordinator *Coordinator, chainSelector protocol.ChainSelector, expectOpen bool) {
	t.Helper()

	// Access internal sourceReaders map directly (we're in the same package)
	coordinator.mu.RLock()
	sourceReaderService := coordinator.sourceStates[chainSelector].reader
	coordinator.mu.RUnlock()

	require.NotNil(t, sourceReaderService, "Source reader service should not be nil")

	verificationTaskCh := sourceReaderService.VerificationTaskChannel()

	// Try non-blocking receive - if channel is closed, we'll get ok=false immediately
	select {
	case _, ok := <-verificationTaskCh:
		if !ok {
			// Channel is closed
			require.False(t, expectOpen, "Source reader channel is closed but expected to be open")
			t.Log("✅ Source reader channel is closed as expected")
		} else {
			// Channel is open with data
			require.True(t, expectOpen, "Source reader channel is open (has data) but expected to be closed")
			t.Log("✅ Source reader channel is open (has pending data)")
		}
	case <-time.After(200 * time.Millisecond):
		// Timeout means channel is open and blocking (no data available)
		require.True(t, expectOpen, "Source reader channel is still open but expected to be closed")
		t.Log("✅ Source reader channel is open (no data, no closure)")
	}
}

// TestReorgDetection_NormalReorg tests that a normal reorg is detected and handled correctly.
// This test validates that:
//  1. Tasks below the finalized block (98, 99) are processed successfully
//  2. Tasks above the finalized block (101, 102) are flushed when reorg occurs
//  3. The coordinator continues operating normally after reorg
//
// Test setup:
//   - Initial state: Finalized block 100, Latest block 105
//   - Canonical chain: 95-110 (need blocks below 100 for finalized tasks)
//   - Reorg: LCA at block 100 (finalized), diverges from block 101
//   - Finalized tasks at 98, 99 (< 100) → should be processed
//   - Pending tasks at 101, 102 (> 100) → should be flushed by reorg
func TestReorgDetection_NormalReorg(t *testing.T) {
	chainSelector := protocol.ChainSelector(1337)
	setup := setupReorgTest(t, chainSelector, 500*time.Millisecond)
	defer setup.cleanup()

	// Create tasks at two ranges:
	// - Tasks at blocks 98, 99: BELOW finalized block (100), should be PROCESSED
	// - Tasks at blocks 101, 102: ABOVE finalized block (100), should be FLUSHED by reorg
	finalizedTasks := createTestVerificationTasks(t, 1, chainSelector, defaultDestChain, []uint64{98, 99})
	pendingTasks := createTestVerificationTasks(t, 3, chainSelector, defaultDestChain, []uint64{101, 102})

	setup.mustStartCoordinator()
	// THEN send tasks via channel (like in verification_coordinator_test.go)
	sendTasksToChannel(t, setup, append(finalizedTasks, pendingTasks...))
	// Wait for finalized tasks to be processed before triggering reorg
	// Tasks at blocks 98, 99 should be processed since they're below finalized block 100
	t.Log("📋 Waiting for finalized tasks (98, 99) to be processed...")
	WaitForMessagesInStorage(setup.t, setup.storage, 2)
	t.Log("✅ Finalized tasks (98, 99) have been processed")

	// Inject a reorg event directly (LCA at block 100)
	// This simulates the reorg detector finding a reorg with LCA at finalized block 100
	t.Log("🔄 Injecting reorg event: LCA at block 100")
	setup.mockReorgDetector.statusCh <- protocol.ChainStatus{
		Type:         protocol.ReorgTypeNormal,
		ResetToBlock: 100, // LCA at finalized block
	}

	// Wait for reorg handler goroutine to process the event
	// With double-checked locking fix, we only need minimal time for goroutine scheduling
	time.Sleep(100 * time.Millisecond)

	// Verify behavior:
	// - Tasks at blocks 98, 99 (below finalized) should have been PROCESSED
	// - Tasks at blocks 101, 102 (in reorged range) should have been FLUSHED
	processedTasks := setup.testVerifier.GetProcessedTasks()
	t.Logf("📊 Processed task count after reorg: %d", len(processedTasks))

	// Should have processed the 2 finalized tasks (98, 99)
	// Tasks at 101, 102 should have been flushed before processing
	require.Equal(t, 2, len(processedTasks), "Only finalized tasks (98, 99) should be processed; tasks at 101, 102 should be flushed")

	require.Equal(t, uint64(98), processedTasks[0].BlockNumber)
	require.Equal(t, uint64(99), processedTasks[1].BlockNumber)

	// Verify that the source reader is still running (channel should be open)
	assertSourceReaderChannelState(t, setup.coordinator, chainSelector, true)
	// Verify reader still open after restart
	setup.mustRestartCoordinator()
	assertSourceReaderChannelState(t, setup.coordinator, chainSelector, true)

	t.Log("✅ Test completed: Normal reorg handled correctly - finalized tasks processed, reorged tasks flushed")
}

// TestReorgDetection_FinalityViolation tests that a finality violation stops the chain reader.
func TestReorgDetection_FinalityViolation(t *testing.T) {
	chainSelector := protocol.ChainSelector(1337)
	setup := setupReorgTest(t, chainSelector, 10*time.Second) // high finality check interval to avoid processing before sending the violation notification
	defer setup.cleanup()

	setup.mustStartCoordinator()
	// Create tasks at blocks 98, 99, 100 (around finalized block)
	tasks := createTestVerificationTasks(t, 1, chainSelector, defaultDestChain, []uint64{98, 99, 100})

	sendTasksToChannel(t, setup, tasks)
	// Wait for tasks to be queued
	time.Sleep(80 * time.Millisecond)

	t.Log("📋 Tasks queued")

	// Inject a finality violation event directly
	// This simulates a reorg deeper than the finalized block
	t.Log("⚠️  Injecting finality violation event")
	setup.mockReorgDetector.statusCh <- protocol.ChainStatus{
		Type:         protocol.ReorgTypeFinalityViolation,
		ResetToBlock: 0, // No safe reset point
	}

	// Wait for finality violation handler goroutine to process the event
	// With double-checked locking fix, we only need minimal time for goroutine scheduling
	time.Sleep(50 * time.Millisecond)

	// After finality violation:
	// 1. All pending tasks should be flushed
	// 2. Source reader should be stopped
	// 3. No new tasks should be processed

	processedCount := setup.testVerifier.GetProcessedTaskCount()
	t.Logf("📊 Processed task count after finality violation: %d", processedCount)

	// All tasks should have been flushed, none processed
	assert.Equal(t, 0, processedCount, "No tasks should be processed after finality violation")

	// Verify that the source reader has been stopped (channel should be closed)
	assertSourceReaderChannelState(t, setup.coordinator, chainSelector, false)

	t.Log("✅ Test completed: Finality violation handled correctly")

	statusMap, err := setup.chainStatusManager.ReadChainStatus(setup.ctx, []protocol.ChainSelector{chainSelector})
	require.NoError(t, err)
	require.Len(t, statusMap, 1)
	require.True(t, statusMap[chainSelector].Disabled, "Chain should be marked as disabled")
	t.Log("✅ Chain marked as disabled in chain status manager")

	t.Log("🔄 Testing coordinator restart with disabled chain - should remain stopped")
	setup.mustRestartCoordinator()
	assertSourceReaderChannelState(t, setup.coordinator, chainSelector, false)

	t.Log("✅ Test completed: Disabled chain correctly skipped on restart")
}

func sendTasksToChannel(t *testing.T, setup *reorgTestSetup, tasks []VerificationTask) {
	t.Helper()
	t.Log("📋 Sending tasks to verification pipeline")

	// Send tasks via channel
	go func() {
		for _, task := range tasks {
			setup.taskChannel <- task
			//time.Sleep(10 * time.Millisecond)
		}
	}()
}
