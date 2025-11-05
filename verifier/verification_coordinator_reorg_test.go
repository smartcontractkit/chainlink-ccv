package verifier_test

// Integration tests for reorg detector and verification coordinator.
//
// These tests verify that the coordinator correctly handles blockchain reorganizations
// by integrating the ReorgDetectorService with the Coordinator's reorg handling logic.
//
// Test Strategy:
//   - Use real ReorgDetectorService instances (not mocked) for authentic reorg detection
//   - Mock HeadTracker and SourceReader for controlled chain state simulation
//   - Use deterministic hash generation (hashFromNumber) for easy debugging
//
// Hash Encoding Quick Reference:
//   Canonical blocks:  [0x00, 0x00, 0x00, BLOCK_NUM, ...] (first 4 bytes = block number)
//   Reorged blocks:    [0xFF, 0x00, 0x00, 0x00, BLOCK_NUM, ...] (0xFF marker + block number)
//
// Example: Block 105 (0x69 in hex)
//   Canonical: [0x00, 0x00, 0x00, 0x69, 0x00, ...]
//   Reorged:   [0xFF, 0x00, 0x00, 0x00, 0x69, ...]
//
// See hashFromNumber() and createReorgedChainBlocks() for detailed documentation.

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/verifier/test"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	protocol_mocks "github.com/smartcontractkit/chainlink-ccv/protocol/common/mocks"
	verifiermocks "github.com/smartcontractkit/chainlink-ccv/verifier/mocks"
)

// mockReorgDetector is a simple mock that returns a channel we can control in tests.
type mockReorgDetector struct {
	statusCh chan protocol.ChainStatus
}

func newMockReorgDetector() *mockReorgDetector {
	return &mockReorgDetector{
		statusCh: make(chan protocol.ChainStatus, 10),
	}
}

func (m *mockReorgDetector) Start(ctx context.Context) (<-chan protocol.ChainStatus, error) {
	return m.statusCh, nil
}

func (m *mockReorgDetector) Close() error {
	close(m.statusCh)
	return nil
}

// reorgTestSetup contains the test fixtures for reorg integration tests.
type reorgTestSetup struct {
	t                 *testing.T
	ctx               context.Context
	cancel            context.CancelFunc
	coordinator       *verifier.Coordinator
	mockSourceReader  *verifiermocks.MockSourceReader
	mockHeadTracker   *protocol_mocks.MockHeadTracker
	mockReorgDetector *mockReorgDetector
	testVerifier      *test.Verifier
	storage           *common.InMemoryOffchainStorage
	chainSelector     protocol.ChainSelector
	lggr              logger.Logger
	taskChannel       chan verifier.VerificationTask

	// Block state for simulating chain progression
	currentLatest    *protocol.BlockHeader
	currentFinalized *protocol.BlockHeader
	blocksMu         sync.RWMutex
}

// hashFromNumber creates a deterministic hash from block number for testing.
//
// This encodes the block number into the first 4 bytes of the hash using big-endian byte order.
// The remaining 28 bytes are left as zeros.
//
// Encoding (Big-Endian):
//   - h[0] = most significant byte  (bits 24-31)
//   - h[1] = second byte            (bits 16-23)
//   - h[2] = third byte             (bits 8-15)
//   - h[3] = least significant byte (bits 0-7)
//
// Examples:
//
//	Block 0:   [0x00, 0x00, 0x00, 0x00, 0x00, ...] (all zeros)
//	Block 100: [0x00, 0x00, 0x00, 0x64, 0x00, ...] (0x64 = 100 in hex)
//	Block 255: [0x00, 0x00, 0x00, 0xFF, 0x00, ...] (0xFF = 255 in hex)
//	Block 256: [0x00, 0x00, 0x01, 0x00, 0x00, ...] (0x0100 = 256 in hex)
//	Block 1000: [0x00, 0x00, 0x03, 0xE8, 0x00, ...] (0x03E8 = 1000 in hex)
//
// To decode a hash back to block number:
//
//	blockNum = (h[0] << 24) | (h[1] << 16) | (h[2] << 8) | h[3]
//
// Why not use SHA256?
//   - Debuggability: You can visually decode block numbers from hex dumps
//   - Simplicity: Test intent is clear - we just need unique, predictable hashes
//   - Performance: Faster test execution
//   - Relevance: We're testing reorg logic, not cryptographic properties
func hashFromNumber(n uint64) protocol.Bytes32 {
	var h protocol.Bytes32
	h[0] = byte(n >> 24) // MSB
	h[1] = byte(n >> 16)
	h[2] = byte(n >> 8)
	h[3] = byte(n) // LSB
	return h
}

// setupReorgTest creates a complete test setup with coordinator and reorg detector.
func setupReorgTest(t *testing.T, chainSelector protocol.ChainSelector, finalityCheckInterval time.Duration) *reorgTestSetup {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	lggr := logger.Test(t)

	// Create mocks using the test helper pattern
	mockSetup := test.SetupMockSourceReader(t)
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
	testVer := test.NewVerifier()

	setup := &reorgTestSetup{
		t:                t,
		ctx:              ctx,
		cancel:           cancel,
		mockSourceReader: mockSetup.Reader,
		mockHeadTracker:  mockHeadTracker,
		chainSelector:    chainSelector,
		lggr:             lggr,
		currentLatest:    initialLatest,
		currentFinalized: initialFinalized,
		testVerifier:     testVer,
		storage:          common.NewInMemoryOffchainStorage(lggr),
		taskChannel:      mockSetup.Channel,
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
	coordinatorConfig := verifier.CoordinatorConfig{
		VerifierID: "reorg-test-coordinator",
		SourceConfigs: map[protocol.ChainSelector]verifier.SourceConfig{
			chainSelector: {
				VerifierAddress: protocol.UnknownAddress("0x1234"),
				PollInterval:    10 * time.Millisecond,
			},
		},
	}

	// Create coordinator with all components
	coordinator, err := verifier.NewCoordinator(
		verifier.WithVerifier(setup.testVerifier),
		verifier.WithStorage(setup.storage),
		verifier.WithLogger(lggr),
		verifier.WithConfig(coordinatorConfig),
		verifier.WithSourceReaders(map[protocol.ChainSelector]verifier.SourceReader{
			chainSelector: setup.mockSourceReader,
		}),
		verifier.WithHeadTrackers(map[protocol.ChainSelector]chainaccess.HeadTracker{
			chainSelector: mockHeadTracker,
		}),
		verifier.WithReorgDetectors(map[protocol.ChainSelector]protocol.ReorgDetector{
			chainSelector: mrd,
		}),
		verifier.WithMonitoring(monitoring.NewNoopVerifierMonitoring()),
		verifier.WithFinalityCheckInterval(finalityCheckInterval),
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

// assertSourceReaderChannelState verifies the state of the source reader's verification task channel.
// When expectOpen is true, it asserts the channel is open (not closed).
// When expectOpen is false, it asserts the channel is closed.
func assertSourceReaderChannelState(t *testing.T, coordinator *verifier.Coordinator, chainSelector protocol.ChainSelector, expectOpen bool) {
	t.Helper()

	sourceReaderService := coordinator.GetSourceReaderService(chainSelector)
	require.NotNil(t, sourceReaderService, "Source reader service should exist")

	verificationTaskCh := sourceReaderService.VerificationTaskChannel()

	// Try non-blocking receive - if channel is closed, we'll get ok=false immediately
	select {
	case _, ok := <-verificationTaskCh:
		// Check if channel state matches expectation
		if !ok {
			// Channel is closed (ok=false)
			if !expectOpen {
				t.Log("✅ Source reader channel is closed as expected")
			} else {
				t.Fatal("Source reader channel is closed but expected to be open")
			}
		} else {
			// Channel is open with data (ok=true)
			if expectOpen {
				t.Log("✅ Source reader channel is open (has pending data)")
			} else {
				t.Fatal("Source reader channel is open (has data) but expected to be closed")
			}
		}
	case <-time.After(200 * time.Millisecond):
		// Timeout means channel is open and blocking (no data available)
		if expectOpen {
			t.Log("✅ Source reader channel is open (no data, no closure)")
		} else {
			t.Fatal("Source reader channel is still open and not closed (expected closed)")
		}
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
	finalizedTasks := []verifier.VerificationTask{
		{
			Message:        test.CreateTestMessage(t, 1, chainSelector, defaultDestChain, 0), // Default finality
			BlockNumber:    98,
			ReceiptBlobs:   []protocol.ReceiptWithBlob{{Blob: []byte("receipt1")}},
			CreatedAt:      time.Now(),
			IdempotencyKey: uuid.NewString(),
		},
		{
			Message:        test.CreateTestMessage(t, 2, chainSelector, defaultDestChain, 0),
			BlockNumber:    99,
			ReceiptBlobs:   []protocol.ReceiptWithBlob{{Blob: []byte("receipt2")}},
			CreatedAt:      time.Now(),
			IdempotencyKey: uuid.NewString(),
		},
	}

	pendingTasks := []verifier.VerificationTask{
		{
			Message:        test.CreateTestMessage(t, 3, chainSelector, defaultDestChain, 0),
			BlockNumber:    101,
			ReceiptBlobs:   []protocol.ReceiptWithBlob{{Blob: []byte("receipt3")}},
			CreatedAt:      time.Now(),
			IdempotencyKey: uuid.NewString(),
		},
		{
			Message:        test.CreateTestMessage(t, 4, chainSelector, defaultDestChain, 0),
			BlockNumber:    102,
			ReceiptBlobs:   []protocol.ReceiptWithBlob{{Blob: []byte("receipt4")}},
			CreatedAt:      time.Now(),
			IdempotencyKey: uuid.NewString(),
		},
	}

	t.Log("📋 Starting coordinator")

	// Start coordinator FIRST
	err := setup.coordinator.Start(setup.ctx)
	require.NoError(t, err)
	t.Log("✅ Coordinator started with reorg detector")

	// THEN send tasks via channel (like in verification_coordinator_test.go)
	go func() {
		for _, task := range append(finalizedTasks, pendingTasks...) {
			setup.taskChannel <- task
			time.Sleep(10 * time.Millisecond)
		}
	}()

	t.Log("📋 Sending tasks to verification pipeline")

	// Wait for finalized tasks to be processed before triggering reorg
	// Tasks at blocks 98, 99 should be processed since they're below finalized block 100
	t.Log("📋 Waiting for finalized tasks (98, 99) to be processed...")
	test.WaitForMessagesInStorage(setup.t, setup.storage, 2)
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

	// Verify source reader is still running by checking that its channel is NOT closed
	t.Log("🔍 Verifying source reader still running after normal reorg...")
	assertSourceReaderChannelState(t, setup.coordinator, chainSelector, true)

	t.Log("✅ Test completed: Normal reorg handled correctly - source reader continues running")
}

// TestReorgDetection_FinalityViolation tests that a finality violation stops the chain reader.
func TestReorgDetection_FinalityViolation(t *testing.T) {
	chainSelector := protocol.ChainSelector(1337)
	setup := setupReorgTest(t, chainSelector, 10*time.Second) // high finality check interval to avoid processing before sending the violation notification
	defer setup.cleanup()

	// Start coordinator
	err := setup.coordinator.Start(setup.ctx)
	require.NoError(t, err)

	t.Log("✅ Coordinator started with reorg detector")

	// Create tasks at blocks 98, 99, 100 (around finalized block)
	tasks := []verifier.VerificationTask{
		{
			Message:        test.CreateTestMessage(t, 1, chainSelector, defaultDestChain, 0), // Default finality
			BlockNumber:    98,
			ReceiptBlobs:   []protocol.ReceiptWithBlob{{Blob: []byte("receipt1")}},
			CreatedAt:      time.Now(),
			IdempotencyKey: uuid.NewString(),
		},
		{
			Message:        test.CreateTestMessage(t, 2, chainSelector, defaultDestChain, 0),
			BlockNumber:    99,
			ReceiptBlobs:   []protocol.ReceiptWithBlob{{Blob: []byte("receipt2")}},
			CreatedAt:      time.Now(),
			IdempotencyKey: uuid.NewString(),
		},
		{
			Message:        test.CreateTestMessage(t, 3, chainSelector, defaultDestChain, 0),
			BlockNumber:    100,
			ReceiptBlobs:   []protocol.ReceiptWithBlob{{Blob: []byte("receipt3")}},
			CreatedAt:      time.Now(),
			IdempotencyKey: uuid.NewString(),
		},
	}

	// Send tasks via channel
	go func() {
		for _, task := range tasks {
			setup.taskChannel <- task
			time.Sleep(10 * time.Millisecond)
		}
	}()

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

	// Verify source reader has stopped by checking that its channel IS closed
	t.Log("🔍 Verifying source reader stopped after finality violation...")
	assertSourceReaderChannelState(t, setup.coordinator, chainSelector, false)

	// Additionally verify no messages were stored
	storedMsgCount := setup.storage.GetTotalCount()
	assert.Equal(t, 0, storedMsgCount,
		"No messages should be stored after finality violation")

	t.Log("✅ Test completed: Finality violation handled correctly - source reader stopped")
}
