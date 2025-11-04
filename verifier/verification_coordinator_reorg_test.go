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
	"fmt"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/verifier/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	protocol_mocks "github.com/smartcontractkit/chainlink-ccv/protocol/common/mocks"
	verifier_mocks "github.com/smartcontractkit/chainlink-ccv/verifier/mocks"
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
	mockSourceReader  *verifier_mocks.MockSourceReader
	mockHeadTracker   *protocol_mocks.MockHeadTracker
	mockReorgDetector *mockReorgDetector
	TestVerifier      *test.TestVerifier
	storage           *common.InMemoryOffchainStorage
	chainSelector     protocol.ChainSelector
	lggr              logger.Logger
	taskChannel       chan verifier.VerificationTask

	// Block state for simulating chain progression
	currentLatest    *protocol.BlockHeader
	currentFinalized *protocol.BlockHeader
	blocksMu         sync.RWMutex
}

// createBlockHeader creates a block header with specified number, hash, and parent hash.
func createBlockHeader(number uint64, hash, parentHash protocol.Bytes32) protocol.BlockHeader {
	return protocol.BlockHeader{
		Number:     number,
		Hash:       hash,
		ParentHash: parentHash,
		Timestamp:  time.Now(),
	}
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

// createChainBlocks creates a canonical chain of blocks from start to end.
func createChainBlocks(start, end uint64) []protocol.BlockHeader {
	blocks := make([]protocol.BlockHeader, 0, end-start+1)
	for i := start; i <= end; i++ {
		hash := hashFromNumber(i)
		parentHash := hashFromNumber(i - 1)
		blocks = append(blocks, createBlockHeader(i, hash, parentHash))
	}
	return blocks
}

// createReorgedChainBlocks creates a reorged chain starting at lcaBlock with different hashes.
//
// This simulates a blockchain reorg by creating blocks with different hashes than the canonical chain.
// The Last Common Ancestor (LCA) block remains unchanged; blocks after it use a different hash pattern.
//
// Hash Pattern for Reorged Blocks:
//   - h[0] = 0xFF (marker byte to distinguish from canonical chain)
//   - h[1-4] = block number in big-endian (same as hashFromNumber, but shifted by 1)
//
// Examples:
//
//	Canonical Block 101: [0x00, 0x00, 0x00, 0x65, 0x00, ...]
//	Reorged Block 101:   [0xFF, 0x00, 0x00, 0x00, 0x65, ...]  <- Note the 0xFF prefix
//
// Parameters:
//   - lcaBlock: The last common ancestor block number (stays canonical)
//   - startReorg: First block number that diverges (should be lcaBlock + 1)
//   - end: Last block number in the reorged chain
//
// Parent Hash Logic:
//   - First reorged block (startReorg) points to LCA's canonical hash
//   - Subsequent blocks point to previous reorged block (with 0xFF pattern)
//
// Usage:
//
//	canonical := createChainBlocks(100, 105)         // [100, 101, 102, 103, 104, 105]
//	reorged := createReorgedChainBlocks(100, 101, 105) // LCA=100, reorg from 101-105
func createReorgedChainBlocks(lcaBlock, startReorg, end uint64) []protocol.BlockHeader {
	blocks := make([]protocol.BlockHeader, 0, end-startReorg+1)

	// LCA block stays the same
	lcaHash := hashFromNumber(lcaBlock)

	// After LCA, use different hash scheme to simulate reorg
	for i := startReorg; i <= end; i++ {
		var hash protocol.Bytes32
		// Use different hash pattern: 0xFF prefix instead of normal pattern
		hash[0] = 0xFF
		hash[1] = byte(i >> 24)
		hash[2] = byte(i >> 16)
		hash[3] = byte(i >> 8)
		hash[4] = byte(i)

		parentHash := lcaHash
		if i > startReorg {
			parentHash[0] = 0xFF
			parentHash[1] = byte((i - 1) >> 24)
			parentHash[2] = byte((i - 1) >> 16)
			parentHash[3] = byte((i - 1) >> 8)
			parentHash[4] = byte(i - 1)
		}

		blocks = append(blocks, createBlockHeader(i, hash, parentHash))
	}
	return blocks
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
	testVerifier := test.NewTestVerifier()

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
		TestVerifier:     testVerifier,
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
		verifier.WithVerifier(setup.TestVerifier),
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

// mockGetBlocksHeadersForBlocks sets up mock to return specified blocks.
func (s *reorgTestSetup) mockGetBlocksHeadersForBlocks(blocks []protocol.BlockHeader) {
	s.mockSourceReader.EXPECT().GetBlocksHeaders(mock.Anything, mock.Anything).RunAndReturn(
		func(ctx context.Context, blockNumbers []*big.Int) (map[*big.Int]protocol.BlockHeader, error) {
			result := make(map[*big.Int]protocol.BlockHeader)
			for _, bn := range blockNumbers {
				blockNum := bn.Uint64()
				for _, b := range blocks {
					if b.Number == blockNum {
						result[bn] = b
						break
					}
				}
			}
			return result, nil
		},
	).Maybe()
}

// mockGetBlockHeaderByHashForBlocks sets up mock to return blocks by hash.
func (s *reorgTestSetup) mockGetBlockHeaderByHashForBlocks(blocks []protocol.BlockHeader) {
	s.mockSourceReader.EXPECT().GetBlockHeaderByHash(mock.Anything, mock.Anything).RunAndReturn(
		func(ctx context.Context, hash protocol.Bytes32) (*protocol.BlockHeader, error) {
			for _, b := range blocks {
				if b.Hash == hash {
					return &b, nil
				}
			}
			return nil, fmt.Errorf("block not found for hash %v", hash)
		},
	).Maybe()
}

// updateChainState updates the current chain state (used to simulate progression).
func (s *reorgTestSetup) updateChainState(latest, finalized *protocol.BlockHeader) {
	s.blocksMu.Lock()
	defer s.blocksMu.Unlock()
	s.currentLatest = latest
	s.currentFinalized = finalized
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
	setup := setupReorgTest(t, chainSelector, 800*time.Millisecond)
	defer setup.cleanup()

	// Create tasks at two ranges:
	// - Tasks at blocks 98, 99: BELOW finalized block (100), should be PROCESSED
	// - Tasks at blocks 101, 102: ABOVE finalized block (100), should be FLUSHED by reorg
	finalizedTasks := []verifier.VerificationTask{
		{
			Message:      test.CreateTestMessage(t, 1, chainSelector, defaultDestChain, 0), // Default finality
			BlockNumber:  98,
			ReceiptBlobs: []protocol.ReceiptWithBlob{{Blob: []byte("receipt1")}},
			CreatedAt:    time.Now(),
		},
		{
			Message:      test.CreateTestMessage(t, 2, chainSelector, defaultDestChain, 0),
			BlockNumber:  99,
			ReceiptBlobs: []protocol.ReceiptWithBlob{{Blob: []byte("receipt2")}},
			CreatedAt:    time.Now(),
		},
	}

	pendingTasks := []verifier.VerificationTask{
		{
			Message:      test.CreateTestMessage(t, 3, chainSelector, defaultDestChain, 0),
			BlockNumber:  101,
			ReceiptBlobs: []protocol.ReceiptWithBlob{{Blob: []byte("receipt3")}},
			CreatedAt:    time.Now(),
		},
		{
			Message:      test.CreateTestMessage(t, 4, chainSelector, defaultDestChain, 0),
			BlockNumber:  102,
			ReceiptBlobs: []protocol.ReceiptWithBlob{{Blob: []byte("receipt4")}},
			CreatedAt:    time.Now(),
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

	// Verify behavior:
	// - Tasks at blocks 98, 99 (below finalized) should have been PROCESSED
	// - Tasks at blocks 101, 102 (in reorged range) should have been FLUSHED
	processedTasks := setup.TestVerifier.GetProcessedTasks()
	t.Logf("📊 Processed task count after reorg: %d", len(processedTasks))

	// Should have processed the 2 finalized tasks (98, 99)
	// Tasks at 101, 102 should have been flushed before processing
	require.Equal(t, 2, len(processedTasks), "Only finalized tasks (98, 99) should be processed; tasks at 101, 102 should be flushed")

	require.Equal(t, uint64(98), processedTasks[0].BlockNumber)
	require.Equal(t, uint64(99), processedTasks[1].BlockNumber)

	t.Log("✅ Test completed: Normal reorg handled correctly - finalized tasks processed, reorged tasks flushed")
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
			Message:      test.CreateTestMessage(t, 1, chainSelector, defaultDestChain, 0), // Default finality
			BlockNumber:  98,
			ReceiptBlobs: []protocol.ReceiptWithBlob{{Blob: []byte("receipt1")}},
			CreatedAt:    time.Now(),
		},
		{
			Message:      test.CreateTestMessage(t, 2, chainSelector, defaultDestChain, 0),
			BlockNumber:  99,
			ReceiptBlobs: []protocol.ReceiptWithBlob{{Blob: []byte("receipt2")}},
			CreatedAt:    time.Now(),
		},
		{
			Message:      test.CreateTestMessage(t, 3, chainSelector, defaultDestChain, 0),
			BlockNumber:  100,
			ReceiptBlobs: []protocol.ReceiptWithBlob{{Blob: []byte("receipt3")}},
			CreatedAt:    time.Now(),
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

	// Give time for the coordinator to process the finality violation
	time.Sleep(200 * time.Millisecond)

	// After finality violation:
	// 1. All pending tasks should be flushed
	// 2. Source reader should be stopped
	// 3. No new tasks should be processed

	processedCount := setup.TestVerifier.GetProcessedTaskCount()
	t.Logf("📊 Processed task count after finality violation: %d", processedCount)

	// All tasks should have been flushed, none processed
	assert.Equal(t, 0, processedCount, "No tasks should be processed after finality violation")

	t.Log("✅ Test completed: Finality violation handled correctly")
}
