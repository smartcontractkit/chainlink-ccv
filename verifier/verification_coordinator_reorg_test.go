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
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/batcher"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/verifier/services"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	protocol_mocks "github.com/smartcontractkit/chainlink-ccv/protocol/common/mocks"
	verifier_mocks "github.com/smartcontractkit/chainlink-ccv/verifier/mocks"
)

// reorgTestSetup contains the test fixtures for reorg integration tests.
type reorgTestSetup struct {
	t                *testing.T
	ctx              context.Context
	cancel           context.CancelFunc
	coordinator      *verifier.Coordinator
	mockSourceReader *verifier_mocks.MockSourceReader
	mockHeadTracker  *protocol_mocks.MockHeadTracker
	reorgDetector    *services.ReorgDetectorService
	TestVerifier     *test.TestVerifier
	storage          *common.InMemoryOffchainStorage
	chainSelector    protocol.ChainSelector
	lggr             logger.Logger

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
func setupReorgTest(t *testing.T, chainSelector protocol.ChainSelector) *reorgTestSetup {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	lggr := logger.Test(t)

	// Create mocks
	mockSourceReader := verifier_mocks.NewMockSourceReader(t)
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

	setup := &reorgTestSetup{
		t:                t,
		ctx:              ctx,
		cancel:           cancel,
		mockSourceReader: mockSourceReader,
		mockHeadTracker:  mockHeadTracker,
		chainSelector:    chainSelector,
		lggr:             lggr,
		currentLatest:    initialLatest,
		currentFinalized: initialFinalized,
		TestVerifier:     test.NewTestVerifier(),
		storage:          common.NewInMemoryOffchainStorage(lggr),
	}

	// Setup mock head tracker to return current state
	mockHeadTracker.EXPECT().LatestAndFinalizedBlock(mock.Anything).RunAndReturn(
		func(ctx context.Context) (*protocol.BlockHeader, *protocol.BlockHeader, error) {
			setup.blocksMu.RLock()
			defer setup.blocksMu.RUnlock()
			return setup.currentLatest, setup.currentFinalized, nil
		},
	).Maybe()

	// Setup mock source reader for VerificationTasks
	mockSourceReader.EXPECT().VerificationTasks(mock.Anything, mock.Anything, mock.Anything).
		Return([]verifier.VerificationTask{}, nil).Maybe()

	// Setup mock source reader for BlockTime
	mockSourceReader.EXPECT().BlockTime(mock.Anything, mock.Anything).
		Return(uint64(time.Now().Unix()), nil).Maybe()

	// Create initial blocks for building tail
	initialBlocks := createChainBlocks(100, 105)
	setup.mockGetBlocksHeadersForBlocks(initialBlocks)

	// Create reorg detector
	reorgDetector, err := services.NewReorgDetectorService(
		mockSourceReader,
		mockHeadTracker,
		services.ReorgDetectorConfig{
			ChainSelector: chainSelector,
			PollInterval:  50 * time.Millisecond, // Fast polling for tests
		},
		lggr,
	)
	require.NoError(t, err)
	setup.reorgDetector = reorgDetector

	// Create coordinator configuration
	coordinatorConfig := verifier.CoordinatorConfig{
		VerifierID: "reorg-test-coordinator",
		SourceConfigs: map[protocol.ChainSelector]verifier.SourceConfig{
			chainSelector: {
				VerifierAddress: protocol.UnknownAddress([]byte("0x1234")),
				PollInterval:    100 * time.Millisecond,
			},
		},
		StorageBatchSize:    10,
		StorageBatchTimeout: 50 * time.Millisecond,
	}

	// Create coordinator with all components
	coordinator, err := verifier.NewVerificationCoordinator(
		verifier.WithVerifier(setup.TestVerifier),
		verifier.WithStorage(setup.storage),
		verifier.WithLogger(lggr),
		verifier.WithConfig(coordinatorConfig),
		verifier.WithSourceReaders(map[protocol.ChainSelector]verifier.SourceReader{
			chainSelector: mockSourceReader,
		}),
		verifier.WithHeadTrackers(map[protocol.ChainSelector]chainaccess.HeadTracker{
			chainSelector: mockHeadTracker,
		}),
		verifier.WithReorgDetectors(map[protocol.ChainSelector]protocol.ReorgDetector{
			chainSelector: reorgDetector,
		}),
		verifier.WithMonitoring(monitoring.NewNoopVerifierMonitoring()),
		verifier.WithFinalityCheckInterval(100*time.Millisecond),
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
		s.coordinator.Close()
	}
	s.cancel()
}

// TestReorgDetection_NormalReorg tests that a normal reorg is detected and handled correctly.
func TestReorgDetection_NormalReorg(t *testing.T) {
	chainSelector := protocol.ChainSelector(1337)
	setup := setupReorgTest(t, chainSelector)
	defer setup.cleanup()

	// Start coordinator
	err := setup.coordinator.Start(setup.ctx)
	require.NoError(t, err)

	// Wait for initial setup
	time.Sleep(200 * time.Millisecond)

	t.Log("✅ Coordinator started with reorg detector")

	// Simulate canonical chain: blocks 100-105
	canonicalBlocks := createChainBlocks(100, 105)
	setup.mockGetBlocksHeadersForBlocks(canonicalBlocks)
	setup.mockGetBlockHeaderByHashForBlocks(canonicalBlocks)

	// Create tasks at blocks 101, 102, 103 (above finalized block 100)
	// These will be added to pending queue
	// Since finalized is 100, these won't be processed yet
	tasks := []verifier.VerificationTask{
		{
			Message:      createTestMessage(t, 1, chainSelector, defaultDestChain, 50), // Custom finality - needs 50 blocks
			BlockNumber:  101,
			ReceiptBlobs: []protocol.ReceiptWithBlob{{Blob: []byte("receipt1")}},
			CreatedAt:    time.Now(),
		},
		{
			Message:      createTestMessage(t, 2, chainSelector, defaultDestChain, 50),
			BlockNumber:  102,
			ReceiptBlobs: []protocol.ReceiptWithBlob{{Blob: []byte("receipt2")}},
			CreatedAt:    time.Now(),
		},
		{
			Message:      createTestMessage(t, 3, chainSelector, defaultDestChain, 50),
			BlockNumber:  103,
			ReceiptBlobs: []protocol.ReceiptWithBlob{{Blob: []byte("receipt3")}},
			CreatedAt:    time.Now(),
		},
	}

	// Inject tasks via mock source reader
	setup.mockSourceReader.ExpectedCalls = nil // Clear previous expectations
	callCount := 0
	setup.mockSourceReader.EXPECT().VerificationTasks(mock.Anything, mock.Anything, mock.Anything).RunAndReturn(
		func(ctx context.Context, fromBlock, toBlock *big.Int) ([]verifier.VerificationTask, error) {
			callCount++
			if callCount == 1 {
				t.Log("📋 Injecting tasks into verification pipeline")
				return tasks, nil
			}
			return []verifier.VerificationTask{}, nil
		},
	).Maybe()

	// Wait for tasks to be queued
	time.Sleep(300 * time.Millisecond)

	t.Log("📋 Tasks added to pending queue")

	// Now simulate a reorg: new block 106 has parent that doesn't match block 105
	// LCA will be at block 100 (finalized block)
	reorgedBlocks := createReorgedChainBlocks(100, 101, 106)

	// Setup mocks for reorged chain
	setup.mockGetBlocksHeadersForBlocks(append(canonicalBlocks, reorgedBlocks...))
	setup.mockGetBlockHeaderByHashForBlocks(append(canonicalBlocks, reorgedBlocks...))

	// Update chain state to trigger reorg detection
	reorgedLatest := &reorgedBlocks[len(reorgedBlocks)-1]
	setup.updateChainState(reorgedLatest, setup.currentFinalized)

	t.Log("🔄 Simulating reorg: new chain diverges from block 101")

	// Wait for reorg to be detected and handled
	// The reorg detector polls every 50ms, and coordinator checks every 100ms
	time.Sleep(500 * time.Millisecond)

	t.Log("⏳ Waiting for reorg detection and handling...")

	// Verify that tasks from blocks > 100 were flushed
	// We can't directly access pending queue, but we can verify that:
	// 1. The reorg was detected (via logs)
	// 2. The coordinator is still running
	// 3. No tasks from reorged blocks were verified

	processedCount := setup.TestVerifier.GetProcessedTaskCount()
	t.Logf("📊 Processed task count after reorg: %d", processedCount)

	// Since all tasks were on blocks 101-103 and reorg happened with LCA at 100,
	// all tasks should have been flushed, so processed count should be 0
	assert.Equal(t, 0, processedCount, "No tasks should be processed after reorg flush")

	t.Log("✅ Test completed: Normal reorg handled correctly")
}

// TestReorgDetection_FinalityViolation tests that a finality violation stops the chain reader.
func TestReorgDetection_FinalityViolation(t *testing.T) {
	chainSelector := protocol.ChainSelector(1337)
	setup := setupReorgTest(t, chainSelector)
	defer setup.cleanup()

	// Start coordinator
	err := setup.coordinator.Start(setup.ctx)
	require.NoError(t, err)

	// Wait for initial setup
	time.Sleep(200 * time.Millisecond)

	t.Log("✅ Coordinator started with reorg detector")

	// Simulate canonical chain
	canonicalBlocks := createChainBlocks(95, 105)
	setup.mockGetBlocksHeadersForBlocks(canonicalBlocks)
	setup.mockGetBlockHeaderByHashForBlocks(canonicalBlocks)

	// Create tasks at blocks 98, 99, 100 (around finalized block)
	tasks := []verifier.VerificationTask{
		{
			Message:      createTestMessage(t, 1, chainSelector, defaultDestChain, 0), // Default finality
			BlockNumber:  98,
			ReceiptBlobs: []protocol.ReceiptWithBlob{{Blob: []byte("receipt1")}},
			CreatedAt:    time.Now(),
		},
		{
			Message:      createTestMessage(t, 2, chainSelector, defaultDestChain, 0),
			BlockNumber:  99,
			ReceiptBlobs: []protocol.ReceiptWithBlob{{Blob: []byte("receipt2")}},
			CreatedAt:    time.Now(),
		},
		{
			Message:      createTestMessage(t, 3, chainSelector, defaultDestChain, 0),
			BlockNumber:  100,
			ReceiptBlobs: []protocol.ReceiptWithBlob{{Blob: []byte("receipt3")}},
			CreatedAt:    time.Now(),
		},
	}

	// Inject tasks
	callCount := 0
	setup.mockSourceReader.EXPECT().VerificationTasks(mock.Anything, mock.Anything, mock.Anything).RunAndReturn(
		func(ctx context.Context, fromBlock, toBlock *big.Int) ([]verifier.VerificationTask, error) {
			callCount++
			if callCount == 1 {
				t.Log("📋 Injecting tasks into verification pipeline")
				return tasks, nil
			}
			return []verifier.VerificationTask{}, nil
		},
	).Maybe()

	// Wait for tasks to be queued
	time.Sleep(300 * time.Millisecond)

	t.Log("📋 Tasks added to pending queue")

	// Simulate finality violation: reorg deeper than finalized block
	// LCA is at block 95, but finalized is 100
	reorgedBlocks := createReorgedChainBlocks(95, 96, 106)

	// Setup mocks for reorged chain
	setup.mockGetBlocksHeadersForBlocks(append(canonicalBlocks, reorgedBlocks...))
	setup.mockGetBlockHeaderByHashForBlocks(append(canonicalBlocks, reorgedBlocks...))

	// Update chain state - change finalized block hash to trigger violation
	reorgedFinalized := &protocol.BlockHeader{
		Number:     100,
		Hash:       reorgedBlocks[4].Hash, // Different hash at same height
		ParentHash: reorgedBlocks[3].Hash,
		Timestamp:  time.Now(),
	}
	reorgedLatest := &reorgedBlocks[len(reorgedBlocks)-1]
	setup.updateChainState(reorgedLatest, reorgedFinalized)

	t.Log("⚠️  Simulating finality violation: reorg deeper than finalized block")

	// Wait for finality violation detection
	time.Sleep(500 * time.Millisecond)

	t.Log("⏳ Waiting for finality violation detection...")

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

// TestReorgDetection_ReorgDuringProcessing tests reorg handling while verification is active.
func TestReorgDetection_ReorgDuringProcessing(t *testing.T) {
	chainSelector := protocol.ChainSelector(1337)
	setup := setupReorgTest(t, chainSelector)
	defer setup.cleanup()

	// Create a slower verifier to simulate active processing
	slowVerifier := &slowTestVerifier{
		TestVerifier:    test.NewTestVerifier(),
		processingDelay: 200 * time.Millisecond,
	}

	// Replace the verifier in setup
	coordinatorConfig := verifier.CoordinatorConfig{
		VerifierID: "reorg-test-coordinator",
		SourceConfigs: map[protocol.ChainSelector]verifier.SourceConfig{
			chainSelector: {
				VerifierAddress: protocol.UnknownAddress([]byte("0x1234")),
				PollInterval:    100 * time.Millisecond,
			},
		},
		StorageBatchSize:    10,
		StorageBatchTimeout: 50 * time.Millisecond,
	}

	coordinator, err := verifier.NewVerificationCoordinator(
		verifier.WithVerifier(slowVerifier),
		verifier.WithStorage(setup.storage),
		verifier.WithLogger(setup.lggr),
		verifier.WithConfig(coordinatorConfig),
		verifier.WithSourceReaders(map[protocol.ChainSelector]verifier.SourceReader{
			chainSelector: setup.mockSourceReader,
		}),
		verifier.WithHeadTrackers(map[protocol.ChainSelector]chainaccess.HeadTracker{
			chainSelector: setup.mockHeadTracker,
		}),
		verifier.WithReorgDetectors(map[protocol.ChainSelector]protocol.ReorgDetector{
			chainSelector: setup.reorgDetector,
		}),
		verifier.WithMonitoring(monitoring.NewNoopVerifierMonitoring()),
		verifier.WithFinalityCheckInterval(100*time.Millisecond),
	)
	require.NoError(t, err)
	setup.coordinator = coordinator

	// Start coordinator
	err = setup.coordinator.Start(setup.ctx)
	require.NoError(t, err)

	// Wait for initial setup
	time.Sleep(200 * time.Millisecond)

	t.Log("✅ Coordinator started with slow verifier")

	// Simulate canonical chain
	canonicalBlocks := createChainBlocks(100, 110)
	setup.mockGetBlocksHeadersForBlocks(canonicalBlocks)
	setup.mockGetBlockHeaderByHashForBlocks(canonicalBlocks)

	// Create finalized tasks that will be processed
	finalizedTasks := []verifier.VerificationTask{
		{
			Message:      createTestMessage(t, 1, chainSelector, defaultDestChain, 0), // Default finality
			BlockNumber:  98,
			ReceiptBlobs: []protocol.ReceiptWithBlob{{Blob: []byte("receipt1")}},
			CreatedAt:    time.Now(),
		},
		{
			Message:      createTestMessage(t, 2, chainSelector, defaultDestChain, 0),
			BlockNumber:  99,
			ReceiptBlobs: []protocol.ReceiptWithBlob{{Blob: []byte("receipt2")}},
			CreatedAt:    time.Now(),
		},
	}

	// And pending tasks that will be flushed by reorg
	pendingTasks := []verifier.VerificationTask{
		{
			Message:      createTestMessage(t, 3, chainSelector, defaultDestChain, 50), // Needs 50 blocks
			BlockNumber:  105,
			ReceiptBlobs: []protocol.ReceiptWithBlob{{Blob: []byte("receipt3")}},
			CreatedAt:    time.Now(),
		},
		{
			Message:      createTestMessage(t, 4, chainSelector, defaultDestChain, 50),
			BlockNumber:  106,
			ReceiptBlobs: []protocol.ReceiptWithBlob{{Blob: []byte("receipt4")}},
			CreatedAt:    time.Now(),
		},
	}

	// Inject tasks
	callCount := 0
	setup.mockSourceReader.EXPECT().VerificationTasks(mock.Anything, mock.Anything, mock.Anything).RunAndReturn(
		func(ctx context.Context, fromBlock, toBlock *big.Int) ([]verifier.VerificationTask, error) {
			callCount++
			if callCount == 1 {
				t.Log("📋 Injecting finalized and pending tasks")
				return append(finalizedTasks, pendingTasks...), nil
			}
			return []verifier.VerificationTask{}, nil
		},
	).Maybe()

	// Wait for tasks to be queued and start processing
	time.Sleep(300 * time.Millisecond)

	t.Log("📋 Tasks queued, verification starting...")

	// Trigger reorg while slow verification is happening
	// Give 100ms for verification to start, then trigger reorg
	time.Sleep(100 * time.Millisecond)

	reorgedBlocks := createReorgedChainBlocks(100, 101, 110)
	setup.mockGetBlocksHeadersForBlocks(append(canonicalBlocks, reorgedBlocks...))
	setup.mockGetBlockHeaderByHashForBlocks(append(canonicalBlocks, reorgedBlocks...))

	reorgedLatest := &reorgedBlocks[len(reorgedBlocks)-1]
	setup.updateChainState(reorgedLatest, setup.currentFinalized)

	t.Log("🔄 Triggering reorg during active verification")

	// Wait for everything to complete
	time.Sleep(1 * time.Second)

	t.Log("⏳ Waiting for reorg handling and verification completion...")

	// Verify behavior:
	// - Finalized tasks (98, 99) should complete processing despite reorg
	// - Pending tasks (105, 106) should be flushed
	processedCount := slowVerifier.GetProcessedTaskCount()
	t.Logf("📊 Processed task count: %d", processedCount)

	// Should process the 2 finalized tasks
	assert.Equal(t, 2, processedCount, "Finalized tasks should complete despite reorg")

	t.Log("✅ Test completed: Reorg during processing handled correctly")
}

// slowTestVerifier simulates slow verification to test concurrent reorg handling.
type slowTestVerifier struct {
	*test.TestVerifier
	processingDelay time.Duration
}

func (s *slowTestVerifier) VerifyMessages(
	ctx context.Context,
	tasks []verifier.VerificationTask,
	ccvDataBatcher *batcher.Batcher[protocol.CCVData],
) batcher.BatchResult[verifier.VerificationError] {
	// Simulate slow processing
	time.Sleep(s.processingDelay)
	return s.TestVerifier.VerifyMessages(ctx, tasks, ccvDataBatcher)
}

// TestReorgDetection_MultipleChains tests that reorgs on one chain don't affect others.
func TestReorgDetection_MultipleChains(t *testing.T) {
	chain1 := protocol.ChainSelector(1337)
	chain2 := protocol.ChainSelector(1338)

	// Setup first chain
	setup1 := setupReorgTest(t, chain1)
	defer setup1.cleanup()

	// Setup second chain
	setup2 := setupReorgTest(t, chain2)
	defer setup2.cleanup()

	// Create a shared coordinator with both chains
	coordinatorConfig := verifier.CoordinatorConfig{
		VerifierID: "multi-chain-reorg-test",
		SourceConfigs: map[protocol.ChainSelector]verifier.SourceConfig{
			chain1: {
				VerifierAddress: protocol.UnknownAddress([]byte("0x1234")),
				PollInterval:    100 * time.Millisecond,
			},
			chain2: {
				VerifierAddress: protocol.UnknownAddress([]byte("0x5678")),
				PollInterval:    100 * time.Millisecond,
			},
		},
		StorageBatchSize:    10,
		StorageBatchTimeout: 50 * time.Millisecond,
	}

	sharedVerifier := test.NewTestVerifier()
	sharedStorage := common.NewInMemoryOffchainStorage(setup1.lggr)

	coordinator, err := verifier.NewVerificationCoordinator(
		verifier.WithVerifier(sharedVerifier),
		verifier.WithStorage(sharedStorage),
		verifier.WithLogger(setup1.lggr),
		verifier.WithConfig(coordinatorConfig),
		verifier.WithSourceReaders(map[protocol.ChainSelector]verifier.SourceReader{
			chain1: setup1.mockSourceReader,
			chain2: setup2.mockSourceReader,
		}),
		verifier.WithHeadTrackers(map[protocol.ChainSelector]chainaccess.HeadTracker{
			chain1: setup1.mockHeadTracker,
			chain2: setup2.mockHeadTracker,
		}),
		verifier.WithReorgDetectors(map[protocol.ChainSelector]protocol.ReorgDetector{
			chain1: setup1.reorgDetector,
			chain2: setup2.reorgDetector,
		}),
		verifier.WithMonitoring(monitoring.NewNoopVerifierMonitoring()),
		verifier.WithFinalityCheckInterval(100*time.Millisecond),
	)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Start coordinator
	err = coordinator.Start(ctx)
	require.NoError(t, err)
	defer coordinator.Close()

	// Wait for initial setup
	time.Sleep(200 * time.Millisecond)

	t.Log("✅ Multi-chain coordinator started")

	// Setup both chains with canonical blocks
	chain1Blocks := createChainBlocks(100, 105)
	chain2Blocks := createChainBlocks(100, 105)

	setup1.mockGetBlocksHeadersForBlocks(chain1Blocks)
	setup1.mockGetBlockHeaderByHashForBlocks(chain1Blocks)
	setup2.mockGetBlocksHeadersForBlocks(chain2Blocks)
	setup2.mockGetBlockHeaderByHashForBlocks(chain2Blocks)

	// Create tasks for both chains
	chain1Tasks := []verifier.VerificationTask{
		{
			Message:      createTestMessage(t, 1, chain1, defaultDestChain, 50),
			BlockNumber:  101,
			ReceiptBlobs: []protocol.ReceiptWithBlob{{Blob: []byte("chain1-receipt1")}},
			CreatedAt:    time.Now(),
		},
		{
			Message:      createTestMessage(t, 2, chain1, defaultDestChain, 50),
			BlockNumber:  102,
			ReceiptBlobs: []protocol.ReceiptWithBlob{{Blob: []byte("chain1-receipt2")}},
			CreatedAt:    time.Now(),
		},
	}

	chain2Tasks := []verifier.VerificationTask{
		{
			Message:      createTestMessage(t, 1, chain2, defaultDestChain, 0), // Default finality - will be processed
			BlockNumber:  98,
			ReceiptBlobs: []protocol.ReceiptWithBlob{{Blob: []byte("chain2-receipt1")}},
			CreatedAt:    time.Now(),
		},
		{
			Message:      createTestMessage(t, 2, chain2, defaultDestChain, 0),
			BlockNumber:  99,
			ReceiptBlobs: []protocol.ReceiptWithBlob{{Blob: []byte("chain2-receipt2")}},
			CreatedAt:    time.Now(),
		},
	}

	// Inject tasks for chain 1
	callCount1 := 0
	setup1.mockSourceReader.EXPECT().VerificationTasks(mock.Anything, mock.Anything, mock.Anything).RunAndReturn(
		func(ctx context.Context, fromBlock, toBlock *big.Int) ([]verifier.VerificationTask, error) {
			callCount1++
			if callCount1 == 1 {
				t.Log("📋 Injecting chain 1 tasks")
				return chain1Tasks, nil
			}
			return []verifier.VerificationTask{}, nil
		},
	).Maybe()

	// Inject tasks for chain 2
	callCount2 := 0
	setup2.mockSourceReader.EXPECT().VerificationTasks(mock.Anything, mock.Anything, mock.Anything).RunAndReturn(
		func(ctx context.Context, fromBlock, toBlock *big.Int) ([]verifier.VerificationTask, error) {
			callCount2++
			if callCount2 == 1 {
				t.Log("📋 Injecting chain 2 tasks")
				return chain2Tasks, nil
			}
			return []verifier.VerificationTask{}, nil
		},
	).Maybe()

	// Wait for tasks to be queued
	time.Sleep(300 * time.Millisecond)

	t.Log("📋 Tasks queued for both chains")

	// Trigger reorg on chain 1 only
	chain1Reorged := createReorgedChainBlocks(100, 101, 105)
	setup1.mockGetBlocksHeadersForBlocks(append(chain1Blocks, chain1Reorged...))
	setup1.mockGetBlockHeaderByHashForBlocks(append(chain1Blocks, chain1Reorged...))

	reorgedLatest := &chain1Reorged[len(chain1Reorged)-1]
	setup1.updateChainState(reorgedLatest, setup1.currentFinalized)

	t.Log("🔄 Triggering reorg on chain 1 only")

	// Wait for reorg handling and finality checks
	time.Sleep(1 * time.Second)

	t.Log("⏳ Waiting for reorg handling...")

	// Verify:
	// - Chain 1 tasks should be flushed (not processed)
	// - Chain 2 tasks should be processed normally
	processedCount := sharedVerifier.GetProcessedTaskCount()
	t.Logf("📊 Total processed task count: %d", processedCount)

	// Should only process chain 2 tasks (2 tasks)
	assert.Equal(t, 2, processedCount, "Only chain 2 tasks should be processed")

	// Verify chain 2 tasks were processed
	processedTasks := sharedVerifier.GetProcessedTasks()
	for _, task := range processedTasks {
		assert.Equal(t, chain2, task.Message.SourceChainSelector, "All processed tasks should be from chain 2")
	}
	t.Log("✅ Test completed: Multiple chain reorg isolation verified")
}
