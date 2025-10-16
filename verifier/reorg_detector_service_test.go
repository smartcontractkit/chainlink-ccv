package verifier_test

import (
	"context"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
	"github.com/smartcontractkit/chainlink-ccv/verifier/internal/verifier_mocks"
)

// mockBlockchain simulates a blockchain with the ability to create reorgs
type mockBlockchain struct {
	blocks map[uint64]protocol.BlockHeader
	tip    uint64
}

func newMockBlockchain() *mockBlockchain {
	return &mockBlockchain{
		blocks: make(map[uint64]protocol.BlockHeader),
		tip:    0,
	}
}

func (m *mockBlockchain) addBlock(number uint64, parentHash protocol.Bytes32) protocol.BlockHeader {
	hash := protocol.Bytes32{}
	// Simple hash generation: just use block number
	hash[0] = byte(number)
	hash[1] = byte(number >> 8)

	header := protocol.BlockHeader{
		Number:     number,
		Hash:       hash,
		ParentHash: parentHash,
		Timestamp:  uint64(time.Now().Unix()),
	}
	m.blocks[number] = header
	if number > m.tip {
		m.tip = number
	}
	return header
}

func (m *mockBlockchain) initializeChain(numBlocks uint64) {
	// Genesis block
	genesis := protocol.BlockHeader{
		Number:     0,
		Hash:       protocol.Bytes32{0xFF},
		ParentHash: protocol.Bytes32{},
		Timestamp:  uint64(time.Now().Unix()),
	}
	m.blocks[0] = genesis

	// Build chain
	for i := uint64(1); i <= numBlocks; i++ {
		parent := m.blocks[i-1]
		m.addBlock(i, parent.Hash)
	}
	m.tip = numBlocks
}

func (m *mockBlockchain) createReorg(fromBlock uint64, newBlocks uint64) {
	// Get the parent of the fork point
	parent := m.blocks[fromBlock-1]

	// Create new blocks from the fork point
	for i := uint64(0); i < newBlocks; i++ {
		blockNum := fromBlock + i
		hash := protocol.Bytes32{}
		// Different hash from original (add 0x80 to distinguish)
		hash[0] = byte(blockNum) | 0x80
		hash[1] = byte(blockNum>>8) | 0x80

		header := protocol.BlockHeader{
			Number:     blockNum,
			Hash:       hash,
			ParentHash: parent.Hash,
			Timestamp:  uint64(time.Now().Unix()),
		}
		m.blocks[blockNum] = header
		parent = header

		if blockNum > m.tip {
			m.tip = blockNum
		}
	}
}

func (m *mockBlockchain) getBlock(number uint64) *protocol.BlockHeader {
	if block, ok := m.blocks[number]; ok {
		return &block
	}
	return nil
}

// setupReorgDetectorMockSourceReader creates a mock SourceReader backed by a mockBlockchain
func setupReorgDetectorMockSourceReader(t *testing.T, blockchain *mockBlockchain) *verifier_mocks.MockSourceReader {
	mockReader := verifier_mocks.NewMockSourceReader(t)

	// LatestFinalizedBlockHeight
	mockReader.On("LatestFinalizedBlockHeight", mock.Anything).
		Return(func(context.Context) *big.Int {
			// Finality is 64 blocks behind tip
			finalizedBlock := blockchain.tip
			if finalizedBlock > 64 {
				finalizedBlock -= 64
			}
			return big.NewInt(int64(finalizedBlock))
		}, func(context.Context) error { return nil })

	// LatestBlockHeight
	mockReader.On("LatestBlockHeight", mock.Anything).
		Return(func(context.Context) *big.Int {
			return big.NewInt(int64(blockchain.tip))
		}, func(context.Context) error { return nil })

	// GetBlockHeader
	mockReader.On("GetBlockHeader", mock.Anything, mock.Anything).
		Return(func(_ context.Context, blockNum *big.Int) *protocol.BlockHeader {
			return blockchain.getBlock(blockNum.Uint64())
		}, func(_ context.Context, blockNum *big.Int) error {
			block := blockchain.getBlock(blockNum.Uint64())
			if block == nil {
				return fmt.Errorf("block not found: %d", blockNum.Uint64())
			}
			return nil
		})

	// GetBlockHash
	mockReader.On("GetBlockHash", mock.Anything, mock.Anything).
		Return(func(_ context.Context, blockNum *big.Int) protocol.Bytes32 {
			block := blockchain.getBlock(blockNum.Uint64())
			if block == nil {
				return protocol.Bytes32{}
			}
			return block.Hash
		}, func(_ context.Context, blockNum *big.Int) error {
			block := blockchain.getBlock(blockNum.Uint64())
			if block == nil {
				return fmt.Errorf("block not found: %d", blockNum.Uint64())
			}
			return nil
		})

	return mockReader
}

func TestReorgDetectorService_Initialization(t *testing.T) {
	t.Skip("TODO: Implement integration test to verify coordinator flushes tasks before reader reset")

	ctx := context.Background()
	lggr := logger.Test(t)

	// Setup blockchain with 200 blocks
	blockchain := newMockBlockchain()
	blockchain.initializeChain(200)

	// Create heads channel
	headsCh := make(chan protocol.BlockHeader, 10)

	// Create a minimal mock without using setupReorgDetectorMockSourceReader
	// to avoid assertions on unused mock expectations
	mockReader := verifier_mocks.NewMockSourceReader(t)

	// Only mock what's actually needed for initialization
	mockReader.On("LatestFinalizedBlockHeight", mock.Anything).
		Return(big.NewInt(136), nil).Maybe()

	mockReader.On("GetBlockHeader", mock.Anything, mock.Anything).
		Return(func(_ context.Context, blockNum *big.Int) *protocol.BlockHeader {
			return blockchain.getBlock(blockNum.Uint64())
		}, func(_ context.Context, blockNum *big.Int) error {
			block := blockchain.getBlock(blockNum.Uint64())
			if block == nil {
				return fmt.Errorf("block not found: %d", blockNum.Uint64())
			}
			return nil
		}).Maybe()

	mockReader.On("SubscribeNewHeads", mock.Anything).
		Return((<-chan protocol.BlockHeader)(headsCh), nil).Once()

	config := verifier.ReorgDetectorConfig{
		ChainSelector: protocol.ChainSelector(1),
		FinalityDepth: 64,
	}

	detector, err := verifier.NewReorgDetectorService(mockReader, config, lggr)
	require.NoError(t, err)

	// Start should block until initial tail is built
	statusCh, err := detector.Start(ctx)
	require.NoError(t, err)
	require.NotNil(t, statusCh)

	// Clean up
	err = detector.Close()
	require.NoError(t, err)
}

func TestReorgDetectorService_RegularReorg(t *testing.T) {
	t.Skip("TODO: Implement integration test to verify coordinator flushes tasks before reader reset")

	ctx := context.Background()
	lggr := logger.Test(t)

	// Setup blockchain with 200 blocks
	blockchain := newMockBlockchain()
	blockchain.initializeChain(200)

	// Create heads channel
	headsCh := make(chan protocol.BlockHeader, 10)

	mockReader := setupReorgDetectorMockSourceReader(t, blockchain)
	mockReader.On("SubscribeNewHeads", mock.Anything).
		Return((<-chan protocol.BlockHeader)(headsCh), nil).Once()

	config := verifier.ReorgDetectorConfig{
		ChainSelector: protocol.ChainSelector(1),
		FinalityDepth: 64,
	}

	detector, err := verifier.NewReorgDetectorService(mockReader, config, lggr)
	require.NoError(t, err)

	statusCh, err := detector.Start(ctx)
	require.NoError(t, err)

	// Wait a bit for initialization
	time.Sleep(100 * time.Millisecond)

	// Create a reorg at block 180 (depth = 10, which is < FinalityDepth)
	blockchain.createReorg(180, 25)

	// Send the reorged block
	reorgedBlock := blockchain.getBlock(180)
	require.NotNil(t, reorgedBlock)
	headsCh <- *reorgedBlock

	// Should receive ChainStatusReorg
	select {
	case status := <-statusCh:
		reorgStatus, ok := status.(protocol.ChainStatusReorg)
		require.True(t, ok, "Expected ChainStatusReorg, got %T", status)
		assert.Equal(t, uint64(179), reorgStatus.CommonAncestorBlock)
		t.Logf("Received regular reorg notification: commonAncestor=%d", reorgStatus.CommonAncestorBlock)
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for reorg notification")
	}

	// Clean up
	err = detector.Close()
	require.NoError(t, err)
}

func TestReorgDetectorService_FinalityViolation(t *testing.T) {
	t.Skip("TODO: Implement integration test to verify coordinator flushes tasks before reader reset")
	ctx := context.Background()
	lggr := logger.Test(t)

	// Setup blockchain with 200 blocks
	blockchain := newMockBlockchain()
	blockchain.initializeChain(200)

	// Create heads channel
	headsCh := make(chan protocol.BlockHeader, 10)

	mockReader := setupReorgDetectorMockSourceReader(t, blockchain)
	mockReader.On("SubscribeNewHeads", mock.Anything).
		Return((<-chan protocol.BlockHeader)(headsCh), nil).Once()

	config := verifier.ReorgDetectorConfig{
		ChainSelector: protocol.ChainSelector(1),
		FinalityDepth: 64,
	}

	detector, err := verifier.NewReorgDetectorService(mockReader, config, lggr)
	require.NoError(t, err)

	statusCh, err := detector.Start(ctx)
	require.NoError(t, err)

	// Wait a bit for initialization
	time.Sleep(100 * time.Millisecond)

	// Create a deep reorg at block 100 (depth = 90, which is > FinalityDepth of 64)
	blockchain.createReorg(100, 105)

	// Send the reorged block
	reorgedBlock := blockchain.getBlock(100)
	require.NotNil(t, reorgedBlock)
	headsCh <- *reorgedBlock

	// Should receive ChainStatusFinalityViolated
	select {
	case status := <-statusCh:
		violationStatus, ok := status.(protocol.ChainStatusFinalityViolated)
		require.True(t, ok, "Expected ChainStatusFinalityViolated, got %T", status)
		assert.Equal(t, uint64(99), violationStatus.SafeRestartBlock)
		t.Logf("Received finality violation notification: safeRestart=%d", violationStatus.SafeRestartBlock)
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for finality violation notification")
	}

	// Clean up
	err = detector.Close()
	require.NoError(t, err)
}

func TestReorgDetectorService_GapDetectionAndBackfill(t *testing.T) {
	t.Skip("TODO: Implement integration test to verify coordinator flushes tasks before reader reset")
	ctx := context.Background()
	lggr := logger.Test(t)

	// Setup blockchain with 200 blocks
	blockchain := newMockBlockchain()
	blockchain.initializeChain(200)

	// Create heads channel
	headsCh := make(chan protocol.BlockHeader, 10)

	mockReader := setupReorgDetectorMockSourceReader(t, blockchain)
	mockReader.On("SubscribeNewHeads", mock.Anything).
		Return((<-chan protocol.BlockHeader)(headsCh), nil).Once()

	config := verifier.ReorgDetectorConfig{
		ChainSelector: protocol.ChainSelector(1),
		FinalityDepth: 64,
	}

	detector, err := verifier.NewReorgDetectorService(mockReader, config, lggr)
	require.NoError(t, err)

	statusCh, err := detector.Start(ctx)
	require.NoError(t, err)

	// Wait a bit for initialization
	time.Sleep(100 * time.Millisecond)

	// Add new blocks to blockchain
	for i := uint64(201); i <= 205; i++ {
		parent := blockchain.getBlock(i - 1)
		blockchain.addBlock(i, parent.Hash)
	}

	// Send block 205 (creates a gap from 201-204)
	block205 := blockchain.getBlock(205)
	require.NotNil(t, block205)
	headsCh <- *block205

	// Give it time to backfill
	time.Sleep(500 * time.Millisecond)

	// Should NOT receive any status updates (no reorg)
	select {
	case status := <-statusCh:
		t.Fatalf("Unexpected status update during gap backfill: %T", status)
	case <-time.After(500 * time.Millisecond):
		// Expected - no status update for normal gap backfill
	}

	// Clean up
	err = detector.Close()
	require.NoError(t, err)
}

func TestReorgDetectorService_NewBlocksWithoutReorg(t *testing.T) {
	t.Skip("TODO: Implement integration test to verify coordinator flushes tasks before reader reset")
	ctx := context.Background()
	lggr := logger.Test(t)

	// Setup blockchain with 200 blocks
	blockchain := newMockBlockchain()
	blockchain.initializeChain(200)

	// Create heads channel
	headsCh := make(chan protocol.BlockHeader, 10)

	mockReader := setupReorgDetectorMockSourceReader(t, blockchain)
	mockReader.On("SubscribeNewHeads", mock.Anything).
		Return((<-chan protocol.BlockHeader)(headsCh), nil).Once()

	config := verifier.ReorgDetectorConfig{
		ChainSelector: protocol.ChainSelector(1),
		FinalityDepth: 64,
	}

	detector, err := verifier.NewReorgDetectorService(mockReader, config, lggr)
	require.NoError(t, err)

	statusCh, err := detector.Start(ctx)
	require.NoError(t, err)

	// Wait a bit for initialization
	time.Sleep(100 * time.Millisecond)

	// Add new blocks (no reorg)
	for i := uint64(201); i <= 210; i++ {
		parent := blockchain.getBlock(i - 1)
		newBlock := blockchain.addBlock(i, parent.Hash)
		headsCh <- newBlock
		time.Sleep(10 * time.Millisecond)
	}

	// Should NOT receive any status updates (no reorg)
	select {
	case status := <-statusCh:
		t.Fatalf("Unexpected status update for normal blocks: %T", status)
	case <-time.After(500 * time.Millisecond):
		// Expected - no status update for normal operation
	}

	// Clean up
	err = detector.Close()
	require.NoError(t, err)
}

func TestReorgDetectorService_ConfigValidation(t *testing.T) {
	t.Skip("TODO: Implement integration test to verify coordinator flushes tasks before reader reset")
	lggr := logger.Test(t)

	tests := []struct {
		name        string
		reader      verifier.SourceReader
		config      verifier.ReorgDetectorConfig
		lggr        logger.Logger
		expectedErr string
	}{
		{
			name:        "nil source reader",
			reader:      nil,
			config:      verifier.ReorgDetectorConfig{ChainSelector: 1},
			lggr:        lggr,
			expectedErr: "source reader is required",
		},
		{
			name:        "zero chain selector",
			reader:      verifier_mocks.NewMockSourceReader(nil),
			config:      verifier.ReorgDetectorConfig{ChainSelector: 0},
			lggr:        lggr,
			expectedErr: "chain selector is required",
		},
		{
			name:        "nil logger",
			reader:      verifier_mocks.NewMockSourceReader(nil),
			config:      verifier.ReorgDetectorConfig{ChainSelector: 1},
			lggr:        nil,
			expectedErr: "logger is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := verifier.NewReorgDetectorService(tt.reader, tt.config, tt.lggr)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedErr)
		})
	}
}

func TestReorgDetectorService_DefaultConfiguration(t *testing.T) {
	t.Skip("TODO: Implement integration test to verify coordinator flushes tasks before reader reset")
	lggr := logger.Test(t)
	mockReader := verifier_mocks.NewMockSourceReader(nil)

	config := verifier.ReorgDetectorConfig{
		ChainSelector: protocol.ChainSelector(1),
		// FinalityDepth not set - should default to 64
	}

	detector, err := verifier.NewReorgDetectorService(mockReader, config, lggr)
	require.NoError(t, err)
	require.NotNil(t, detector)

	// Check config was set with defaults
	// Note: We can't directly access detector.config since it's not exported
	// This test just verifies the detector was created successfully with default config
}
