package verifier

import (
	"context"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	protocol_mocks "github.com/smartcontractkit/chainlink-ccv/protocol/common/mocks"
)

const (
	InitialLatestBlock    = 1000
	InitialFinalizedBlock = 950
)

func TestFinality_FinalizedMessage(t *testing.T) {
	setup := initializeCoordinator(t, "test-finality-coordinator")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err := setup.coordinator.Start(ctx)
	require.NoError(t, err)
	defer func() {
		if err := setup.coordinator.Close(); err != nil {
			t.Logf("Error closing coordinator: %v", err)
		}
	}()

	// Message at block 940 (< finalized 950) should be processed immediately
	finalizedMessage := CreateTestMessage(t, 1, 1337, 2337, 0, 300_000)
	messageID, _ := finalizedMessage.MessageID()

	// Create test CCV and executor addresses matching those in CreateTestMessage
	ccvAddr := make([]byte, 20)
	ccvAddr[0] = 0x11

	executorAddr := make([]byte, 20)
	executorAddr[0] = 0x22

	finalizedEvent := protocol.MessageSentEvent{
		DestChainSelector: finalizedMessage.DestChainSelector,
		SequenceNumber:    uint64(finalizedMessage.SequenceNumber),
		MessageID:         messageID,
		Message:           finalizedMessage,
		Receipts: []protocol.ReceiptWithBlob{
			{
				Issuer:            protocol.UnknownAddress(ccvAddr),
				DestGasLimit:      300000,
				DestBytesOverhead: 100,
				Blob:              []byte("test-blob"),
				ExtraArgs:         []byte{}, // Empty = default finality
			},
			{
				// Executor receipt - always at the end
				Issuer:            protocol.UnknownAddress(executorAddr),
				DestGasLimit:      0,
				DestBytesOverhead: 0,
				Blob:              []byte{},
				ExtraArgs:         []byte{},
			},
		},
		BlockNumber: InitialFinalizedBlock - 10, // 940 <= 950 (finalized), should be processed immediately
	}

	// Send message
	setup.sentEventsCh <- finalizedEvent
	// Wait for processing (poll interval is 100ms, add some buffer)
	time.Sleep(200 * time.Millisecond)

	// Should have processed the finalized message
	processedCount := setup.mockVerifier.GetProcessedTaskCount()
	require.Equal(t, 1, processedCount, "Should have processed the finalized message")
}

func TestFinality_CustomFinality(t *testing.T) {
	setup := initializeCoordinator(t, "test-custom-finality-coordinator")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err := setup.coordinator.Start(ctx)
	require.NoError(t, err)
	defer func() {
		if err := setup.coordinator.Close(); err != nil {
			t.Logf("Error closing coordinator: %v", err)
		}
	}()

	customFinality := uint16(15)
	customGasLimit := uint32(300_000)

	readyMessage := CreateTestMessage(t, 1, 1337, 2337, customFinality, customGasLimit)
	messageID, _ := readyMessage.MessageID()

	// Create test CCV and executor addresses matching those in CreateTestMessage
	ccvAddr := make([]byte, 20)
	ccvAddr[0] = 0x11

	executorAddr := make([]byte, 20)
	executorAddr[0] = 0x22

	readyEvent := protocol.MessageSentEvent{
		DestChainSelector: readyMessage.DestChainSelector,
		SequenceNumber:    uint64(readyMessage.SequenceNumber),
		MessageID:         messageID,
		Message:           readyMessage,
		Receipts: []protocol.ReceiptWithBlob{
			{
				Issuer:            protocol.UnknownAddress(ccvAddr),
				DestGasLimit:      300000,
				DestBytesOverhead: 100,
				Blob:              []byte("test-blob"),
				ExtraArgs:         []byte{},
			},
			{
				// Executor receipt - always at the end
				Issuer:            protocol.UnknownAddress(executorAddr),
				DestGasLimit:      0,
				DestBytesOverhead: 0,
				Blob:              []byte{},
				ExtraArgs:         []byte{},
			},
		},
		BlockNumber: uint64(InitialLatestBlock - customFinality), // should be ready
	}

	// Send message
	setup.sentEventsCh <- readyEvent
	// Wait for processing (poll interval is 100ms, add some buffer)
	time.Sleep(200 * time.Millisecond)

	// Should have processed the ready message
	processedCount := setup.mockVerifier.GetProcessedTaskCount()
	require.Equal(t, 1, processedCount, "Should have processed the ready message")
}

func TestFinality_WaitingForFinality(t *testing.T) {
	setup := initializeCoordinator(t, "test-finality-coordinator")

	// Use a context with timeout to prevent hanging forever
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err := setup.coordinator.Start(ctx)
	require.NoError(t, err)
	defer func() {
		// Ensure coordinator is stopped and all goroutines are cleaned up
		if err := setup.coordinator.Close(); err != nil {
			t.Logf("Error closing coordinator: %v", err)
		}
	}()

	nonFinalizedMessage := CreateTestMessage(t, 1, 1337, 2337, 0, 300_000)
	nonFinalizedBlock := InitialFinalizedBlock + 10
	messageID, _ := nonFinalizedMessage.MessageID()

	// Create test CCV and executor addresses matching those in CreateTestMessage
	ccvAddr := make([]byte, 20)
	ccvAddr[0] = 0x11

	executorAddr := make([]byte, 20)
	executorAddr[0] = 0x22

	nonFinalizedEvent := protocol.MessageSentEvent{
		DestChainSelector: nonFinalizedMessage.DestChainSelector,
		SequenceNumber:    uint64(nonFinalizedMessage.SequenceNumber),
		MessageID:         messageID,
		Message:           nonFinalizedMessage,
		Receipts: []protocol.ReceiptWithBlob{
			{
				Issuer:            protocol.UnknownAddress(ccvAddr),
				DestGasLimit:      300000,
				DestBytesOverhead: 100,
				Blob:              []byte("test-blob"),
				ExtraArgs:         []byte{}, // Empty = default finality
			},
			{
				// Executor receipt - always at the end
				Issuer:            protocol.UnknownAddress(executorAddr),
				DestGasLimit:      0,
				DestBytesOverhead: 0,
				Blob:              []byte{},
				ExtraArgs:         []byte{},
			},
		},
		BlockNumber: uint64(nonFinalizedBlock), // should be waiting for finality
	}

	// Send message with timeout
	select {
	case setup.sentEventsCh <- nonFinalizedEvent:
		// Successfully sent
	case <-ctx.Done():
		t.Fatal("Timeout sending event to verification channel")
	}

	// Wait for task to be added to finality queue (poll interval is 50ms)
	// Give it enough time to be picked up but not processed
	time.Sleep(150 * time.Millisecond)

	// Should NOT have processed the non-finalized message yet
	processedCount := setup.mockVerifier.GetProcessedTaskCount()
	require.Equal(t, 0, processedCount, "Should not have processed the non-finalized message")

	// Update the shared variable to simulate finalized block advancing
	setup.setFinalizedBlock(uint64(nonFinalizedBlock))
	// TODO: This is a hack because the mock doesn't keep on returning the event if it's within range once it's sent to channel.
	//  This is purely a mock limitation.
	select {
	case setup.sentEventsCh <- nonFinalizedEvent:
		// Successfully sent
	case <-ctx.Done():
		t.Fatal("Timeout sending event to verification channel")
	}

	// Poll until message is processed or timeout
	deadline := time.Now().Add(2 * time.Second)
	processed := false
	for time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
		if setup.mockVerifier.GetProcessedTaskCount() == 1 {
			processed = true
			break
		}
	}

	// Should have processed the now-finalized message
	require.True(t, processed, "Message should have been processed after finality reached")
	processedCount = setup.mockVerifier.GetProcessedTaskCount()
	require.Equal(t, 1, processedCount, "Should have processed exactly 1 message")
}

type coordinatorTestSetup struct {
	coordinator           *Coordinator
	mockSourceReader      *mocks.MockSourceReader
	mockVerifier          *TestVerifier
	sentEventsCh          chan protocol.MessageSentEvent
	currentFinalizedBlock *big.Int      // to control the return value of LatestFinalizedBlockHeight
	finalizedBlockMu      *sync.RWMutex // protects currentFinalizedBlock from data races
}

// Helper to safely update finalized block.
func (s *coordinatorTestSetup) setFinalizedBlock(block uint64) {
	s.finalizedBlockMu.Lock()
	defer s.finalizedBlockMu.Unlock()
	s.currentFinalizedBlock.SetUint64(block)
}

func initializeCoordinator(t *testing.T, verifierID string) *coordinatorTestSetup {
	lggr, err := logger.NewWith(func(config *zap.Config) {
		config.Development = true
		config.Encoding = "console"
	})
	require.NoError(t, err)

	mockVerifier := NewTestVerifier()
	mockSetup := SetupMockSourceReader(t)
	mockSetup.ExpectFetchMessageSentEvent(false)
	mockSourceReader := mockSetup.Reader
	mockStorage := &NoopStorage{}
	verificationTaskCh := mockSetup.Channel

	mockSourceReader.EXPECT().GetBlocksHeaders(mock.Anything, mock.Anything).Return(nil, nil).Maybe()

	// Mock ChainStatusManager to prevent initialization hangs
	mockChainStatusManager := protocol_mocks.NewMockChainStatusManager(t)
	// Return empty map to indicate no prior chain status (forces fallback to lookback calculation)
	mockChainStatusManager.EXPECT().ReadChainStatuses(mock.Anything, mock.Anything).Return(make(map[protocol.ChainSelector]*protocol.ChainStatusInfo), nil).Maybe()
	// Allow writes for chain status updates
	mockChainStatusManager.EXPECT().WriteChainStatuses(mock.Anything, mock.Anything).Return(nil).Maybe()

	currentFinalizedBlock := big.NewInt(InitialFinalizedBlock)
	finalizedBlockMu := &sync.RWMutex{}
	mockSetup.Reader.EXPECT().LatestAndFinalizedBlock(mock.Anything).RunAndReturn(func(ctx context.Context) (*protocol.BlockHeader, *protocol.BlockHeader, error) {
		// Return latest and finalized headers with proper synchronization
		// Must lock before accessing big.Int to avoid concurrent access issues
		finalizedBlockMu.RLock()
		finalizedNum := currentFinalizedBlock.Uint64()
		finalizedBlockMu.RUnlock()

		latest := &protocol.BlockHeader{
			Number:     InitialLatestBlock,
			Hash:       protocol.Bytes32{byte(InitialLatestBlock % 256)},
			ParentHash: protocol.Bytes32{byte((InitialLatestBlock - 1) % 256)},
			Timestamp:  time.Now(),
		}
		finalized := &protocol.BlockHeader{
			Number:     finalizedNum,
			Hash:       protocol.Bytes32{byte(finalizedNum % 256)},
			ParentHash: protocol.Bytes32{byte((finalizedNum - 1) % 256)},
			Timestamp:  time.Now(),
		}
		return latest, finalized, nil
	}).Maybe()

	verifierAddr := make([]byte, 20)
	verifierAddr[0] = 0x11

	config := CoordinatorConfig{
		SourceConfigs: map[protocol.ChainSelector]SourceConfig{
			1337: {
				VerifierAddress: protocol.UnknownAddress(verifierAddr),
				PollInterval:    50 * time.Millisecond, // Fast polling for tests
			},
		},
		VerifierID: verifierID,
	}

	coordinator, err := NewCoordinator(
		t.Context(),
		lggr,
		mockVerifier,
		map[protocol.ChainSelector]chainaccess.SourceReader{1337: mockSourceReader},
		mockStorage,
		config,
		&NoopLatencyTracker{},
		&noopMonitoring{},
		mockChainStatusManager,
	)
	require.NoError(t, err)

	return &coordinatorTestSetup{
		coordinator:           coordinator,
		mockSourceReader:      mockSourceReader,
		mockVerifier:          mockVerifier,
		sentEventsCh:          verificationTaskCh,
		currentFinalizedBlock: currentFinalizedBlock,
		finalizedBlockMu:      finalizedBlockMu,
	}
}
