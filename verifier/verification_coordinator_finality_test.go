package verifier_test

import (
	"context"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/smartcontractkit/chainlink-ccv/verifier"
	"github.com/smartcontractkit/chainlink-ccv/verifier/internal/verifier_mocks"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	protocol "github.com/smartcontractkit/chainlink-ccv/protocol/pkg/types"
)

const (
	InitialLatestBlock    = 1000
	InitialFinalizedBlock = 950
)

// testVerifier keeps track of all processed messages for testing.
type testVerifier struct {
	processedTasks []verifier.VerificationTask
	mu             sync.RWMutex
}

func newTestVerifier() *testVerifier {
	return &testVerifier{
		processedTasks: make([]verifier.VerificationTask, 0),
	}
}

func (t *testVerifier) VerifyMessage(
	ctx context.Context,
	verificationTask verifier.VerificationTask,
	ccvDataCh chan<- protocol.CCVData,
	verificationErrorCh chan<- verifier.VerificationError,
) {
	t.mu.Lock()
	t.processedTasks = append(t.processedTasks, verificationTask)
	t.mu.Unlock()

	// Create mock CCV data
	messageID, _ := verificationTask.Message.MessageID()
	ccvData := protocol.CCVData{
		MessageID:             messageID,
		Nonce:                 verificationTask.Message.Nonce,
		SourceChainSelector:   verificationTask.Message.SourceChainSelector,
		DestChainSelector:     verificationTask.Message.DestChainSelector,
		SourceVerifierAddress: protocol.UnknownAddress{},
		DestVerifierAddress:   protocol.UnknownAddress{},
		CCVData:               []byte("mock-signature"),
		BlobData:              []byte("mock-blob"),
		Timestamp:             time.Now().UnixMicro(),
		Message:               verificationTask.Message,
		ReceiptBlobs:          verificationTask.ReceiptBlobs,
	}

	select {
	case ccvDataCh <- ccvData:
	case <-ctx.Done():
	}
}

func (t *testVerifier) getProcessedTaskCount() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.processedTasks)
}

// testStorage for testing.
type testStorage struct{}

func (m *testStorage) WriteCCVNodeData(ctx context.Context, data []protocol.CCVData) error {
	return nil
}

func TestFinality_FinalizedMessage(t *testing.T) {
	setup := initializeCoordinator(t, "test-finality-coordinator")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := setup.coordinator.Start(ctx)
	require.NoError(t, err)
	defer setup.coordinator.Stop()

	// Message at block 940 (< finalized 950) should be processed immediately
	finalizedMessage := createTestMessage(t, 1, 1337, 2337, 0)
	finalizedTask := verifier.VerificationTask{
		Message: finalizedMessage,
		ReceiptBlobs: []protocol.ReceiptWithBlob{{
			Issuer:            protocol.UnknownAddress([]byte("verifier-1337")),
			DestGasLimit:      300000,
			DestBytesOverhead: 100,
			Blob:              []byte("test-blob"),
			ExtraArgs:         []byte{}, // Empty = default finality
		}},
		BlockNumber: InitialFinalizedBlock - 10, // 940 <= 950 (finalized), should be processed immediately
	}

	// Send message
	setup.verificationTaskCh <- finalizedTask
	// Wait for processing
	time.Sleep(20 * time.Millisecond)

	// Should have processed the finalized message
	processedCount := setup.mockVerifier.getProcessedTaskCount()
	require.Equal(t, 1, processedCount, "Should have processed the finalized message")
}

func TestFinality_CustomFinality(t *testing.T) {
	setup := initializeCoordinator(t, "test-custom-finality-coordinator")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := setup.coordinator.Start(ctx)
	require.NoError(t, err)
	defer setup.coordinator.Stop()

	customFinality := uint16(15)

	readyMessage := createTestMessage(t, 1, 1337, 2337, customFinality)
	readyTask := verifier.VerificationTask{
		Message: readyMessage,
		ReceiptBlobs: []protocol.ReceiptWithBlob{{
			Issuer:            protocol.UnknownAddress([]byte("verifier-1337")),
			DestGasLimit:      300000,
			DestBytesOverhead: 100,
			Blob:              []byte("test-blob"),
			ExtraArgs:         []byte{},
		}},
		BlockNumber: uint64(InitialLatestBlock - customFinality), // should be ready
	}

	// Send message
	setup.verificationTaskCh <- readyTask
	time.Sleep(20 * time.Millisecond)

	// Should have processed the ready message
	processedCount := setup.mockVerifier.getProcessedTaskCount()
	require.Equal(t, 1, processedCount, "Should have processed the ready message")
}

func TestFinality_WaitingForFinality(t *testing.T) {
	setup := initializeCoordinator(t, "test-finality-coordinator")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := setup.coordinator.Start(ctx)
	require.NoError(t, err)
	defer setup.coordinator.Stop()

	nonFinalizedMessage := createTestMessage(t, 1, 1337, 2337, 0)
	nonFinalizedBlock := InitialFinalizedBlock + 10
	nonFinalizedTask := verifier.VerificationTask{
		Message: nonFinalizedMessage,
		ReceiptBlobs: []protocol.ReceiptWithBlob{{
			Issuer:            protocol.UnknownAddress([]byte("verifier-1337")),
			DestGasLimit:      300000,
			DestBytesOverhead: 100,
			Blob:              []byte("test-blob"),
			ExtraArgs:         []byte{}, // Empty = default finality
		}},
		BlockNumber: uint64(nonFinalizedBlock), // should be waiting for finality
	}

	// Send message
	setup.verificationTaskCh <- nonFinalizedTask

	// Wait for processing
	time.Sleep(20 * time.Millisecond)

	// Should have processed the finalized message
	processedCount := setup.mockVerifier.getProcessedTaskCount()
	require.Equal(t, 0, processedCount, "Should not have processed the non-finalized message")

	// Update the shared variable to simulate finalized block advancing
	setup.finalizedBlockMu.Lock()
	setup.currentFinalizedBlock.SetInt64(int64(nonFinalizedBlock))
	setup.finalizedBlockMu.Unlock()

	// Wait for the finality check to run (finality check interval is 10ms)
	time.Sleep(20 * time.Millisecond)

	// Should have processed the now-finalized message
	processedCount = setup.mockVerifier.getProcessedTaskCount()
	require.Equal(t, 1, processedCount, "Should have processed the now finalized message")
}

type coordinatorTestSetup struct {
	coordinator           *verifier.Coordinator
	mockSourceReader      *verifier_mocks.MockSourceReader
	mockVerifier          *testVerifier
	verificationTaskCh    chan verifier.VerificationTask
	currentFinalizedBlock *big.Int      // to control the return value of LatestFinalizedBlock
	finalizedBlockMu      *sync.RWMutex // protects currentFinalizedBlock from data races
}

func initializeCoordinator(t *testing.T, verifierID string) *coordinatorTestSetup {
	lggr, err := logger.NewWith(func(config *zap.Config) {
		config.Development = true
		config.Encoding = "console"
	})
	require.NoError(t, err)

	mockSourceReader := verifier_mocks.NewMockSourceReader(t)
	mockVerifier := newTestVerifier()
	mockStorage := &testStorage{}

	verificationTaskCh := make(chan verifier.VerificationTask, 10)
	mockSourceReader.EXPECT().Start(mock.Anything).Return(nil)
	mockSourceReader.EXPECT().VerificationTaskChannel().Return((<-chan verifier.VerificationTask)(verificationTaskCh))
	mockSourceReader.EXPECT().Stop().Return(nil)

	currentFinalizedBlock := big.NewInt(InitialFinalizedBlock)
	finalizedBlockMu := &sync.RWMutex{}
	mockSourceReader.EXPECT().LatestBlock(mock.Anything).Return(big.NewInt(InitialLatestBlock), nil).Maybe()
	mockSourceReader.EXPECT().LatestFinalizedBlock(mock.Anything).RunAndReturn(func(ctx context.Context) (*big.Int, error) {
		// Return a copy with proper synchronization to avoid data races
		finalizedBlockMu.RLock()
		defer finalizedBlockMu.RUnlock()
		return new(big.Int).Set(currentFinalizedBlock), nil
	}).Maybe()

	config := verifier.CoordinatorConfig{
		SourceConfigs: map[protocol.ChainSelector]verifier.SourceConfig{
			1337: {VerifierAddress: protocol.UnknownAddress([]byte("verifier-1337"))},
		},
		VerifierID: verifierID,
	}

	coordinator, err := verifier.NewVerificationCoordinator(
		verifier.WithVerifier(mockVerifier),
		verifier.WithSourceReaders(map[protocol.ChainSelector]verifier.SourceReader{
			1337: mockSourceReader,
		}),
		verifier.WithStorage(mockStorage),
		verifier.WithConfig(config),
		verifier.WithLogger(lggr),
		verifier.WithFinalityCheckInterval(10*time.Millisecond),
	)
	require.NoError(t, err)

	return &coordinatorTestSetup{
		coordinator:           coordinator,
		mockSourceReader:      mockSourceReader,
		mockVerifier:          mockVerifier,
		verificationTaskCh:    verificationTaskCh,
		currentFinalizedBlock: currentFinalizedBlock,
		finalizedBlockMu:      finalizedBlockMu,
	}
}
