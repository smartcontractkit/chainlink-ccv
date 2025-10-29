package verifier_test

import (
	"context"
	"math/big"
	"sync"
	"testing"
	"time"

	protocol_mocks "github.com/smartcontractkit/chainlink-ccv/protocol/common/mocks"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/batcher"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
	"github.com/smartcontractkit/chainlink-ccv/verifier/internal/verifier_mocks"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
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

func (t *testVerifier) VerifyMessages(
	ctx context.Context,
	tasks []verifier.VerificationTask,
	ccvDataBatcher *batcher.Batcher[protocol.CCVData],
) batcher.BatchResult[verifier.VerificationError] {
	t.mu.Lock()
	t.processedTasks = append(t.processedTasks, tasks...)
	t.mu.Unlock()

	// Create mock CCV data for each task
	for _, verificationTask := range tasks {
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

		if err := ccvDataBatcher.Add(ccvData); err != nil {
			// If context is canceled or batcher is closed, stop processing
			return batcher.BatchResult[verifier.VerificationError]{Items: nil, Error: nil}
		}
	}

	// No errors in this test implementation
	return batcher.BatchResult[verifier.VerificationError]{Items: nil, Error: nil}
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
	defer setup.coordinator.Close()

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
	// Wait for processing (poll interval is 100ms, add some buffer)
	time.Sleep(200 * time.Millisecond)

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
	defer setup.coordinator.Close()

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
	// Wait for processing (poll interval is 100ms, add some buffer)
	time.Sleep(200 * time.Millisecond)

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
	defer setup.coordinator.Close()

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

	// Wait for processing (poll interval is 100ms, add some buffer)
	time.Sleep(200 * time.Millisecond)

	// Should NOT have processed the non-finalized message yet
	processedCount := setup.mockVerifier.getProcessedTaskCount()
	require.Equal(t, 0, processedCount, "Should not have processed the non-finalized message")

	// Update the shared variable to simulate finalized block advancing
	setup.finalizedBlockMu.Lock()
	setup.currentFinalizedBlock.SetInt64(int64(nonFinalizedBlock))
	setup.finalizedBlockMu.Unlock()

	// Wait for the finality check to run (finality check interval is 10ms)
	time.Sleep(50 * time.Millisecond)

	// Should have processed the now-finalized message
	processedCount = setup.mockVerifier.getProcessedTaskCount()
	require.Equal(t, 1, processedCount, "Should have processed the now finalized message")
}

type coordinatorTestSetup struct {
	coordinator           *verifier.Coordinator
	mockSourceReader      *verifier_mocks.MockSourceReader
	mockVerifier          *testVerifier
	verificationTaskCh    chan verifier.VerificationTask
	currentFinalizedBlock *big.Int      // to control the return value of LatestFinalizedBlockHeight
	finalizedBlockMu      *sync.RWMutex // protects currentFinalizedBlock from data races
}

func initializeCoordinator(t *testing.T, verifierID string) *coordinatorTestSetup {
	lggr, err := logger.NewWith(func(config *zap.Config) {
		config.Development = true
		config.Encoding = "console"
	})
	require.NoError(t, err)

	mockVerifier := newTestVerifier()
	mockSourceReader := verifier_mocks.NewMockSourceReader(t)
	mockStorage := &testStorage{}
	verificationTaskCh := make(chan verifier.VerificationTask, 10)

	mockSourceReader.EXPECT().VerificationTasks(mock.Anything, mock.Anything, mock.Anything).RunAndReturn(func(ctx context.Context, b, b2 *big.Int) ([]verifier.VerificationTask, error) {
		var tasks []verifier.VerificationTask
		for {
			select {
			case task := <-verificationTaskCh:
				tasks = append(tasks, task)
			default:
				return tasks, nil
			}
		}
	})

	mockSourceReader.EXPECT().BlockTime(mock.Anything, mock.Anything).Return(uint64(time.Now().Unix()), nil).Maybe()

	mockHeadTracker := protocol_mocks.NewMockHeadTracker(t)
	currentFinalizedBlock := big.NewInt(InitialFinalizedBlock)
	finalizedBlockMu := &sync.RWMutex{}
	mockHeadTracker.EXPECT().LatestAndFinalizedBlock(mock.Anything).RunAndReturn(func(ctx context.Context) (*protocol.BlockHeader, *protocol.BlockHeader, error) {
		// Return latest and finalized headers with proper synchronization
		finalizedBlockMu.RLock()
		defer finalizedBlockMu.RUnlock()

		latest := &protocol.BlockHeader{
			Number:               InitialLatestBlock,
			Hash:                 protocol.Bytes32{byte(InitialLatestBlock % 256)},
			ParentHash:           protocol.Bytes32{byte((InitialLatestBlock - 1) % 256)},
			Timestamp:            time.Now(),
			FinalizedBlockNumber: currentFinalizedBlock.Uint64(),
		}
		finalized := &protocol.BlockHeader{
			Number:               currentFinalizedBlock.Uint64(),
			Hash:                 protocol.Bytes32{byte(currentFinalizedBlock.Uint64() % 256)},
			ParentHash:           protocol.Bytes32{byte((currentFinalizedBlock.Uint64() - 1) % 256)},
			Timestamp:            time.Now(),
			FinalizedBlockNumber: currentFinalizedBlock.Uint64(),
		}
		return latest, finalized, nil
	}).Maybe()

	config := verifier.CoordinatorConfig{
		SourceConfigs: map[protocol.ChainSelector]verifier.SourceConfig{
			1337: {
				VerifierAddress: protocol.UnknownAddress([]byte("verifier-1337")),
				PollInterval:    50 * time.Millisecond, // Fast polling for tests
			},
		},
		VerifierID: verifierID,
	}

	noopMonitoring := monitoring.NewNoopVerifierMonitoring()
	coordinator, err := verifier.NewVerificationCoordinator(
		verifier.WithVerifier(mockVerifier),
		verifier.WithSourceReaders(map[protocol.ChainSelector]verifier.SourceReader{
			1337: mockSourceReader,
		}),
		verifier.WithHeadTrackers(map[protocol.ChainSelector]chainaccess.HeadTracker{
			1337: mockHeadTracker,
		}),
		verifier.WithStorage(mockStorage),
		verifier.WithConfig(config),
		verifier.WithLogger(lggr),
		verifier.WithMonitoring(noopMonitoring),
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
