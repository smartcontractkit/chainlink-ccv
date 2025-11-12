package verifier

import (
	"context"
	"encoding/binary"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/batcher"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/common"
)

// WaitForMessagesInStorage waits for the specified number of messages to be processed.
// Since messages are batched, we can't rely on one notification per message.
// Instead, we poll the storage to check if the expected count has been reached.
func WaitForMessagesInStorage(t *testing.T, storage *common.InMemoryOffchainStorage, count int) {
	timeout := time.After(30 * time.Second)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			require.FailNow(t, "Timeout waiting for messages", "expected %d messages, got %d", count, storage.GetTotalCount())
		case <-ticker.C:
			if storage.GetTotalCount() >= count {
				return
			}
		}
	}
}

func CreateTestMessage(t *testing.T, nonce protocol.Nonce, sourceChainSelector, destChainSelector protocol.ChainSelector, finality uint16, gasLimit uint32) protocol.Message {
	// Create empty token transfer
	tokenTransfer := protocol.NewEmptyTokenTransfer()

	sender := protocol.UnknownAddress([]byte("sender_address"))
	receiver := protocol.UnknownAddress([]byte("receiver_address"))
	onRampAddr := protocol.UnknownAddress([]byte("onramp_address"))
	offRampAddr := protocol.UnknownAddress([]byte("offramp_address"))

	message, err := protocol.NewMessage(
		sourceChainSelector,
		destChainSelector,
		nonce,
		onRampAddr,
		offRampAddr,
		finality,
		gasLimit,
		sender,
		receiver,
		[]byte("test data"), // dest blob
		[]byte("test data"), // data
		tokenTransfer,
	)
	require.NoError(t, err)
	return *message
}

// MockSourceReaderSetup contains a mock source Reader and its Channel.
type MockSourceReaderSetup struct {
	Reader  *MockSourceReader
	Channel chan VerificationTask
}

// SetupMockSourceReader creates a mock source Reader with expectations.
func SetupMockSourceReader(t *testing.T) *MockSourceReaderSetup {
	mockReader := NewMockSourceReader(t)
	channel := make(chan VerificationTask, 10)

	now := time.Now().Unix()

	mockReader.EXPECT().BlockTime(mock.Anything, mock.Anything).Return(uint64(now), nil).Maybe()
	mockReader.EXPECT().GetRMNCursedSubjects(mock.Anything).Return(nil, nil).Maybe()

	return &MockSourceReaderSetup{
		Reader:  mockReader,
		Channel: channel,
	}
}

func (msrs *MockSourceReaderSetup) ExpectVerificationTask(maybeVerificationTask bool) {
	call := msrs.Reader.EXPECT().VerificationTasks(mock.Anything, mock.Anything, mock.Anything).RunAndReturn(func(ctx context.Context, b, b2 *big.Int) ([]VerificationTask, error) {
		var tasks []VerificationTask
		for {
			select {
			case task := <-msrs.Channel:
				tasks = append(tasks, task)
			default:
				return tasks, nil
			}
		}
	})
	if maybeVerificationTask {
		call.Maybe()
	}
}

// Test constants.
const (
	defaultDestChain = protocol.ChainSelector(100)
)

// mockReorgDetector is a simple mock that returns a channel we can control in tests.
type mockReorgDetector struct {
	statusCh  chan protocol.ChainStatus
	closeOnce sync.Once
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
	m.closeOnce.Do(func() {
		close(m.statusCh)
	})
	return nil
}

// noopMonitoring is a simple noop monitoring implementation for tests.
type noopMonitoring struct{}

func (m *noopMonitoring) Metrics() MetricLabeler { return &noopMetricLabeler{} }

type noopMetricLabeler struct{}

func (m *noopMetricLabeler) With(keyValues ...string) MetricLabeler                                 { return m }
func (m *noopMetricLabeler) RecordMessageE2ELatency(ctx context.Context, duration time.Duration)    {}
func (m *noopMetricLabeler) IncrementMessagesProcessed(ctx context.Context)                         {}
func (m *noopMetricLabeler) IncrementMessagesVerificationFailed(ctx context.Context)                {}
func (m *noopMetricLabeler) RecordFinalityWaitDuration(ctx context.Context, duration time.Duration) {}
func (m *noopMetricLabeler) RecordMessageVerificationDuration(ctx context.Context, duration time.Duration) {
}
func (m *noopMetricLabeler) RecordStorageWriteDuration(ctx context.Context, duration time.Duration) {}
func (m *noopMetricLabeler) RecordFinalityQueueSize(ctx context.Context, size int64)                {}
func (m *noopMetricLabeler) RecordCCVDataChannelSize(ctx context.Context, size int64)               {}
func (m *noopMetricLabeler) IncrementStorageWriteErrors(ctx context.Context)                        {}
func (m *noopMetricLabeler) RecordSourceChainLatestBlock(ctx context.Context, blockNum int64)       {}
func (m *noopMetricLabeler) RecordSourceChainFinalizedBlock(ctx context.Context, blockNum int64)    {}

// TestVerifier keeps track of all processed messages for testing.
type TestVerifier struct {
	processedTasks []VerificationTask
	mu             sync.RWMutex
}

func NewTestVerifier() *TestVerifier {
	return &TestVerifier{
		processedTasks: make([]VerificationTask, 0),
	}
}

func (t *TestVerifier) VerifyMessages(
	_ context.Context,
	tasks []VerificationTask,
	ccvDataBatcher *batcher.Batcher[CCVDataWithIdempotencyKey],
) batcher.BatchResult[VerificationError] {
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
			Timestamp:             time.Now(),
			Message:               verificationTask.Message,
			ReceiptBlobs:          verificationTask.ReceiptBlobs,
		}

		ccvDataWithKey := CCVDataWithIdempotencyKey{
			CCVData:        ccvData,
			IdempotencyKey: verificationTask.IdempotencyKey,
		}

		if err := ccvDataBatcher.Add(ccvDataWithKey); err != nil {
			// If context is canceled or batcher is closed, stop processing
			return batcher.BatchResult[VerificationError]{Items: nil, Error: nil}
		}
	}

	// No errors in this test implementation
	return batcher.BatchResult[VerificationError]{Items: nil, Error: nil}
}

func (t *TestVerifier) GetProcessedTaskCount() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.processedTasks)
}

func (t *TestVerifier) Reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.processedTasks = make([]VerificationTask, 0)
}

func (t *TestVerifier) GetProcessedTasks() []VerificationTask {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return append([]VerificationTask(nil), t.processedTasks...)
}

// NoopStorage for testing.
type NoopStorage struct{}

func (m *NoopStorage) WriteCCVNodeData(ctx context.Context, data []protocol.CCVData, idempotencyKeys []string) error {
	return nil
}

// createTestVerificationTasks creates a batch of verification tasks for testing.
// Each task will have a sequential message ID starting from startSeqNum and uses the provided block numbers.
func createTestVerificationTasks(
	t *testing.T,
	startNonce uint64,
	chainSelector, destChain protocol.ChainSelector,
	blockNumbers []uint64,
) []VerificationTask {
	t.Helper()

	tasks := make([]VerificationTask, len(blockNumbers))
	for i, blockNum := range blockNumbers {
		nonce := startNonce + uint64(i)
		tasks[i] = VerificationTask{
			Message:        CreateTestMessage(t, protocol.Nonce(nonce), chainSelector, destChain, 0, 300_000),
			BlockNumber:    blockNum,
			ReceiptBlobs:   []protocol.ReceiptWithBlob{{Blob: []byte("receipt1")}},
			CreatedAt:      time.Now(),
			IdempotencyKey: uuid.NewString(),
		}
	}
	return tasks
}

func hashFromNumber(n uint64) protocol.Bytes32 {
	var h protocol.Bytes32
	binary.BigEndian.PutUint64(h[:], n)
	return h
}
