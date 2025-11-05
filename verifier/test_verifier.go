package verifier

import (
	"context"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/batcher"
)

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
