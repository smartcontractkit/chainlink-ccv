package test

import (
	"context"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/batcher"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
)

// Verifier keeps track of all processed messages for testing.
type Verifier struct {
	processedTasks []verifier.VerificationTask
	mu             sync.RWMutex
}

func NewVerifier() *Verifier {
	return &Verifier{
		processedTasks: make([]verifier.VerificationTask, 0),
	}
}

func (t *Verifier) VerifyMessages(
	_ context.Context,
	tasks []verifier.VerificationTask,
	ccvDataBatcher *batcher.Batcher[verifier.CCVDataWithIdempotencyKey],
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
			Timestamp:             time.Now(),
			Message:               verificationTask.Message,
			ReceiptBlobs:          verificationTask.ReceiptBlobs,
		}

		ccvDataWithKey := verifier.CCVDataWithIdempotencyKey{
			CCVData:        ccvData,
			IdempotencyKey: verificationTask.IdempotencyKey,
		}

		if err := ccvDataBatcher.Add(ccvDataWithKey); err != nil {
			// If context is canceled or batcher is closed, stop processing
			return batcher.BatchResult[verifier.VerificationError]{Items: nil, Error: nil}
		}
	}

	// No errors in this test implementation
	return batcher.BatchResult[verifier.VerificationError]{Items: nil, Error: nil}
}

func (t *Verifier) GetProcessedTaskCount() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.processedTasks)
}

func (t *Verifier) Reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.processedTasks = make([]verifier.VerificationTask, 0)
}

func (t *Verifier) GetProcessedTasks() []verifier.VerificationTask {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return append([]verifier.VerificationTask(nil), t.processedTasks...)
}

// NoopStorage for testing.
type NoopStorage struct{}

func (m *NoopStorage) WriteCCVNodeData(ctx context.Context, data []protocol.CCVData, idempotencyKeys []string) error {
	return nil
}
