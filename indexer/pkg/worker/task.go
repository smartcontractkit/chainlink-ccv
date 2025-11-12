package worker

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/readers"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/registry"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type Task struct {
	logger    logger.Logger
	messageID protocol.Bytes32
	message   protocol.CCVData
	registry  *registry.VerifierRegistry
	storage   common.IndexerStorage
	attempt   int // 1-indexed
	runAt     time.Time
	index     int // heap index
	lastErr   error
}

type TaskResult struct {
	MissingVerifiers    int
	SuccessfulVerifiers int
	FailedVerifiers     int
}

func NewTask(lggr logger.Logger, message protocol.CCVData, registry *registry.VerifierRegistry, storage common.IndexerStorage) (*Task, error) {
	return &Task{
		logger:    logger.Named(logger.With(lggr, "messageID", message.MessageID), "Task"),
		messageID: message.MessageID,
		message:   message,
		registry:  registry,
		storage:   storage,
		attempt:   0,
		lastErr:   nil,
	}, nil
}

// collectVerifierResults processes all verifier readers concurrently and collects successful results.
func (t *Task) collectVerifierResults(ctx context.Context, verifierReaders []*readers.VerifierReader) []protocol.CCVData {
	if len(verifierReaders) == 0 {
		return nil
	}

	var (
		mu      sync.Mutex
		results []protocol.CCVData
		wg      sync.WaitGroup
	)

	wg.Add(len(verifierReaders))
	for _, reader := range verifierReaders {
		if reader == nil {
			wg.Done()
			continue
		}

		resultCh, err := reader.ProcessMessage(t.messageID)
		if err != nil {
			wg.Done()
			continue
		}

		go func(ch <-chan common.Result[protocol.CCVData]) {
			defer wg.Done()
			select {
			case result, ok := <-ch:
				if !ok {
					return
				}
				if result.Err() == nil {
					mu.Lock()
					t.logger.Debugf("Received result from %s for MessageID %s", reader.IssuerAddress(), t.messageID.String())
					results = append(results, result.Value())
					mu.Unlock()
				}
			case <-ctx.Done():
				return
			}
		}(resultCh)
	}

	wg.Wait()
	return results
}

func (t *Task) loadVerifierReaders(verifierAddresses []string) (readers []*readers.VerifierReader, missingReaders []string) {
	for _, v := range verifierAddresses {
		unknownAddress, err := protocol.NewUnknownAddressFromHex(v)
		if err != nil {
			missingReaders = append(missingReaders, v)
			continue
		}

		reader := t.registry.GetVerifier(unknownAddress)
		if reader == nil {
			missingReaders = append(missingReaders, v)
			continue
		}

		readers = append(readers, reader)
	}
	return readers, missingReaders
}

func (t *Task) getMissingVerifiers(ctx context.Context) (missing []string, err error) {
	existing, err := t.getExistingVerifiers(ctx)
	if err != nil {
		return nil, err
	}

	for _, v := range t.getVerifiers() {
		if !slices.Contains(existing, v) {
			missing = append(missing, v)
		}
	}
	return missing, nil
}

func (t *Task) getExistingVerifiers(ctx context.Context) (existing []string, err error) {
	results, err := t.storage.GetCCVData(ctx, t.messageID)
	if err != nil {
		return nil, err
	}

	for _, r := range results {
		existing = append(existing, r.DestVerifierAddress.String())
	}

	return existing, nil
}

func (t *Task) getVerifiers() []string {
	verifiers := []string{}
	blobsExcludingExecutor := t.message.ReceiptBlobs[:len(t.message.ReceiptBlobs)-1]
	for _, receipt := range blobsExcludingExecutor {
		verifiers = append(verifiers, receipt.Issuer.String())
	}

	return verifiers
}
