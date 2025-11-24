package worker

import (
	"context"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/readers"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/registry"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/storage"
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
	ttl       time.Time
}

type TaskResult struct {
	UnknownCCVs             int
	SuccessfulVerifications int
	UnavailableCCVs         int
}

func NewTask(lggr logger.Logger, message protocol.CCVData, registry *registry.VerifierRegistry, storage common.IndexerStorage, verificationVisabilityWindow time.Duration) (*Task, error) {
	return &Task{
		logger:    logger.Named(logger.With(lggr, "messageID", message.MessageID), "Task"),
		messageID: message.MessageID,
		message:   message,
		registry:  registry,
		storage:   storage,
		attempt:   0,
		lastErr:   nil,
		ttl:       time.Now().Add(verificationVisabilityWindow),
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
					t.logger.Debugf("Received result from %s for MessageID %s", result.Value().SourceVerifierAddress, t.messageID.String())
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

func (t *Task) loadVerifierReaders(verifierAddresses []string) (readers []*readers.VerifierReader, loadedReaders, missingReaders []string) {
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
		loadedReaders = append(loadedReaders, unknownAddress.String())
	}
	return readers, loadedReaders, missingReaders
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
	var results []protocol.CCVData

	// If we're using the sink, ignore the cache and use the persistent stores
	if sink, ok := t.storage.(*storage.Sink); ok {
		results, err = sink.GetCCVDataSkipCache(ctx, t.messageID)
	} else {
		results, err = t.storage.GetCCVData(ctx, t.messageID)
	}

	if err != nil {
		return nil, err
	}

	for _, r := range results {
		existing = append(existing, strings.ToLower(r.SourceVerifierAddress.String()))
	}

	return existing, nil
}

func (t *Task) getVerifiers() []string {
	verifiers := []string{}
	// This should be -1 off length, however bug exists somewhere pre-indexer such that this returns twice
	// As we're migrating away from this structure anyway, temp placeholder
	blobsExcludingExecutor := t.message.ReceiptBlobs[:len(t.message.ReceiptBlobs)-2]
	for _, receipt := range blobsExcludingExecutor {
		verifiers = append(verifiers, strings.ToLower(receipt.Issuer.String()))
	}

	return verifiers
}
