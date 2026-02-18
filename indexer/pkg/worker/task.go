package worker

import (
	"context"
	"fmt"
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
	message   protocol.VerifierResult
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

func NewTask(lggr logger.Logger, message protocol.VerifierResult, registry *registry.VerifierRegistry, storage common.IndexerStorage, verificationVisabilityWindow time.Duration) (*Task, error) {
	if lggr == nil {
		return nil, fmt.Errorf("logger is required")
	}
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
func (t *Task) collectVerifierResults(ctx context.Context, verifierReaders []*readers.VerifierReader) []common.VerifierResultWithMetadata {
	if len(verifierReaders) == 0 {
		return nil
	}

	var (
		mu      sync.Mutex
		results []common.VerifierResultWithMetadata
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

		go func(ch <-chan common.Result[protocol.VerifierResult]) {
			defer wg.Done()
			select {
			case result, ok := <-ch:
				if !ok {
					return
				}
				if result.Err() == nil {
					mu.Lock()
					t.logger.Debugf("Received result from %s for MessageID %s", result.Value().VerifierSourceAddress, t.messageID.String())
					verifierResultWithMetadata := common.VerifierResultWithMetadata{
						VerifierResult: result.Value(),
						Metadata: common.VerifierResultMetadata{
							AttestationTimestamp: result.Value().Timestamp,
							IngestionTimestamp:   time.Now(),
							VerifierName:         t.registry.GetVerifierNameFromAddress(result.Value().VerifierSourceAddress),
						},
					}
					results = append(results, verifierResultWithMetadata)
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
		// normalize casing to lower-case hex strings to match getExistingVerifiers/getVerifiers
		loadedReaders = append(loadedReaders, strings.ToLower(unknownAddress.String()))
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
	var results []common.VerifierResultWithMetadata

	results, err = t.storage.GetCCVData(ctx, t.messageID)

	// If the data is not found, it must be a discovery only message
	// We'll safely return here knowing we don't have any verifications.
	if err == storage.ErrCCVDataNotFound {
		return existing, nil
	}

	if err != nil {
		return nil, err
	}

	for _, r := range results {
		existing = append(existing, strings.ToLower(r.VerifierResult.VerifierSourceAddress.String()))
	}

	return existing, nil
}

func (t *Task) getVerifiers() []string {
	verifiers := []string{}
	// Extract verifiers from MessageCCVAddresses
	for _, addr := range t.message.MessageCCVAddresses {
		verifiers = append(verifiers, strings.ToLower(addr.String()))
	}

	return verifiers
}

func (t *Task) SetMessageStatus(ctx context.Context, messageStatus common.MessageStatus, lastErr string) error {
	return t.storage.UpdateMessageStatus(ctx, t.messageID, messageStatus, lastErr)
}
