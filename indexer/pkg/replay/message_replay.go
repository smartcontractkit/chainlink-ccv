package replay

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/readers"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

func (e *Engine) runMessageReplay(ctx context.Context, job *Job) error {
	if len(job.MessageIDs) == 0 {
		return fmt.Errorf("message replay requires at least one message ID")
	}
	if e.registry == nil {
		return fmt.Errorf("verifier registry not configured")
	}

	var aggReader *readers.ResilientReader
	if e.aggregatorReaderFactory != nil {
		var err error
		aggReader, err = e.aggregatorReaderFactory(0)
		if err != nil {
			e.lggr.Warnw("Could not create aggregator reader for CCV fallback", "error", err)
		}
	}

	startIdx := int(job.ProgressCursor)
	if startIdx > 0 {
		e.lggr.Infow("Resuming message replay", "jobID", job.ID, "fromIndex", startIdx, "total", len(job.MessageIDs))
	}

	for i := startIdx; i < len(job.MessageIDs); i++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		msgIDHex := job.MessageIDs[i]
		msgID, err := protocol.NewBytes32FromString(msgIDHex)
		if err != nil {
			e.lggr.Warnw("Invalid message ID, skipping", "messageID", msgIDHex, "error", err)
			if err := e.checkpointMessage(ctx, job, i+1); err != nil {
				return err
			}
			continue
		}

		e.lggr.Infow("Replaying message", "jobID", job.ID, "messageID", msgIDHex, "index", i, "total", len(job.MessageIDs))

		if err := e.gatherAllVerifications(ctx, job, msgID, aggReader); err != nil {
			e.lggr.Warnw("Error gathering verifications for message",
				"jobID", job.ID,
				"messageID", msgIDHex,
				"error", err,
			)
		}

		if err := e.checkpointMessage(ctx, job, i+1); err != nil {
			return err
		}
	}

	e.lggr.Infow("Message replay finished", "jobID", job.ID, "total", len(job.MessageIDs))
	return nil
}

// gatherAllVerifications fetches verifications from all known verifiers for a
// single message ID. It first checks that the message exists in local storage,
// then tries to obtain CCV addresses from existing verifier_results. When no
// local CCV data is available, it falls back to the aggregator to re-discover
// the message's CCV addresses.
func (e *Engine) gatherAllVerifications(
	ctx context.Context,
	job *Job,
	msgID protocol.Bytes32,
	aggReader *readers.ResilientReader,
) error {
	if _, err := e.storage.GetMessage(ctx, msgID); err != nil {
		e.lggr.Warnw("Message not found in local storage, skipping verifier gathering",
			"messageID", msgID,
		)
		return nil
	}

	ccvAddresses := e.collectLocalCCVAddresses(ctx, msgID)

	if len(ccvAddresses) == 0 {
		ccvAddresses = e.fallbackAggregatorCCVAddresses(ctx, msgID, aggReader)
	}

	if len(ccvAddresses) == 0 {
		e.lggr.Warnw("No CCV addresses found for message, skipping verifier gathering",
			"messageID", msgID,
		)
		return nil
	}

	return e.queryVerifiers(ctx, job, msgID, ccvAddresses)
}

// collectLocalCCVAddresses unions CCV addresses from existing verifier_results.
func (e *Engine) collectLocalCCVAddresses(ctx context.Context, msgID protocol.Bytes32) []protocol.UnknownAddress {
	existing, err := e.storage.GetCCVData(ctx, msgID)
	if err != nil || len(existing) == 0 {
		return nil
	}

	seen := make(map[string]struct{})
	var addrs []protocol.UnknownAddress
	for _, entry := range existing {
		for _, addr := range entry.VerifierResult.MessageCCVAddresses {
			key := addr.String()
			if _, ok := seen[key]; !ok {
				seen[key] = struct{}{}
				addrs = append(addrs, addr)
			}
		}
	}
	return addrs
}

// fallbackAggregatorCCVAddresses queries the aggregator for verifier results
// to extract CCV addresses when no local data is available.
func (e *Engine) fallbackAggregatorCCVAddresses(
	ctx context.Context,
	msgID protocol.Bytes32,
	aggReader *readers.ResilientReader,
) []protocol.UnknownAddress {
	if aggReader == nil {
		e.lggr.Warnw("No aggregator reader available for CCV address fallback",
			"messageID", msgID,
		)
		return nil
	}

	results, err := aggReader.GetVerifications(ctx, []protocol.Bytes32{msgID})
	if err != nil {
		e.lggr.Warnw("Aggregator GetVerifications failed for CCV fallback",
			"messageID", msgID,
			"error", err,
		)
		return nil
	}

	vr, ok := results[msgID]
	if !ok {
		return nil
	}

	return vr.MessageCCVAddresses
}

// queryVerifiers fans out to all configured verifier readers for the given
// CCV addresses and persists the results.
func (e *Engine) queryVerifiers(
	ctx context.Context,
	job *Job,
	msgID protocol.Bytes32,
	ccvAddresses []protocol.UnknownAddress,
) error {
	for _, addr := range ccvAddresses {
		verifierReaders := e.registry.GetVerifiers(addr)
		if len(verifierReaders) == 0 {
			continue
		}

		for _, reader := range verifierReaders {
			resultCh, err := reader.ProcessMessage(msgID)
			if err != nil {
				e.lggr.Warnw("Failed to enqueue message for verifier",
					"messageID", msgID,
					"verifier", strings.ToLower(addr.String()),
					"error", err,
				)
				continue
			}

			select {
			case <-ctx.Done():
				return ctx.Err()
			case result, ok := <-resultCh:
				if !ok || result.Err() != nil {
					continue
				}
				vrm := common.VerifierResultWithMetadata{
					VerifierResult: result.Value(),
					Metadata: common.VerifierResultMetadata{
						AttestationTimestamp: result.Value().Timestamp,
						IngestionTimestamp:   time.Now(),
						VerifierName:         e.registry.GetVerifierNameFromAddress(result.Value().VerifierSourceAddress),
					},
				}
				if err := e.storage.UpsertVerifierResults(ctx, []common.VerifierResultWithMetadata{vrm}, job.ForceOverwrite); err != nil {
					e.lggr.Warnw("Failed to persist verifier result",
						"messageID", msgID,
						"error", err,
					)
				}
			}
		}
	}
	return nil
}

func (e *Engine) checkpointMessage(ctx context.Context, job *Job, nextIdx int) error {
	return e.store.UpdateProgress(ctx, e.store.DataSource(), job.ID, int64(nextIdx), nextIdx)
}
