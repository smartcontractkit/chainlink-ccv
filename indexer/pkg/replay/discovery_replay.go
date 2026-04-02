package replay

import (
	"context"
	"fmt"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

func (e *Engine) runDiscoveryReplay(ctx context.Context, job *Job) error {
	if job.SinceSequenceNumber == nil {
		return fmt.Errorf("discovery replay requires since_sequence_number")
	}
	if e.aggregatorReaderFactory == nil {
		return fmt.Errorf("aggregator reader factory not configured")
	}

	sinceValue := job.ProgressCursor
	if sinceValue == 0 {
		sinceValue = *job.SinceSequenceNumber
	}

	reader, err := e.aggregatorReaderFactory(sinceValue)
	if err != nil {
		return fmt.Errorf("failed to create aggregator reader for replay: %w", err)
	}

	e.lggr.Infow("Discovery replay starting",
		"jobID", job.ID,
		"sinceSequenceNumber", *job.SinceSequenceNumber,
		"resumeCursor", sinceValue,
		"force", job.ForceOverwrite,
	)

	totalProcessed := job.ProcessedItems
	consecutiveEmpty := 0
	maxConsecutiveEmpty := 3

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		responses, err := reader.ReadCCVData(ctx)
		if err != nil {
			return fmt.Errorf("ReadCCVData failed: %w", err)
		}

		if len(responses) == 0 {
			consecutiveEmpty++
			if consecutiveEmpty >= maxConsecutiveEmpty {
				e.lggr.Infow("No more data from aggregator, discovery replay finished",
					"jobID", job.ID, "totalProcessed", totalProcessed)
				return nil
			}
			time.Sleep(e.batchThrottleDelay)
			continue
		}
		consecutiveEmpty = 0

		messages, verifications, _ := common.ConvertDiscoveryResponses(responses, time.Now(), e.registry)
		e.lggr.Infow("Discovery replay batch",
			"jobID", job.ID,
			"responses", len(responses),
			"messages", len(messages),
			"verifications", len(verifications),
		)

		if err := e.persistDiscoveryBatch(ctx, job, messages, verifications); err != nil {
			return fmt.Errorf("failed to persist discovery batch: %w", err)
		}

		// Gather CCV records from verifiers for each discovered message
		if e.registry != nil {
			for _, resp := range responses {
				if err := e.gatherVerificationsForMessage(ctx, job, resp.Data); err != nil {
					e.lggr.Warnw("Failed to gather verifications during discovery replay",
						"jobID", job.ID,
						"messageID", resp.Data.MessageID,
						"error", err,
					)
				}
			}
		}

		currentCursor, _ := reader.GetSinceValue()
		totalProcessed += len(responses)

		if err := e.store.UpdateProgress(ctx, e.store.DataSource(), job.ID, currentCursor, totalProcessed); err != nil {
			e.lggr.Warnw("Failed to checkpoint progress", "jobID", job.ID, "error", err)
		}

		time.Sleep(e.batchThrottleDelay)
	}
}

func (e *Engine) persistDiscoveryBatch(
	ctx context.Context,
	job *Job,
	messages []common.MessageWithMetadata,
	verifications []common.VerifierResultWithMetadata,
) error {
	encodable, skipped := common.FilterEncodableMessages(messages)
	for _, s := range skipped {
		e.lggr.Warnw("Skipping non-encodable message in replay", "index", s.Index, "reason", s.Reason)
	}

	if len(encodable) > 0 {
		if err := e.storage.UpsertMessages(ctx, encodable, job.ForceOverwrite); err != nil {
			return fmt.Errorf("failed to upsert messages: %w", err)
		}
	}

	if len(verifications) > 0 {
		if err := e.storage.UpsertVerifierResults(ctx, verifications, job.ForceOverwrite); err != nil {
			return fmt.Errorf("failed to upsert verifications: %w", err)
		}
	}

	return nil
}

// gatherVerificationsForMessage fetches CCV records from all known verifiers
// for a single message using CCV addresses already present in the discovery
// response and persists them.
func (e *Engine) gatherVerificationsForMessage(ctx context.Context, job *Job, vr protocol.VerifierResult) error {
	return e.queryVerifiers(ctx, job, vr.MessageID, vr.MessageCCVAddresses)
}
