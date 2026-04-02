package replay

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

func (e *Engine) runMessageReplay(ctx context.Context, job *Job) error {
	if len(job.MessageIDs) == 0 {
		return fmt.Errorf("message replay requires at least one message ID")
	}
	if e.registry == nil {
		return fmt.Errorf("verifier registry not configured")
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

		if err := e.gatherAllVerifications(ctx, job, msgID); err != nil {
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
// single message ID. CCV addresses are read from the messages table, which is
// populated during discovery.
func (e *Engine) gatherAllVerifications(ctx context.Context, job *Job, msgID protocol.Bytes32) error {
	msg, err := e.storage.GetMessage(ctx, msgID)
	if err != nil {
		e.lggr.Warnw("Message not found in local storage, skipping verifier gathering",
			"messageID", msgID,
		)
		return nil
	}

	if len(msg.MessageCCVAddresses) == 0 {
		e.lggr.Warnw("No CCV addresses stored for message, skipping verifier gathering",
			"messageID", msgID,
		)
		return nil
	}

	return e.queryVerifiers(ctx, job, msgID, msg.MessageCCVAddresses)
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
