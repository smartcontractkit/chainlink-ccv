package verifier

import (
	"context"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/batcher"
)

// verifierDBAdapter adapts the existing Verifier interface (which pushes results to a batcher)
// to the DB interface (which returns results directly).
//
// It creates a short-lived in-memory batcher per call, lets the Verifier populate it,
// then cancels the batcher's context to flush and drain all collected results.
type verifierDBAdapter struct {
	verifier Verifier
}

func (a *verifierDBAdapter) VerifyMessages(ctx context.Context, tasks []VerificationTask) ([]protocol.VerifierNodeResult, []VerificationError) {
	// Create a child context we can cancel to flush the batcher after verification completes.
	batcherCtx, cancelBatcher := context.WithCancel(ctx)
	defer cancelBatcher()

	// maxSize large enough that it never auto-flushes mid-batch; maxWait long enough
	// that timer-based flushing doesn't interfere before we cancel ourselves.
	b := batcher.NewBatcher[protocol.VerifierNodeResult](batcherCtx, len(tasks)+1, 24*time.Hour, 1)

	errorBatch := a.verifier.VerifyMessages(ctx, tasks, b)

	// Cancel the batcher context so its background goroutine exits and closes outCh.
	cancelBatcher()

	// Drain all results from the now-closing batcher.
	var results []protocol.VerifierNodeResult
	for batch := range b.OutChannel() {
		if batch.Error == nil {
			results = append(results, batch.Items...)
		}
	}

	return results, errorBatch.Items
}
