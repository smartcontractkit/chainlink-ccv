package sourcereader

import (
	"context"

	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
)

var _ chainaccess.SourceReader = (*observedSourceReader)(nil)

// observedSourceReader wraps a SourceReader and use a decorator pattern to track various metrics.
// Currently, it tracks the latest and finalized block numbers observed from the source chain.
// In the future it should also track number of requests made, errors, and latencies (i.e. using histograms).
// It must stay chain-agnostic to allow easy plug-and-play behavior for different chain families.
type observedSourceReader struct {
	chainaccess.SourceReader

	verifierID    string
	chainSelector string
	monitoring    verifier.Monitoring
}

func NewObservedSourceReader(
	sourceReader chainaccess.SourceReader,
	verifierID string,
	chainSelector protocol.ChainSelector,
	monitoring verifier.Monitoring,
) chainaccess.SourceReader {
	return observedSourceReader{
		SourceReader:  sourceReader,
		verifierID:    verifierID,
		chainSelector: chainSelector.String(),
		monitoring:    monitoring,
	}
}

func (o observedSourceReader) LatestAndFinalizedBlock(ctx context.Context) (latest, finalized *protocol.BlockHeader, err error) {
	latest, finalized, err = o.SourceReader.LatestAndFinalizedBlock(ctx)
	if err != nil {
		return latest, finalized, err
	}

	if latest != nil {
		o.monitoring.Metrics().
			With("source_chain", o.chainSelector, "verifier_id", o.verifierID).
			//nolint:gosec // disable G115
			RecordSourceChainLatestBlock(ctx, int64(latest.Number))
	}

	if finalized != nil {
		o.monitoring.Metrics().
			With("source_chain", o.chainSelector, "verifier_id", o.verifierID).
			//nolint:gosec // disable G115
			RecordSourceChainFinalizedBlock(ctx, int64(finalized.Number))
	}
	return latest, finalized, err
}
