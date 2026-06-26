package readers

import (
	"context"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

var _ protocol.VerifierResultsAPI = (*observedReader)(nil)

type observedReader struct {
	protocol.VerifierResultsAPI

	m common.IndexerMetricLabeler
}

// NewObservedReader wraps a VerifierResultsAPI, tagging its metrics and logs with
// a "target" label so per-target read health is observable independently.
func NewObservedReader(
	delegate protocol.VerifierResultsAPI,
	m common.IndexerMetricLabeler,
) protocol.VerifierResultsAPI {
	return &observedReader{
		VerifierResultsAPI: delegate,
		m:                  m,
	}
}

func (o *observedReader) GetVerifications(ctx context.Context, messageIDs []protocol.Bytes32) (map[protocol.Bytes32]protocol.VerifierResult, error) {
	start := time.Now()

	results, err := o.VerifierResultsAPI.GetVerifications(ctx, messageIDs)

	duration := time.Since(start)
	errored := err != nil

	if errored {
		o.m.IncrementStorageError(ctx, "GetVerifications")
	}

	o.m.RecordStorageLatency(ctx, "GetVerifications", duration, errored)

	return results, err
}
