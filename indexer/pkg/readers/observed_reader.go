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
	protocol.DiscoveryStorageReader

	m common.IndexerMetricLabeler
}

func NewObservedReader(
	verifierResultsAPI protocol.VerifierResultsAPI,
	discoveryStorageReader protocol.DiscoveryStorageReader,
	m common.IndexerMetricLabeler,
) protocol.VerifierResultsAPI {
	return &observedReader{
		VerifierResultsAPI:     verifierResultsAPI,
		DiscoveryStorageReader: discoveryStorageReader,
		m:                      m,
	}
}

func (o *observedReader) GetVerifications(ctx context.Context, messageIDs []protocol.Bytes32) (map[protocol.Bytes32]protocol.VerifierResult, error) {
	start := time.Now()
	results, err := o.VerifierResultsAPI.GetVerifications(ctx, messageIDs)
	duration := time.Since(start)
	errored := err != nil
	if errored {
		o.m.IncrementOffchainReadError(ctx)
	}
	o.m.RecordOffchainReadLatency(ctx, duration, errored)

	return results, err
}

func (o *observedReader) ReadCCVData(ctx context.Context) ([]protocol.QueryResponse, error) {
	start := time.Now()
	results, err := o.DiscoveryStorageReader.ReadCCVData(ctx)
	duration := time.Since(start)
	errored := err != nil
	if errored {
		o.m.IncrementOffchainReadError(ctx)
	}
	o.m.RecordOffchainReadLatency(ctx, duration, errored)

	return results, err
}

func (o *observedReader) GetSinceValue() int64 {
	return o.DiscoveryStorageReader.GetSinceValue()
}

func (o *observedReader) SetSinceValue(since int64) {
	o.DiscoveryStorageReader.SetSinceValue(since)
}
