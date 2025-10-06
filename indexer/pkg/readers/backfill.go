package readers

import (
	"context"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

var _ protocol.DisconnectableReader = (*BackfillReader)(nil)

type BackfillReader struct {
	reader    protocol.OffchainStorageReader
	startUnix int64
	endUnix   int64
	// disconnectSignal tracks whether this reader should be disconnected
	disconnectSignal bool
}

func NewBackfillReader(reader protocol.OffchainStorageReader, lggr logger.Logger, startUnix, endUnix int64) *ResilientReader {
	config := DefaultResilienceConfig()
	config.AllowDisconnect = true
	config.MaxRequestsPerSecond = 100 // Allow high requests per second to quickly read the entire backfill
	return NewResilientReader(&BackfillReader{reader: reader, startUnix: startUnix, endUnix: endUnix}, lggr, config)
}

func (b *BackfillReader) ReadCCVData(ctx context.Context) ([]protocol.QueryResponse, error) {
	queryResponse, err := b.reader.ReadCCVData(ctx)
	if err != nil {
		return nil, err
	}

	// Filter the query response to only include those within the timestamp range [startUnix, endUnix)
	// If the timestamp is greater than or equal to the endUnix, signal for disconnection
	var filteredQueryResponse []protocol.QueryResponse
	for _, response := range queryResponse {
		if response.Timestamp != nil && *response.Timestamp >= b.startUnix && *response.Timestamp < b.endUnix {
			filteredQueryResponse = append(filteredQueryResponse, response)
		}

		if response.Timestamp != nil && *response.Timestamp >= b.endUnix {
			b.disconnectSignal = true
		}
	}

	return filteredQueryResponse, nil
}

// ShouldDisconnect implements the DisconnectableReader interface.
// Returns true when the reader has reached the endUnix timestamp and should be disconnected.
func (b *BackfillReader) ShouldDisconnect() bool {
	return b.disconnectSignal
}
