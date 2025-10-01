package readers

import (
	"context"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

var _ protocol.DisconnectableReader = (*BackfillReader)(nil)

type BackfillReader struct {
	reader    protocol.OffchainStorageReader
	startUnix int64
	endUnix   int64
	// disconnectSignal tracks whether this reader should be disconnected
	disconnectSignal bool
}

func NewBackfillReader(reader protocol.OffchainStorageReader, startUnix, endUnix int64) *BackfillReader {
	return &BackfillReader{reader: reader, startUnix: startUnix, endUnix: endUnix}
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
