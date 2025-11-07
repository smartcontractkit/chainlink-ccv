package storageaccess

import (
	"context"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// AggregatorChainStatusManager implements ChainStatusManager using AggregatorWriter and AggregatorReader.
type AggregatorChainStatusManager struct {
	writer *AggregatorWriter
	reader *AggregatorReader
}

// NewAggregatorChainStatusManager creates a new chain status manager with injected dependencies.
func NewAggregatorChainStatusManager(writer *AggregatorWriter, reader *AggregatorReader) protocol.ChainStatusManager {
	return &AggregatorChainStatusManager{
		writer: writer,
		reader: reader,
	}
}

// WriteChainStatuses writes chain statuses for multiple chains atomically using the aggregator writer.
func (cm *AggregatorChainStatusManager) WriteChainStatuses(ctx context.Context, statuses []protocol.ChainStatusInfo) error {
	return cm.writer.WriteChainStatus(ctx, statuses)
}

// ReadChainStatuses reads chain statuses for multiple chains using the aggregator reader.
// Returns map of chainSelector -> ChainStatusInfo. Missing chains are not included in the map.
func (cm *AggregatorChainStatusManager) ReadChainStatuses(ctx context.Context, chainSelectors []protocol.ChainSelector) (map[protocol.ChainSelector]*protocol.ChainStatusInfo, error) {
	return cm.reader.ReadChainStatus(ctx, chainSelectors)
}

// Close closes both the writer and reader connections.
func (cm *AggregatorChainStatusManager) Close() error {
	var writerErr, readerErr error

	if cm.writer != nil {
		writerErr = cm.writer.Close()
	}

	if cm.reader != nil {
		readerErr = cm.reader.Close()
	}

	// Return the first error encountered
	if writerErr != nil {
		return writerErr
	}
	return readerErr
}

// GetWriter returns the underlying AggregatorWriter for CCV data operations.
func (cm *AggregatorChainStatusManager) GetWriter() *AggregatorWriter {
	return cm.writer
}

// GetReader returns the underlying AggregatorReader for CCV data operations.
func (cm *AggregatorChainStatusManager) GetReader() *AggregatorReader {
	return cm.reader
}
