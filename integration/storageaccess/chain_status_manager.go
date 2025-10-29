package storageaccess

import (
	"context"
	"math/big"

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

// WriteChainStatus writes a chain status using the aggregator writer.
func (cm *AggregatorChainStatusManager) WriteChainStatus(ctx context.Context, chainSelector protocol.ChainSelector, blockHeight *big.Int) error {
	return cm.writer.WriteChainStatus(ctx, chainSelector, blockHeight, false) // Default to not disabled
}

// ReadChainStatus reads a chain status using the aggregator reader.
func (cm *AggregatorChainStatusManager) ReadChainStatus(ctx context.Context, chainSelector protocol.ChainSelector) (*big.Int, error) {
	return cm.reader.ReadChainStatus(ctx, chainSelector)
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
