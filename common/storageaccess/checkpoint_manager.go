package storageaccess

import (
	"context"
	"math/big"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// AggregatorCheckpointManager implements CheckpointManager using AggregatorWriter and AggregatorReader.
type AggregatorCheckpointManager struct {
	writer *AggregatorWriter
	reader *AggregatorReader
}

// NewAggregatorCheckpointManager creates a new checkpoint manager with injected dependencies.
func NewAggregatorCheckpointManager(writer *AggregatorWriter, reader *AggregatorReader) protocol.CheckpointManager {
	return &AggregatorCheckpointManager{
		writer: writer,
		reader: reader,
	}
}

// WriteCheckpoint writes a checkpoint using the aggregator writer.
func (cm *AggregatorCheckpointManager) WriteCheckpoint(ctx context.Context, chainSelector protocol.ChainSelector, blockHeight *big.Int) error {
	return cm.writer.WriteCheckpoint(ctx, chainSelector, blockHeight)
}

// ReadCheckpoint reads a checkpoint using the aggregator reader.
func (cm *AggregatorCheckpointManager) ReadCheckpoint(ctx context.Context, chainSelector protocol.ChainSelector) (*big.Int, error) {
	return cm.reader.ReadCheckpoint(ctx, chainSelector)
}

// Close closes both the writer and reader connections.
func (cm *AggregatorCheckpointManager) Close() error {
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
func (cm *AggregatorCheckpointManager) GetWriter() *AggregatorWriter {
	return cm.writer
}

// GetReader returns the underlying AggregatorReader for CCV data operations.
func (cm *AggregatorCheckpointManager) GetReader() *AggregatorReader {
	return cm.reader
}
