package common

import (
	"context"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// IndexerStorage defines the interface for all storage operations for the indexer.
// Implementations should be thread-safe.
type IndexerStorage interface {
	IndexerStorageReader
	IndexerStorageWriter
}

type IndexerStorageReader interface {
	VerifierResultsStorageReader
}

type IndexerStorageWriter interface {
	VerifierResultsStorageWriter
}

// VerifierResultsStorageReader provides the interface to retrieve verification results from storage.
type VerifierResultsStorageReader interface {
	// GetCCVData using the messageID for a o(1) lookup
	GetCCVData(ctx context.Context, messageID protocol.Bytes32) ([]VerifierResultWithMetadata, error)
	// QueryCCVData retrieves all CCVData that matches the filter set
	QueryCCVData(ctx context.Context, start, end int64, sourceChainSelectors, destChainSelectors []protocol.ChainSelector, limit, offset uint64) (map[string][]VerifierResultWithMetadata, error)
}

// VerifierResultsStorageWriter provides the interface for inserting verifications to storage.
type VerifierResultsStorageWriter interface {
	// InsertCCVData appends a new CCVData to the storage for the given messageID
	InsertCCVData(ctx context.Context, ccvData VerifierResultWithMetadata) error
	// BatchInsertCCVData appends a list of CCVData to the storage
	BatchInsertCCVData(ctx context.Context, ccvDataList []VerifierResultWithMetadata) error
}

// MessageStorageReader provides the interface to retrieve messages from storage.
type MessageStorageReader interface {
	// GetMessage using the messageID for a o(1) lookup
	GetMessage(ctx context.Context, messageID protocol.Bytes32) (MessageWithMetadata, error)
	// QueryMessages retrieves all messages that matches the filter set
	QueryMessages(ctx context.Context, start, end int64, sourceChainSelectors, destChainSelectors []protocol.ChainSelector, limit, offset uint64) (MessageWithMetadata, error)
}

// MessageStorageWriter provides the interface to insert messages to storage.
type MessageStorageWriter interface {
	// InsertMessage inserts a message into storage.
	InsertMessage(ctx context.Context, message protocol.Message) error
	// BatchInsertMessages appends a list of messages into storage.
	BatchInsertMessages(ctx context.Context, messages []protocol.Message) error
	// UpdateMessageStatus updates the status of indexing to storage.
	UpdateMessageStatus(ctx context.Context, messageID protocol.Bytes32, status MessageStatus, lastErr string) error
}
