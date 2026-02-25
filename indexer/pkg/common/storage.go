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
	MessageStorageReader
	DiscoveryStateReader
}

type IndexerStorageWriter interface {
	VerifierResultsStorageWriter
	MessageStorageWriter
	DiscoveryStateWriter
	// PersistDiscoveryBatch atomically persists messages, verifications, and the discovery sequence number.
	PersistDiscoveryBatch(ctx context.Context, batch DiscoveryBatch) error
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
	QueryMessages(ctx context.Context, start, end int64, sourceChainSelectors, destChainSelectors []protocol.ChainSelector, limit, offset uint64) ([]MessageWithMetadata, error)
}

// MessageStorageWriter provides the interface to insert messages to storage.
type MessageStorageWriter interface {
	// InsertMessages appends a list of messages into storage.
	InsertMessages(ctx context.Context, messages []MessageWithMetadata) error
	// UpdateMessageStatus updates the status of indexing to storage.
	UpdateMessageStatus(ctx context.Context, messageID protocol.Bytes32, status MessageStatus, lastErr string) error
}

// DiscoveryStateReader provides the interface to retrieve the state for different discovery sources.
type DiscoveryStateReader interface {
	// GetDiscoverySequenceNumber returns the latest sequence number for a given discovery source.
	GetDiscoverySequenceNumber(ctx context.Context, discoveryLocation string) (int, error)
}

// DiscoveryStateWriter provides the interface to insert and update state for different discovery sources.
type DiscoveryStateWriter interface {
	// CreateDiscoveryState creates a new record containing metadata about the discovery source.
	CreateDiscoveryState(ctx context.Context, discoveryLocation string, startingSequenceNumber int) error
}
