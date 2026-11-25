package common

import (
	"context"
	"errors"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// IndexerStorage defines the interface for all storage operations for the indexer.
// Implementations should be thread-safe.
type IndexerStorage interface {
	IndexerStorageReader
	IndexerStorageWriter
	protocol.HealthReporter
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
	// InsertVerifierResults appends a list of verifier results to the storage
	InsertVerifierResults(ctx context.Context, verifierResults []VerifierResultWithMetadata) error
}

// MessageStorageReader provides the interface to retrieve messages from storage.
type MessageStorageReader interface {
	// GetMessage using the messageID for a o(1) lookup
	GetMessage(ctx context.Context, messageID protocol.Bytes32) (MessageWithMetadata, error)
	// QueryMessages retrieves all messages that matches the filter set
	QueryMessages(ctx context.Context, start, end int64, sourceChainSelectors, destChainSelectors []protocol.ChainSelector, limit, offset uint64) ([]MessageWithMetadata, error)
	// GetProcessingMessages returns a page of messages currently in PROCESSING status
	// whose ingestion_timestamp is after createdAfter (i.e. still within the visibility window).
	// Used at startup to resume tasks that were interrupted before completion.
	GetProcessingMessages(ctx context.Context, createdAfter time.Time, limit, offset uint64) ([]MessageWithMetadata, error)
}

// MessageStorageWriter provides the interface to update message state in storage.
type MessageStorageWriter interface {
	// UpdateMessageStatus updates the status of indexing to storage.
	UpdateMessageStatus(ctx context.Context, messageID protocol.Bytes32, status MessageStatus, lastErr string) error
	// ClaimWork leases up to limit due PROCESSING messages inside their retry_deadline, and increments their attempt count.
	ClaimWork(ctx context.Context, limit int, lease time.Duration) ([]WorkClaim, error)
	// SettleWork ends one attempt while the claim is held; it returns ErrClaimLost when it is not.
	SettleWork(ctx context.Context, s WorkSettlement) (MessageStatus, error)
	// ExpireWork times out up to limit PROCESSING messages that are not leased and are past their deadline.
	ExpireWork(ctx context.Context, limit int) (int64, error)
	// CountProcessingMessages returns the number of PROCESSING messages.
	CountProcessingMessages(ctx context.Context) (int64, error)
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

// DiscoveryLocker gives the lock that allows one discovery leader across all indexer replicas.
type DiscoveryLocker interface {
	// TryAcquireDiscoveryLock gets the lock without blocking. acquired is false when another replica holds it.
	// The store frees the lock if the holder sends no heartbeat for leaseTimeout.
	TryAcquireDiscoveryLock(ctx context.Context, leaseTimeout time.Duration) (lock DiscoveryLock, acquired bool, err error)
}

// DiscoveryLock is a held discovery lock.
type DiscoveryLock interface {
	// Heartbeat keeps the lock. An error means that the lock can be lost.
	Heartbeat(ctx context.Context) error
	// Release frees the lock. It is safe to call more than once.
	Release()
}

// ErrClaimLost means another worker claimed the message again, or the message is no longer PROCESSING.
var ErrClaimLost = errors.New("worker claim lost")

// WorkClaim is one leased message. Attempt is the claim token: ClaimWork increments it.
// SettleWork changes the row only if attempt_count is still Attempt, so a stale worker gets ErrClaimLost.
type WorkClaim struct {
	MessageID protocol.Bytes32
	Attempt   int
	// TraceParent is the w3c traceparent of the discovery span, empty if none was stored.
	TraceParent string
}

// WorkSettlement ends one attempt. Status MessageProcessing schedules a retry after RetryDelay.
type WorkSettlement struct {
	MessageID  protocol.Bytes32
	Attempt    int
	Status     MessageStatus
	LastErr    string
	RetryDelay time.Duration
}
