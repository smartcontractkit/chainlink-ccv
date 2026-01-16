package storage

import (
	"context"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// Entry represents a stored verifier node result with additional metadata.
type Entry struct {
	value                 protocol.VerifierNodeResult
	verifierSourceAddress protocol.UnknownAddress
	verifierDestAddress   protocol.UnknownAddress
	timestamp             time.Time
}

// CCVStorage defines the interface for storing and retrieving verifier node results.
// It abstracts the underlying storage mechanism - it could be in-memory, database, s3, etc.
type CCVStorage interface {
	// Get retrieves entries by their message IDs or error
	Get(ctx context.Context, keys []protocol.Bytes32) (map[protocol.Bytes32]Entry, error)
	// Set stores multiple entries, errors if any entry fails to store.
	Set(ctx context.Context, entries []Entry) error
}
