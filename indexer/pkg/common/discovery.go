package common

import "context"

// MessageDiscovery defines the interface for discovering messages from a trusted discovery source.
type MessageDiscovery interface {
	// Start MessageDiscovery and listen to new CCIP Messages.
	Start(ctx context.Context) chan VerifierResultWithMetadata
	// Close gracefully stops MessageDiscovery.
	Close() error
	// Replay messages since a given sequence number until an inclusive end value.
	Replay(ctx context.Context, start, end uint64) error
}
