package protocol

import (
	"context"
	"time"
)

// ReorgDetectorConfig contains configuration for reorg detection.
type ReorgDetectorConfig struct {
	MaxTailLength int           // Maximum blocks to keep in tail
	CheckInterval time.Duration // How often to check for reorgs
}

// ReorgType indicates the type of reorg detected.
type ReorgType int

const (
	ReorgTypeRegular ReorgType = iota
	ReorgTypeFinalityViolation
)

// String returns the string representation of ReorgType.
func (r ReorgType) String() string {
	switch r {
	case ReorgTypeRegular:
		return "Regular"
	case ReorgTypeFinalityViolation:
		return "FinalityViolation"
	default:
		return "Unknown"
	}
}

// ReorgNotification is sent to SourceReaderService when a reorg is detected.
type ReorgNotification struct {
	ChainSelector ChainSelector
	ResetToBlock  uint64    // Block number to reset reader to
	Type          ReorgType // Regular or FinalityViolation
}

// ChainStatus is a marker interface for different chain status types.
// Implementations: ChainStatusGood, ChainStatusReorg, ChainStatusFinalityViolated
type ChainStatus interface {
	isChainStatus()
}

// Implement marker interface for all ChainStatus types
func (ChainStatusGood) isChainStatus()             {}
func (ChainStatusReorg) isChainStatus()            {}
func (ChainStatusFinalityViolated) isChainStatus() {}

// ReorgDetector monitors a blockchain for reorgs and finality violations.
type ReorgDetector interface {
	// Start fetches the initial chain tail (up to MaxTailLength blocks from finalized head),
	// then begins monitoring for reorgs. Blocks until initial tail is ready.
	// The first message sent on the returned channel is the initial ChainStatusGood.
	// Subsequent messages indicate reorgs (ChainStatusReorg) or finality violations (ChainStatusFinalityViolated).
	// Returns error if initial tail cannot be fetched.
	// The returned channel is closed when the detector stops.
	Start(ctx context.Context) (<-chan ChainStatus, error)

	// Close stops the detector and closes the status channel.
	Close() error
}
