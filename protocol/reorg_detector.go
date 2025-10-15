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
	// InitialStatus fetches initial chain status (stable block as single-block tail).
	InitialStatus(ctx context.Context) (ChainStatus, error)

	// Start begins the reorg detection loop.
	// Sends ChainStatus updates to statusChan.
	// Must be called after InitialStatus.
	Start(ctx context.Context, initialStatus ChainStatus, statusChan chan<- ChainStatus) error

	// Close stops the reorg detection loop.
	Close() error
}
