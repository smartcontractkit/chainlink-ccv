package protocol

import (
	"time"
)

// BlockHeader represents blockchain block header metadata.
type BlockHeader struct {
	Number               uint64
	Hash                 Bytes32
	ParentHash           Bytes32
	Timestamp            time.Time
	FinalizedBlockNumber uint64 // Latest finalized block at time of this block
}

// ReorgType indicates the type of reorg detected.
type ReorgType int

const (
	// ReorgTypeNormal indicates a regular reorg within finalized boundaries.
	ReorgTypeNormal ReorgType = iota
	// ReorgTypeFinalityViolation indicates a finality violation (critical error).
	ReorgTypeFinalityViolation
)

// String returns the string representation of ReorgType.
func (r ReorgType) String() string {
	switch r {
	case ReorgTypeNormal:
		return "Normal"
	case ReorgTypeFinalityViolation:
		return "FinalityViolation"
	default:
		return "Unknown"
	}
}

// ChainStatus represents a reorg or finality violation event.
//
// ResetToBlock usage:
// - ReorgTypeNormal: Block number to reset to (common ancestor)
// - ReorgTypeFinalityViolation: Always 0 (no safe reset point - requires immediate stop).
type ChainStatus struct {
	Type         ReorgType
	ResetToBlock uint64 // Block number to reset to (0 for finality violations)
}

func (c ChainStatus) IsFinalityViolated() bool {
	return c.Type == ReorgTypeFinalityViolation
}
