package chaindisable

import (
	"context"
	"time"
)

// LaneSide identifies which side of a lane a chain status applies to.
type LaneSide string

const (
	LaneSideSource      LaneSide = "source"
	LaneSideDestination LaneSide = "destination"
)

// ChainStatus represents the disabled state of a chain for one lane side.
// No row in the DB means enabled; a row with disabled=false is the audit trail after re-enabling.
type ChainStatus struct {
	ChainSelector uint64
	Side          LaneSide
	Disabled      bool
	UpdatedAt     time.Time
}

// Store persists chain disable/enable state.
type Store interface {
	// BatchSetStatus upserts disabled status for the given side and selectors.
	// Pass disabled=true to disable, disabled=false to re-enable.
	BatchSetStatus(ctx context.Context, side LaneSide, selectors []uint64, disabled bool) error
	// List returns all chain status rows, including re-enabled ones (audit trail).
	List(ctx context.Context) ([]ChainStatus, error)
	// ListDisabled returns only rows where disabled = true.
	ListDisabled(ctx context.Context) ([]ChainStatus, error)
	// Get returns the status for a specific selector + lane side. Returns nil if no row exists (= enabled).
	Get(ctx context.Context, side LaneSide, selector uint64) (*ChainStatus, error)
}
