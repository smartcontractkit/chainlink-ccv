package chainstatus

// LaneReport exposes the chain selectors for both ends of a lane.
// Both *model.CommitVerificationRecord and *model.CommitAggregatedReport satisfy this interface.
// The interface is intentionally broad so future checks (e.g. token address, off-ramp address)
// can be added without changing IsDisabled's signature.
type LaneReport interface {
	// GetSourceChainSelector returns the source chain selector for the lane.
	GetSourceChainSelector() uint64
	// GetDestinationSelector returns the destination chain selector for the lane.
	GetDestinationSelector() uint64
}

// Checker determines whether chain processing is currently disabled for a given lane.
type Checker interface {
	// IsDisabled returns true if chain processing is disabled for the given lane report.
	IsDisabled(report LaneReport) bool
}

// NoopChecker never disables any chain. Use in tests and when no registry is wired.
type NoopChecker struct{}

func (NoopChecker) IsDisabled(_ LaneReport) bool { return false }
