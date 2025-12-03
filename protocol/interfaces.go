package protocol

import (
	"context"
	"math/big"
)

// ChainStatusInfo represents chain status with selector, block height and disabled state.
type ChainStatusInfo struct {
	ChainSelector        ChainSelector
	FinalizedBlockHeight *big.Int
	Disabled             bool
}

// ChainStatusManager defines the interface for chain status operations.
type ChainStatusManager interface {
	// WriteChainStatuses writes chain statuses for multiple chains atomically
	WriteChainStatuses(ctx context.Context, statuses []ChainStatusInfo) error

	// ReadChainStatuses reads chain statuses for multiple chains
	// Returns map of chainSelector -> ChainStatusInfo
	// Missing chains are not included in the map
	ReadChainStatuses(ctx context.Context, chainSelectors []ChainSelector) (map[ChainSelector]*ChainStatusInfo, error)
}

// HealthReporter should be implemented by any type requiring health checks.
type HealthReporter interface {
	// Ready should return nil if ready, or an error message otherwise. From the k8s docs:
	// > ready means it's initialized and healthy means that it can accept traffic in kubernetes
	// See: https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/
	Ready() error
	// HealthReport returns a full health report of the callee including its dependencies.
	// Keys are based on Name(), with nil values when healthy or errors otherwise.
	// Use CopyHealth to collect reports from sub-services.
	// This should run very fast, so avoid doing computation and instead prefer reporting pre-calculated state.
	HealthReport() map[string]error
	// Name returns the fully qualified name of the component. Usually the logger name.
	Name() string
}

// Service represents a long-running service inside the Application.
//
// The simplest way to implement a Service is via NewService.
//
// For other cases, consider embedding a services.StateMachine to implement these
// calls in a safe manner.
type Service interface {
	// Start the service.
	//  - Must return promptly if the context is canceled.
	//  - Must not retain the context after returning (only applies to start-up)
	//  - Must not depend on external resources (no blocking network calls)
	Start(context.Context) error
	// Close stops the Service.
	// Invariants: Usually after this call the Service cannot be started
	// again, you need to build a new Service to do so.
	//
	// See MultiCloser
	Close() error

	HealthReporter
}

// FinalityViolationChecker validates that finalized blocks never change their hash.
// This is a synchronous, pull-based interface driven by the caller (typically SourceReaderService).
// The caller updates the checker with new finalized blocks and checks for violations before processing.
type FinalityViolationChecker interface {
	// UpdateFinalized tells the checker about a new finalized block.
	// The checker will fetch and store block headers from the last known finalized up to this block.
	// This should be called on every poll cycle before checking for violations.
	// Returns error if headers cannot be fetched.
	UpdateFinalized(ctx context.Context, finalizedBlock uint64) error

	// IsFinalityViolated checks if any previously finalized block has changed its hash.
	// This performs a lightweight check against stored state without making RPC calls.
	// Should be called after UpdateFinalized to validate chain consistency.
	// Returns true if a violation is detected (critical error requiring service shutdown).
	IsFinalityViolated() bool
}
