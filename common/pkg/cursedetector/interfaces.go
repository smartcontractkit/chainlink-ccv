package cursedetector

import (
	"context"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// RMNCurseReader provides read-only access to RMN Remote curse state.
// Both SourceReader and DestinationReader implement this interface.
type RMNCurseReader interface {
	// GetRMNCursedSubjects queries the configured RMN Remote contract.
	// Returns cursed subjects as bytes16, which can be:
	// - Global curse constant (0x0100000000000000000000000000000001)
	// - Chain selectors as bytes16s
	GetRMNCursedSubjects(ctx context.Context) ([]protocol.Bytes16, error)
}

// CurseDetector monitors RMN Remotes for curse status.
// Reusable for both verifier (source RMN Remotes) and executor (dest RMN Remotes).
type CurseDetector interface {
	// IsRemoteChainCursed checks if remoteChain is cursed per localChain's RMN Remote.
	// Returns true if:
	//   - remoteChain appears in localChain's cursed subjects, OR
	//   - localChain has a global curse
	//
	// Usage:
	//   Verifier: IsRemoteChainCursed(sourceChain, destChain)
	//   Executor: IsRemoteChainCursed(destChain, sourceChain)
	IsRemoteChainCursed(localChain, remoteChain protocol.ChainSelector) bool

	// Start begins polling RMN Remote contracts for curse updates.
	Start(ctx context.Context) error

	// Close stops the curse detector.
	Close() error
}
