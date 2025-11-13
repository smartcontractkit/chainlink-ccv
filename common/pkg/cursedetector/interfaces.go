package cursedetector

import (
	"context"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

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
