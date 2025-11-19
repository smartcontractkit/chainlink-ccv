package common

import (
	context "context"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// CurseChecker abstracts checking for chain curse status.
// Implementations expected to use RMNCurseReader to poll RMN Remote contracts and maintain curse state.
// Reusable for both verifier (source RMN Remotes) and executor (dest RMN Remotes).
type CurseChecker interface {
	// IsRemoteChainCursed checks if remoteChain is cursed per localChain's RMN Remote.
	// Returns true if:
	//   - remoteChain appears in localChain's cursed subjects, OR
	//   - localChain has a global curse
	//
	// Usage:
	//   Verifier: IsRemoteChainCursed(sourceChain, destChain)
	//   Executor: IsRemoteChainCursed(destChain, sourceChain)
	IsRemoteChainCursed(ctx context.Context, localChain, remoteChain protocol.ChainSelector) bool
}

type CurseCheckerService interface {
	protocol.Service
	CurseChecker
}

type RMNRemoteReader interface {
	GetRMNCursedSubjects(ctx context.Context) ([]protocol.Bytes16, error)
}
