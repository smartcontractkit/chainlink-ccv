package common

import (
	"context"
	"time"

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

// CurseCheckerService is an interface that combines a CurseChecker and a Service.
// Used in the verifier that wants to consistently poll chains rather than executor which wants to query on demand.
type CurseCheckerService interface {
	protocol.Service
	CurseChecker
}

// RMNRemoteReader provides read-only access to RMN Remote curse state.
type RMNRemoteReader interface {
	// GetRMNCursedSubjects queries the configured RMN Remote contract. Shared between verifier and executor.
	// Returns cursed subjects as bytes16, which can be:
	// - Global curse constant (0x0100000000000000000000000000000001)
	// - Chain selectors as bytes16s
	GetRMNCursedSubjects(ctx context.Context) ([]protocol.Bytes16, error)
}

// TimeProvider is an interface for providing the current time.
type TimeProvider interface {
	// GetTime provides the current time.
	GetTime() time.Time
}
