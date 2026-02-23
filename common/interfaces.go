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

type CurseCheckerMetrics interface {
	// SetRemoteChainCursed sets value 1 if source chain is cursed
	SetRemoteChainCursed(ctx context.Context, localSelector, remoteSelector protocol.ChainSelector, cursed bool)
	// SetLocalChainGlobalCursed sets value 1 if source chain is cursed
	SetLocalChainGlobalCursed(ctx context.Context, localSelector protocol.ChainSelector, globalCurse bool)
}

// TimeProvider is an interface for providing the current time.
type TimeProvider interface {
	// GetTime provides the current time.
	GetTime() time.Time
}
