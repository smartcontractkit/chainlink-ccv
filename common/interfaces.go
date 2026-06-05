package common

import (
	"context"
	"errors"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// ErrCurseStateUnknown indicates curse state could not be determined (e.g. no successful RPC poll yet).
// Callers should treat the lane as cursed (fail closed) when this error is returned.
var ErrCurseStateUnknown = errors.New("curse state unknown: no successful RPC poll yet")

// ErrMessageRulesStateUnknown indicates message rules could not be determined.
// Callers should block/retry until a successful rules refresh instead of dropping or signing.
var ErrMessageRulesStateUnknown = errors.New("message rules state unknown: no successful aggregator poll yet")

// CurseChecker abstracts checking for chain curse status.
// Implementations expected to use RMNCurseReader to poll RMN Remote contracts and maintain curse state.
// Reusable for both verifier (source RMN Remotes) and executor (dest RMN Remotes).
type CurseChecker interface {
	// IsRemoteChainCursed checks if remoteChain is cursed per localChain's RMN Remote.
	// Returns (true, nil) if cursed, (false, nil) if not cursed.
	// Returns (true, ErrCurseStateUnknown) when state is unknown (fail closed).
	//
	// Usage:
	//   Verifier: IsRemoteChainCursed(sourceChain, destChain)
	//   Executor: IsRemoteChainCursed(destChain, sourceChain)
	IsRemoteChainCursed(ctx context.Context, localChain, remoteChain protocol.ChainSelector) (bool, error)
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

// MessageRulesChecker validates that messages match active message rules.
type MessageRulesChecker interface {
	// IsMessageDisabled checks whether the provided message matches an active message rule.
	// Returns (true, nil) if disabled, (false, nil) if not disabled.
	// Returns (true, ErrMessageRulesStateUnknown) when state is unknown (fail closed).
	IsMessageDisabled(ctx context.Context, message protocol.Message) (bool, error)
}

type MessageRulesCheckerMetrics interface {
	// SetMessageDisablementRulesRefreshFailure records whether the latest registry refresh failed.
	SetMessageDisablementRulesRefreshFailure(ctx context.Context, failed int64)
}

type MessageRulesCheckerService interface {
	protocol.Service
	MessageRulesChecker
}
