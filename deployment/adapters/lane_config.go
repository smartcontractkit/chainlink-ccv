package adapters

import (
	mcmstypes "github.com/smartcontractkit/mcms/types"

	"github.com/smartcontractkit/chainlink-deployments-framework/chain"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"
)

// LaneConfigInput is the per-chain input for configuring lanes to/from remote chains.
// The adapter resolves local contract addresses (OnRamp, OffRamp, Router, FeeQuoter)
// from ExistingAddresses; callers do not need to supply them explicitly.
type LaneConfigInput struct {
	// ChainSelector is the local chain being configured.
	ChainSelector uint64
	// UseTestRouter selects the TestRouter instead of the production Router.
	UseTestRouter bool
	// ExistingAddresses are the deployed addresses on this chain, used by the
	// adapter to resolve OnRamp, OffRamp, Router, FeeQuoter, etc.
	ExistingAddresses []datastore.AddressRef
	// RemoteChains maps remote chain selector → lane config for that remote chain.
	RemoteChains map[uint64]RemoteLaneConfig
}

// RemoteLaneConfig describes how the local chain should be configured for a
// specific remote chain. Nil pointer fields fall back to adapter defaults.
type RemoteLaneConfig struct {
	// AllowTrafficFrom enables/disables inbound traffic from this remote chain.
	// Nil uses the adapter default (typically true).
	AllowTrafficFrom *bool
	// ExecutorQualifier identifies the executor on the local chain for traffic
	// from this remote chain. Empty uses the adapter default.
	ExecutorQualifier string
	// InboundCCVQualifiers are committee verifier qualifiers on the local chain
	// used to verify inbound traffic from this remote chain.
	InboundCCVQualifiers []string
	// OutboundCCVQualifiers are committee verifier qualifiers on the local chain
	// used to verify outbound traffic to this remote chain.
	OutboundCCVQualifiers []string
	// BaseExecutionGasCost overrides the default base execution gas cost.
	BaseExecutionGasCost *uint32
	// TokenReceiverAllowed overrides whether token receivers are allowed.
	TokenReceiverAllowed *bool
	// MessageNetworkFeeUSDCents overrides the message network fee.
	MessageNetworkFeeUSDCents *uint16
	// TokenNetworkFeeUSDCents overrides the token network fee.
	TokenNetworkFeeUSDCents *uint16
	// FamilyExtras carries chain-family-specific configuration (e.g. FeeQuoter
	// overrides, executor dest chain config) that the adapter interprets.
	FamilyExtras map[string]any
}

// LaneConfigOutput is the output of a lane configuration sequence.
type LaneConfigOutput struct {
	// Addresses are any newly registered addresses.
	Addresses []datastore.AddressRef
	// BatchOps are MCMS batch operations for proposals. Empty in deployer-key mode.
	BatchOps []mcmstypes.BatchOperation
}

// LaneConfigAdapter handles onchain lane configuration on a single chain.
// Implementations are chain-family-specific and registered via Registry.
//
// The adapter's ConfigureLane sequence is expected to be idempotent: re-running
// for an already-configured lane reconciles any drifted config rather than
// creating duplicate state.
type LaneConfigAdapter interface {
	// ConfigureLane returns the per-family sequence that configures lanes on a
	// single chain for traffic to/from the specified remote chains.
	ConfigureLane() *operations.Sequence[LaneConfigInput, LaneConfigOutput, chain.BlockChains]
}
