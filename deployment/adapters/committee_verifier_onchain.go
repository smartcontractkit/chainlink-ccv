package adapters

import (
	"context"

	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
)

// SignatureConfigChange describes an update to a CommitteeVerifier's signature configs.
type SignatureConfigChange struct {
	// RemovedSourceChainSelectors are source chains whose configs should be cleared.
	// Leave nil when only updating thresholds or signers without removing any chain.
	RemovedSourceChainSelectors []uint64
	// NewConfigs are the full desired configs to apply. Each replaces the existing
	// config for its SourceChainSelector.
	NewConfigs []SignatureConfig
}

// CommitteeVerifierOnchainAdapter handles all onchain interactions with the CommitteeVerifier
// contract. Implementations are chain-family-specific and registered via Registry.
type CommitteeVerifierOnchainAdapter interface {
	// ScanCommitteeStates reads all CommitteeVerifier contracts on chainSelector from the
	// deployment environment and returns their current onchain state.
	ScanCommitteeStates(ctx context.Context, env deployment.Environment, chainSelector uint64) ([]*CommitteeState, error)

	// ApplySignatureConfigs applies the given change to the CommitteeVerifier at
	// destChainSelector for the given committee qualifier. In deployer-key mode it
	// submits the transaction directly and blocks until mined.
	ApplySignatureConfigs(
		ctx context.Context,
		env deployment.Environment,
		destChainSelector uint64,
		qualifier string,
		change SignatureConfigChange,
	) error

	// SetAllowedFinalityConfig sets the allowed-finality config on the CommitteeVerifier
	// at chainSelector for the committee qualifier. Finality is passed as primitives
	// (waitForFinality / waitForSafe / blockDepth) so this package stays free of
	// chain-family finality encodings; the adapter encodes them for its family. In
	// deployer-key mode it submits the transaction directly and blocks until mined.
	SetAllowedFinalityConfig(
		ctx context.Context,
		env deployment.Environment,
		chainSelector uint64,
		qualifier string,
		waitForFinality bool,
		waitForSafe bool,
		blockDepth uint16,
	) error

	// ApplyAllowlistUpdates updates the per-destination-chain sender allowlist on the
	// CommitteeVerifier at chainSelector for the committee qualifier. The allowlist is
	// keyed by destChainSelector; added/removed senders are hex address strings the
	// adapter interprets for its family. In deployer-key mode it submits the
	// transaction directly and blocks until mined.
	ApplyAllowlistUpdates(
		ctx context.Context,
		env deployment.Environment,
		chainSelector uint64,
		qualifier string,
		destChainSelector uint64,
		allowlistEnabled bool,
		addedSenders []string,
		removedSenders []string,
	) error
}
