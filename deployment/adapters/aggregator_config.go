package adapters

import (
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
)

type CommitteeState struct {
	Qualifier        string
	ChainSelector    uint64
	Address          string
	SignatureConfigs []SignatureConfig
}

type SignatureConfig struct {
	SourceChainSelector uint64
	Signers             []string
	Threshold           uint8
}

// AggregatorConfigAdapter provides chain-family-specific offchain logic for populating
// the aggregator config.
//
// The aggregator's committee configuration is organized to include the following:
// * quorum configs for each source chain selector, which includes the source verifier address,
// * destination verifier addresses for each destination chain selector.
//
// Note that a source chain selector can also be a destination chain selector, i.e. the selectors
// refer to the same chain.
//
// Most chains will resolve the same address in the quorum configs and the destination verifier addresses.
// However, some chains may not.
type AggregatorConfigAdapter interface {
	// ResolveSourceVerifierAddress returns the source verifier contract address for the given chain and qualifier using the datastore.
	// This is used to populate the quorum configs.
	// If the chain family doesn't need any special logic, this can return the same value as ResolveDestinationVerifierAddress.
	ResolveSourceVerifierAddress(ds datastore.DataStore, chainSelector uint64, qualifier string) (string, error)

	// ResolveDestinationVerifierAddress returns the destination verifier contract address for the given chain and qualifier using the datastore.
	// This is used to populate the destination verifier addresses.
	// If the chain family doesn't need any special logic, this can return the same value as ResolveSourceVerifierAddress.
	ResolveDestinationVerifierAddress(ds datastore.DataStore, chainSelector uint64, qualifier string) (string, error)

	// GetDeployedChains returns all destination chain selectors for which a committee verifier
	// with the given qualifier is recorded in the datastore. The EVM implementation lives in
	// chainlink-ccip/chains/evm and is registered via adapters.Registry at process startup.
	// Used by the registry to enumerate all dest chains that must be updated when committee
	// membership changes, without requiring an exhaustive onchain scan.
	GetDeployedChains(ds datastore.DataStore, qualifier string) []uint64
}
