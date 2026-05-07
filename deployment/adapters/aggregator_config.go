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

// AggregatorConfigAdapter provides chain-family-specific offchain logic for aggregator config:
// resolving verifier addresses from the datastore without any onchain reads.
type AggregatorConfigAdapter interface {
	// ResolveVerifierAddress returns the verifier contract address for the given chain and qualifier using the datastore.
	ResolveVerifierAddress(ds datastore.DataStore, chainSelector uint64, qualifier string) (string, error)
	// GetDeployedChains returns all destination chain selectors for which a committee verifier
	// with the given qualifier is recorded in the datastore. The EVM implementation lives in
	// chainlink-ccip/chains/evm and is registered via adapters.Registry at process startup.
	// Used by the registry to enumerate all dest chains that must be updated when committee
	// membership changes, without requiring an exhaustive onchain scan.
	GetDeployedChains(ds datastore.DataStore, qualifier string) []uint64
}
