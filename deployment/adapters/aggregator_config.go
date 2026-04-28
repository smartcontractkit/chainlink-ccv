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
}
