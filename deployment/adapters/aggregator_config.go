package adapters

import (
	"context"

	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
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

// AggregatorConfigAdapter provides chain-family-specific logic to discover committee state
// and resolve verifier addresses for aggregator offchain config.
type AggregatorConfigAdapter interface {
	// ScanCommitteeStates returns committee states for the given chain from the deployment env.
	ScanCommitteeStates(ctx context.Context, env deployment.Environment, chainSelector uint64) ([]*CommitteeState, error)
	// ResolveVerifierAddress returns the verifier contract address for the given chain and qualifier using the datastore.
	ResolveVerifierAddress(ds datastore.DataStore, chainSelector uint64, qualifier string) (string, error)
}
