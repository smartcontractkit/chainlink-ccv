package evm

import (
	"context"
	"fmt"

	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"

	"github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
)

type evmAggregatorConfigAdapter struct{}

// ScanCommitteeStates queries the EVM chain for all deployed committee verifier contracts
// and returns their on-chain state (signers, thresholds, etc.) for the aggregator config.
func (a *evmAggregatorConfigAdapter) ScanCommitteeStates(ctx context.Context, env deployment.Environment, chainSelector uint64) ([]*adapters.CommitteeState, error) {
	// TODO: call EVM committee verifier contracts on the given chain to enumerate
	// deployed committee states and return their signer/threshold configs.
	return nil, fmt.Errorf("EVM aggregator config adapter not yet implemented for chain %d", chainSelector)
}

// ResolveVerifierAddress returns the committee verifier contract address stored in the
// EVM-specific datastore entry for the given chain and qualifier.
func (a *evmAggregatorConfigAdapter) ResolveVerifierAddress(ds datastore.DataStore, chainSelector uint64, qualifier string) (string, error) {
	// TODO: read the verifier address from the EVM datastore entry for this
	// chainSelector and qualifier.
	return "", fmt.Errorf("EVM aggregator config adapter not yet implemented for chain %d", chainSelector)
}
