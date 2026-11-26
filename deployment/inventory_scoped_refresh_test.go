package deployment

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
	"github.com/smartcontractkit/chainlink-ccv/deployment/inventory"
)

const (
	scopedCantonSelector   = uint64(2308837218439511688)
	scopedEthereumSelector = uint64(5009297550715157269)
	scopedSigner           = "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
)

// scopedScanAdapter serves per-chain scans and errors; no discovery, so scoped refreshes only
// touch the chains they are given.
type scopedScanAdapter struct {
	adapters.CommitteeVerifierOnchainAdapter
	states map[uint64][]*adapters.CommitteeState
	errs   map[uint64]error
}

func (s *scopedScanAdapter) ScanCommitteeStates(_ context.Context, _ deployment.Environment, chain uint64) ([]*adapters.CommitteeState, error) {
	if s.errs[chain] != nil {
		return nil, s.errs[chain]
	}
	return s.states[chain], nil
}

// A scoped refresh must not clear another chain's failure alert from the persisted metadata:
// the alert tracks the chain's refresh record, not whether this run scanned it.
func TestRefreshInventoryChainsKeepsUnscannedFailureAlerts(t *testing.T) {
	cantonAdapter := &scopedScanAdapter{states: map[uint64][]*adapters.CommitteeState{
		scopedCantonSelector: {{
			Qualifier: "default", ChainSelector: scopedCantonSelector, Address: "canton-cv",
			SignatureConfigs: []adapters.SignatureConfig{{
				SourceChainSelector: scopedEthereumSelector, Threshold: 1, Signers: []string{scopedSigner},
			}},
		}},
	}}
	adapters.GetCommitteeVerifierOnchainRegistry().Register(chainsel.FamilyCanton, cantonAdapter)

	ds := datastore.NewMemoryDataStore()
	require.NoError(t, SaveNOPSigners(ds, map[string]map[string]string{"nop-a": {"evm": scopedSigner}}))
	require.NoError(t, SaveJDNodes(ds, map[string]JDNode{"node-a": {Name: "nop-a", CSAKey: "csa-a"}}))
	require.NoError(t, SaveAggregatorConfig(ds, "agg-1", &model.Committee{
		QuorumConfigs: map[model.SourceSelector]*model.QuorumConfig{
			"5009297550715157269": {Signers: []model.Signer{{Address: scopedSigner}}, Threshold: 1},
		},
		DestinationVerifiers: map[model.DestinationSelector]string{"2308837218439511688": "canton-cv"},
	}))
	require.NoError(t, SaveAggregatorQualifier(ds, "agg-1", "default"))
	env := deployment.Environment{DataStore: ds.Seal(), GetContext: t.Context}

	require.NoError(t, RefreshInventoryChains(env, ds, []uint64{scopedCantonSelector}))
	cantonAdapter.errs = map[uint64]error{scopedCantonSelector: errors.New("ledger unavailable")}
	require.NoError(t, RefreshInventoryChains(env, ds, []uint64{scopedCantonSelector}))
	failure := inventory.Issue{Kind: inventory.IssueOnchainReadFailed, Subject: "canton-mainnet", Detail: "ledger unavailable"}
	assert.Contains(t, storedInventory(t, ds).Issues, failure)

	// An EVM-only scoped refresh: Canton is not scanned, its failure alert must survive in the
	// saved JSON, alongside its retained committee and refresh record.
	adapters.GetCommitteeVerifierOnchainRegistry().Register(chainsel.FamilyEVM, &scopedScanAdapter{
		states: map[uint64][]*adapters.CommitteeState{
			scopedEthereumSelector: {{
				Qualifier: "default", ChainSelector: scopedEthereumSelector, Address: "0x0000000000000000000000000000000000000002",
				SignatureConfigs: []adapters.SignatureConfig{{
					SourceChainSelector: scopedCantonSelector, Threshold: 1, Signers: []string{scopedSigner},
				}},
			}},
		},
	})
	require.NoError(t, RefreshInventoryChains(env, ds, []uint64{scopedEthereumSelector}))

	stored := storedInventory(t, ds)
	assert.Contains(t, stored.Issues, failure, "an unscanned chain keeps its read-failure alert")
	var cantonRows int
	for _, c := range stored.Committees {
		for _, d := range c.VerifierDeployments {
			if c.Source == inventory.SourceOnchain && d.Chain == inventory.ChainSelector(scopedCantonSelector) {
				cantonRows++
			}
		}
	}
	assert.Equal(t, 1, cantonRows, "the unscanned chain's committee is retained")
	var cantonRefresh *inventory.OnchainRefresh
	for i := range stored.Refreshes {
		if stored.Refreshes[i].Chain == inventory.ChainSelector(scopedCantonSelector) {
			cantonRefresh = &stored.Refreshes[i]
		}
	}
	require.NotNil(t, cantonRefresh)
	assert.Equal(t, "ledger unavailable", cantonRefresh.LastError)
}
