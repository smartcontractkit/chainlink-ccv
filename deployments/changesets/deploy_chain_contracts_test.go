package changesets_test

import (
	"testing"

	"github.com/Masterminds/semver/v3"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/create2_factory"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/testsetup"
	contract_utils "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/utils/operations/contract"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_2_0/operations/router"
	cs_core "github.com/smartcontractkit/chainlink-ccip/deployment/utils/changesets"
	"github.com/smartcontractkit/chainlink-ccip/deployment/utils/mcms"
	cldfevm "github.com/smartcontractkit/chainlink-deployments-framework/chain/evm"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"

	"github.com/smartcontractkit/chainlink-ccv/deployments/changesets"
	"github.com/smartcontractkit/chainlink-ccv/deployments/testutils"
)

func TestDeployChainContractsFromTopology_VerifyPreconditions(t *testing.T) {
	selector := chainsel.TEST_90000001.Selector
	env := newTestEnvironment(t, []uint64{selector})

	tests := []struct {
		name        string
		cfg         cs_core.WithMCMS[changesets.DeployChainContractsFromTopologyCfg]
		expectedErr string
	}{
		{
			name: "rejects nil topology",
			cfg: cs_core.WithMCMS[changesets.DeployChainContractsFromTopologyCfg]{
				MCMS: mcms.Input{},
				Cfg: changesets.DeployChainContractsFromTopologyCfg{
					Topology:       nil,
					ChainSelector:  selector,
					CREATE2Factory: common.HexToAddress("0x01"),
				},
			},
			expectedErr: "topology is required",
		},
		{
			name: "rejects topology with no committees",
			cfg: cs_core.WithMCMS[changesets.DeployChainContractsFromTopologyCfg]{
				MCMS: mcms.Input{},
				Cfg: changesets.DeployChainContractsFromTopologyCfg{
					Topology:       newTestTopology(WithCommittees(nil)),
					ChainSelector:  selector,
					CREATE2Factory: common.HexToAddress("0x01"),
				},
			},
			expectedErr: "no committees defined in topology",
		},
		{
			name: "rejects chain selector not in environment",
			cfg: cs_core.WithMCMS[changesets.DeployChainContractsFromTopologyCfg]{
				MCMS: mcms.Input{},
				Cfg: changesets.DeployChainContractsFromTopologyCfg{
					Topology:       newTestTopology(),
					ChainSelector:  999999999,
					CREATE2Factory: common.HexToAddress("0x01"),
				},
			},
			expectedErr: "chain selector 999999999 is not available in environment",
		},
		{
			name: "rejects zero CREATE2Factory address",
			cfg: cs_core.WithMCMS[changesets.DeployChainContractsFromTopologyCfg]{
				MCMS: mcms.Input{},
				Cfg: changesets.DeployChainContractsFromTopologyCfg{
					Topology:       newTestTopology(),
					ChainSelector:  selector,
					CREATE2Factory: common.Address{},
				},
			},
			expectedErr: "CREATE2Factory address is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mcmsRegistry := cs_core.GetRegistry()
			err := changesets.DeployChainContractsFromTopology(mcmsRegistry).VerifyPreconditions(env, tt.cfg)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedErr)
		})
	}
}

func TestDeployChainContractsFromTopology_TestRouterDeployment(t *testing.T) {
	tests := []struct {
		name             string
		deployTestRouter bool
		expectTestRouter bool
	}{
		{
			name:             "deploys test router when enabled",
			deployTestRouter: true,
			expectTestRouter: true,
		},
		{
			name:             "does not deploy test router when disabled",
			deployTestRouter: false,
			expectTestRouter: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			selector := chainsel.TEST_90000001.Selector
			env, evmChains := testutils.NewSimulatedEVMEnvironment(t, []uint64{selector})

			create2FactoryAddr := deployCreate2Factory(t, env, evmChains[0], selector)

			basicParams := testsetup.CreateBasicContractParams()
			mcmsRegistry := cs_core.GetRegistry()
			out, err := changesets.DeployChainContractsFromTopology(mcmsRegistry).Apply(
				env,
				cs_core.WithMCMS[changesets.DeployChainContractsFromTopologyCfg]{
					MCMS: mcms.Input{},
					Cfg: changesets.DeployChainContractsFromTopologyCfg{
						Topology:         newTestTopology(),
						DeployTestRouter: tt.deployTestRouter,
						ChainSelector:    selector,
						CREATE2Factory:   create2FactoryAddr,
						RMNRemote:        basicParams.RMNRemote,
						OffRamp:          basicParams.OffRamp,
						OnRamp:           basicParams.OnRamp,
						FeeQuoter:        basicParams.FeeQuoter,
						Executors:        basicParams.Executors,
					},
				},
			)
			require.NoError(t, err, "Failed to apply DeployChainContractsFromTopology changeset")

			newAddrs, err := out.DataStore.Addresses().Fetch()
			require.NoError(t, err, "Failed to fetch addresses from datastore")

			foundTestRouter := false
			for _, addr := range newAddrs {
				if addr.Type == datastore.ContractType(router.TestRouterContractType) {
					require.NotEqual(t, common.Address{}, common.HexToAddress(addr.Address), "Test Router address should be set")
					require.Equal(t, selector, addr.ChainSelector, "Test Router should be for the correct chain")
					foundTestRouter = true

					break
				}
			}
			require.Equal(t, tt.expectTestRouter, foundTestRouter, "Test Router presence mismatch")
		})
	}
}

func deployCreate2Factory(t *testing.T, env deployment.Environment, chain cldfevm.Chain, selector uint64) common.Address {
	t.Helper()

	ref, err := contract_utils.MaybeDeployContract(
		env.OperationsBundle,
		create2_factory.Deploy,
		chain,
		contract_utils.DeployInput[create2_factory.ConstructorArgs]{
			TypeAndVersion: deployment.NewTypeAndVersion(create2_factory.ContractType, *semver.MustParse("1.7.0")),
			ChainSelector:  selector,
			Args: create2_factory.ConstructorArgs{
				AllowList: []common.Address{chain.DeployerKey.From},
			},
		},
		nil,
	)
	require.NoError(t, err, "Failed to deploy CREATE2Factory")

	return common.HexToAddress(ref.Address)
}
