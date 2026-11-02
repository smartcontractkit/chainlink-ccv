package mcms

import (
	"math"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccip/deployment/deploy"
	"github.com/smartcontractkit/chainlink-ccip/deployment/testhelpers"
	cciputils "github.com/smartcontractkit/chainlink-ccip/deployment/utils"
	"github.com/smartcontractkit/chainlink-ccip/deployment/utils/changesets"
	"github.com/smartcontractkit/chainlink-ccip/deployment/utils/datastore"
	"github.com/smartcontractkit/chainlink-ccip/deployment/utils/mcms"
	evm_contract "github.com/smartcontractkit/chainlink-deployments-framework/chain/evm/operations/contract"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/mcms/types"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/testutils/dsutils"
)

var registry = deploy.GetRegistry()

func DefaultInput(desc string) mcms.Input {
	return mcms.Input{
		OverridePreviousRoot: false,
		ValidUntil:           math.MaxUint32,
		TimelockDelay:        types.MustParseDuration("0s"),
		TimelockAction:       types.TimelockActionSchedule,
		Qualifier:            cciputils.CLLQualifier,
		Description:          desc,
	}
}

// ExecuteWrites proposes the writes the deployer did not execute itself (it is not an allowed
// caller) through the CLL timelock and executes the proposal. Writes already executed are skipped,
// so callers can pass every write an operation returned. All writes must target the same chain.
func ExecuteWrites(t *testing.T, env *deployment.Environment, desc string, writes []evm_contract.WriteOutput) {
	t.Helper()

	batchOp, err := evm_contract.NewBatchOperationFromWrites(writes)
	require.NoError(t, err)
	if len(batchOp.Transactions) == 0 {
		return
	}
	out, err := changesets.NewOutputBuilder(*env, changesets.GetRegistry()).
		WithBatchOps([]types.BatchOperation{batchOp}).
		Build(DefaultInput(desc))
	require.NoError(t, err)
	testhelpers.ProcessTimelockProposals(t, *env, out.MCMSTimelockProposals, true)
}

func Deploy(t *testing.T, env *deployment.Environment, selector uint64, qualifiers []string) {
	t.Helper()

	ref := datastore.GetAddressRef(
		env.DataStore.Addresses().Filter(),
		selector,
		cciputils.RBACTimelock,
		cciputils.Version_1_0_0,
		cciputils.CLLQualifier,
	)
	if ref.Address != "" {
		return
	}

	finalize := deploy.FinalizeDeployMCMS(registry, nil)
	deployer := deploy.DeployMCMS(registry, nil)
	for _, qualifier := range qualifiers {
		cfg := deploy.MCMSDeploymentConfig{
			AdapterVersion: deploy.MCMSVersion,
			MCMS:           testhelpers.MCMSInputForQualifier(qualifier),
			Chains: map[uint64]deploy.MCMSDeploymentConfigPerChain{
				selector: {
					Canceller:        testhelpers.SingleGroupMCMS(),
					Bypasser:         testhelpers.SingleGroupMCMS(),
					Proposer:         testhelpers.SingleGroupMCMS(),
					TimelockMinDelay: big.NewInt(1),
					Qualifier:        new(qualifier),
				},
			},
		}

		output1, err := deployer.Apply(*env, cfg)
		require.NoError(t, err)
		testhelpers.ProcessTimelockProposals(t, *env, output1.MCMSTimelockProposals, true)
		dsutils.MergeDataStore(t, env, output1.DataStore.Seal())

		output2, err := finalize.Apply(*env, cfg)
		require.NoError(t, err)
		testhelpers.ProcessTimelockProposals(t, *env, output2.MCMSTimelockProposals, true)
		dsutils.MergeDataStore(t, env, output2.DataStore.Seal())
	}
}
