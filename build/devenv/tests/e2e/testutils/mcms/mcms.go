package mcms

import (
	"math"
	"math/big"
	"testing"

	"github.com/smartcontractkit/chainlink-ccip/deployment/deploy"
	"github.com/smartcontractkit/chainlink-ccip/deployment/testhelpers"
	cciputils "github.com/smartcontractkit/chainlink-ccip/deployment/utils"
	"github.com/smartcontractkit/chainlink-ccip/deployment/utils/datastore"
	"github.com/smartcontractkit/chainlink-ccip/deployment/utils/mcms"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/testutils/dsutils"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/mcms/types"
	"github.com/stretchr/testify/require"
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
					TimelockMinDelay: big.NewInt(0),
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
