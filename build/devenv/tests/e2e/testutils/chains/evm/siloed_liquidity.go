package evm

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"

	erc20_ops "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_0_0/operations/erc20"
	siloed_ops_v161 "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_6_1/operations/siloed_lock_release_token_pool"
	"github.com/smartcontractkit/chainlink-ccip/deployment/testhelpers"
	"github.com/smartcontractkit/chainlink-ccip/deployment/tokens"
	"github.com/smartcontractkit/chainlink-ccip/deployment/utils/changesets"
	"github.com/smartcontractkit/chainlink-deployments-framework/chain/evm/operations/contract"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	cldf_ops "github.com/smartcontractkit/chainlink-deployments-framework/operations"
	mcms_types "github.com/smartcontractkit/mcms/types"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/testutils/mcms"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/testutils/tokenpool"
)

// ProvideSiloedLiquidity designates remoteSel as a siloed chain on a v1.6.1
// SiloedLockReleaseTokenPool and funds that silo with amount whole tokens.
//
// Unlike the plain LockReleaseTokenPool, a siloed pool tracks liquidity in internal accounting, so
// transferring tokens straight to the pool address does not make them available to releaseOrMint -
// the liquidity has to come in through provideSiloedLiquidity.
//
// Two callers are involved. updateSiloDesignations is onlyOwner, and the pool is owned by the
// timelock once TokenExpansion has transferred authority, so it goes out as a timelock proposal;
// it marks remoteSel siloed and names the deployer as that silo's rebalancer in one call.
// provideSiloedLiquidity is then rebalancer-gated, so the deployer can approve and fund directly.
func ProvideSiloedLiquidity(
	t *testing.T,
	env *deployment.Environment,
	pool tokenpool.TokenPool,
	remoteSel uint64,
	amount int64,
) {
	t.Helper()

	chain, ok := env.BlockChains.EVMChains()[pool.Selector()]
	require.True(t, ok, "evm chain not found for selector %d", pool.Selector())

	poolAddr := common.HexToAddress(pool.Address())
	tokenAddr := common.HexToAddress(pool.Token())
	deployer := chain.DeployerKey.From
	scaled := tokens.ScaleTokenAmount(big.NewInt(amount), pool.Decimals())

	// Silo remoteSel and hand the deployer the silo rebalancer role, via the timelock.
	env.OperationsBundle = cldf_ops.NewBundle(env.OperationsBundle.GetContext, env.OperationsBundle.Logger, cldf_ops.NewMemoryReporter())
	designationsReport, err := cldf_ops.ExecuteOperation(env.OperationsBundle, siloed_ops_v161.UpdateSiloDesignations, chain, contract.FunctionInput[siloed_ops_v161.UpdateSiloDesignationsArgs]{
		ChainSelector: pool.Selector(),
		Address:       poolAddr,
		Args: siloed_ops_v161.UpdateSiloDesignationsArgs{
			Removes: []uint64{},
			Adds: []siloed_ops_v161.SiloConfigUpdate{
				{RemoteChainSelector: remoteSel, Rebalancer: deployer},
			},
		},
	})
	require.NoError(t, err, "build updateSiloDesignations for pool %s on chain %d", pool.Address(), pool.Selector())

	batchOp, err := contract.NewBatchOperationFromWrites([]contract.WriteOutput{designationsReport.Output})
	require.NoError(t, err, "build batch operation for updateSiloDesignations")

	out, err := changesets.NewOutputBuilder(*env, changesets.GetRegistry()).
		WithBatchOps([]mcms_types.BatchOperation{batchOp}).
		Build(mcms.DefaultInput("Silo chain " + pool.Address()))
	require.NoError(t, err, "build timelock proposal for updateSiloDesignations")
	testhelpers.ProcessTimelockProposals(t, *env, out.MCMSTimelockProposals, true)

	isSiloedReport, err := cldf_ops.ExecuteOperation(env.OperationsBundle, siloed_ops_v161.IsSiloed, chain, contract.FunctionInput[uint64]{
		ChainSelector: pool.Selector(),
		Address:       poolAddr,
		Args:          remoteSel,
	})
	require.NoError(t, err, "read isSiloed for chain %d", remoteSel)
	require.True(t, isSiloedReport.Output, "chain %d should be siloed on pool %s after updateSiloDesignations", remoteSel, pool.Address())

	// Deployer is now the silo rebalancer, so it can fund the silo directly.
	_, err = cldf_ops.ExecuteOperation(env.OperationsBundle, erc20_ops.Approve, chain, contract.FunctionInput[erc20_ops.ApproveArgs]{
		ChainSelector: pool.Selector(),
		Address:       tokenAddr,
		Args:          erc20_ops.ApproveArgs{Spender: poolAddr, Value: scaled},
	})
	require.NoError(t, err, "approve pool %s to pull %d tokens", pool.Address(), amount)

	_, err = cldf_ops.ExecuteOperation(env.OperationsBundle, siloed_ops_v161.ProvideSiloedLiquidity, chain, contract.FunctionInput[siloed_ops_v161.ProvideSiloedLiquidityArgs]{
		ChainSelector: pool.Selector(),
		Address:       poolAddr,
		Args: siloed_ops_v161.ProvideSiloedLiquidityArgs{
			RemoteChainSelector: remoteSel,
			Amount:              scaled,
		},
	})
	require.NoError(t, err, "provide siloed liquidity for chain %d on pool %s", remoteSel, pool.Address())

	availableReport, err := cldf_ops.ExecuteOperation(env.OperationsBundle, siloed_ops_v161.GetAvailableTokens, chain, contract.FunctionInput[uint64]{
		ChainSelector: pool.Selector(),
		Address:       poolAddr,
		Args:          remoteSel,
	})
	require.NoError(t, err, "read available tokens for chain %d", remoteSel)
	require.Equal(t, 0, availableReport.Output.Cmp(scaled),
		"silo for chain %d should hold %s, got %s", remoteSel, scaled, availableReport.Output)
}
