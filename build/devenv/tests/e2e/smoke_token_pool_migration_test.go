package e2e

import (
	"testing"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/stretchr/testify/require"

	cciputils "github.com/smartcontractkit/chainlink-ccip/deployment/utils"
	ccv "github.com/smartcontractkit/chainlink-ccv/build/devenv"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/testutils/chains/evm"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/testutils/mcms"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/testutils/tokenpool"
	"github.com/smartcontractkit/chainlink-ccv/protocol"

	_ "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_0_0/adapters"
	_ "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_5_1/adapters"
	_ "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_6_1/adapters"
	_ "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/adapters"
)

func TestE2ESmoke_TokenPoolMigrationEVM2EVM(t *testing.T) {
	const (
		QualLockReleaseAV1 = "EVM_POOL_LNR_A_V1"
		QualLockReleaseBV1 = "EVM_POOL_LNR_B_V1"
		QualLockReleaseAV2 = "EVM_POOL_LNR_A_V2"
		QualLockReleaseBV2 = "EVM_POOL_LNR_B_V2"
		QualBurnMintAV1    = "EVM_POOL_BNM_A_V1"
		QualBurnMintBV1    = "EVM_POOL_BNM_B_V1"
		QualBurnMintAV2    = "EVM_POOL_BNM_A_V2"
		QualBurnMintBV2    = "EVM_POOL_BNM_B_V2"
		TokensToSend       = 1
	)

	lib, err := ccv.NewLibFromCCVEnv(&ccv.Plog, GetSmokeTestConfig(), chainsel.FamilyEVM)
	require.NoError(t, err)

	chains, err := lib.Chains(ccv.Plog.WithContext(t.Context()))
	require.NoError(t, err)

	env, err := lib.CLDFEnvironment()
	require.NoError(t, err)
	require.NotNil(t, env)
	for sel := range env.BlockChains.All() {
		mcms.Deploy(t, env, sel, []string{cciputils.CLLQualifier})
	}

	require.GreaterOrEqual(t, len(chains), 2, "expected at least 2 EVM chains for this test in the environment")
	selA := chains[0].ChainSelector()
	selB := chains[1].ChainSelector()
	fCfg := protocol.Finality(0)

	t.Run("BurnMintTokenPool Migration", func(t *testing.T) {
		// Part 1: deploy legacy pools and ensure token transfers work
		poolAV1 := evm.DeployBurnMintTokenPoolV151(t, env, selA, QualBurnMintAV1)
		poolBV1 := evm.DeployBurnMintTokenPoolV161(t, env, selB, QualBurnMintBV1)
		tokenpool.ConnectAll(t, env, cciputils.Version_1_6_1, []tokenpool.Connection{
			{
				PoolA: poolAV1,
				PoolB: poolBV1,
				RateLimits: tokenpool.BidirectionalRateLimitPair{
					AB: tokenpool.DefaultOutboundRateLimit(),
					BA: tokenpool.DefaultOutboundRateLimit(),
				},
			},
		})
		require.NotEmpty(t, poolAV1.Address())
		require.NotEmpty(t, poolBV1.Address())
		require.NotEmpty(t, poolAV1.Token())
		require.NotEmpty(t, poolBV1.Token())
		tokenpool.RunBidirectionalTokenTransfer(t, lib, poolAV1, poolBV1, TokensToSend, fCfg, "pre-migration")

		// Part 2: migrate and ensure token transfers still work
		poolAV2 := evm.DeployTokenPoolV200(t, env, cciputils.BurnMintTokenPool.String(), QualBurnMintAV2, poolAV1, tokenpool.DefaultFinalityConfig())
		poolBV2 := evm.DeployTokenPoolV200(t, env, cciputils.BurnMintTokenPool.String(), QualBurnMintBV2, poolBV1, tokenpool.DefaultFinalityConfig())
		tokenpool.ConnectAll(t, env, cciputils.Version_2_0_0, []tokenpool.Connection{
			{
				PoolA: poolAV2,
				PoolB: poolBV2,
				RateLimits: tokenpool.BidirectionalRateLimitPair{
					AB: tokenpool.DefaultOutboundRateLimit(),
					BA: tokenpool.DefaultOutboundRateLimit(),
				},
			},
		})
		require.NotEqual(t, poolAV1.Address(), poolAV2.Address())
		require.NotEqual(t, poolBV1.Address(), poolBV2.Address())
		require.Equal(t, poolAV1.Token(), poolAV2.Token())
		require.Equal(t, poolBV1.Token(), poolBV2.Token())
		tokenpool.RunBidirectionalTokenTransfer(t, lib, poolAV2, poolBV2, TokensToSend, fCfg, "post-migration")
	})

	t.Run("LockReleaseTokenPool Migration", func(t *testing.T) {
		// Part 1: deploy legacy pools and ensure token transfers work
		poolAV1 := evm.DeployLockReleaseTokenPoolV161(t, env, selA, QualLockReleaseAV1)
		poolBV1 := evm.DeployLockReleaseTokenPoolV161(t, env, selB, QualLockReleaseBV1)
		evm.TransferTokens(t, env, poolAV1.Selector(), poolAV1.Token(), poolAV1.Address(), 100)
		evm.TransferTokens(t, env, poolBV1.Selector(), poolBV1.Token(), poolBV1.Address(), 100)
		tokenpool.ConnectAll(t, env, cciputils.Version_1_6_1, []tokenpool.Connection{
			{
				PoolA: poolAV1,
				PoolB: poolBV1,
				RateLimits: tokenpool.BidirectionalRateLimitPair{
					AB: tokenpool.DefaultOutboundRateLimit(),
					BA: tokenpool.DefaultOutboundRateLimit(),
				},
			},
		})
		require.NotEmpty(t, poolAV1.Address())
		require.NotEmpty(t, poolBV1.Address())
		require.NotEmpty(t, poolAV1.Token())
		require.NotEmpty(t, poolBV1.Token())
		tokenpool.RunBidirectionalTokenTransfer(t, lib, poolAV1, poolBV1, TokensToSend, fCfg, "pre-migration")

		// Part 2: migrate and ensure token transfers still work
		poolAV2 := evm.DeployTokenPoolV200(t, env, cciputils.LockReleaseTokenPool.String(), QualLockReleaseAV2, poolAV1, tokenpool.DefaultFinalityConfig())
		poolBV2 := evm.DeployTokenPoolV200(t, env, cciputils.LockReleaseTokenPool.String(), QualLockReleaseBV2, poolBV1, tokenpool.DefaultFinalityConfig())
		tokenpool.ConnectAll(t, env, cciputils.Version_2_0_0, []tokenpool.Connection{
			{
				PoolA: poolAV2,
				PoolB: poolBV2,
				RateLimits: tokenpool.BidirectionalRateLimitPair{
					AB: tokenpool.DefaultOutboundRateLimit(),
					BA: tokenpool.DefaultOutboundRateLimit(),
				},
			},
		})
		require.NotEqual(t, poolAV1.Address(), poolAV2.Address())
		require.NotEqual(t, poolBV1.Address(), poolBV2.Address())
		require.Equal(t, poolAV1.Token(), poolAV2.Token())
		require.Equal(t, poolBV1.Token(), poolBV2.Token())
		tokenpool.RunBidirectionalTokenTransfer(t, lib, poolAV2, poolBV2, TokensToSend, fCfg, "post-migration")
	})
}
