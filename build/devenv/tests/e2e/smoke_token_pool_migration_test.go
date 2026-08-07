package e2e

import (
	"testing"

	"github.com/stretchr/testify/require"

	chainsel "github.com/smartcontractkit/chain-selectors"
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
	if testing.Short() {
		t.Skip("skipping e2e test in short mode; requires a running devenv environment")
	}
	const (
		QualLockReleaseAV1      = "EVM_POOL_LNR_A_V1"
		QualLockReleaseBV1      = "EVM_POOL_LNR_B_V1"
		QualLockReleaseAV2      = "EVM_POOL_LNR_A_V2"
		QualLockReleaseBV2      = "EVM_POOL_LNR_B_V2"
		QualBurnMintAV1         = "EVM_POOL_BNM_A_V1"
		QualBurnMintBV1         = "EVM_POOL_BNM_B_V1"
		QualBurnMintAV2         = "EVM_POOL_BNM_A_V2"
		QualBurnMintBV2         = "EVM_POOL_BNM_B_V2"
		QualBurnFromMintAV1     = "EVM_POOL_BFM_A_V1"
		QualBurnFromMintBV1     = "EVM_POOL_BFM_B_V1"
		QualBurnFromMintAV2     = "EVM_POOL_BFM_A_V2"
		QualBurnFromMintBV2     = "EVM_POOL_BFM_B_V2"
		QualBurnWithFromMintAV1 = "EVM_POOL_BWFM_A_V1"
		QualBurnWithFromMintBV1 = "EVM_POOL_BWFM_B_V1"
		QualBurnWithFromMintAV2 = "EVM_POOL_BWFM_A_V2"
		QualBurnWithFromMintBV2 = "EVM_POOL_BWFM_B_V2"
		QualSiloedAV1           = "EVM_POOL_SLNR_A_V1"
		QualSiloedBV1           = "EVM_POOL_SLNR_B_V1"
		QualSiloedAV2           = "EVM_POOL_SLNR_A_V2"
		QualSiloedBV2           = "EVM_POOL_SLNR_B_V2"
		TokensToSend            = 1
		SiloedLiquidity         = 100
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

	// BurnFromMintTokenPool is a custom burn-mint variant: it burns via burnFrom(pool, amount)
	// rather than burn(amount), relying on the max self-allowance its constructor grants.
	t.Run("BurnFromMintTokenPool Migration", func(t *testing.T) {
		// Part 1: deploy legacy pools and ensure token transfers work
		poolAV1 := evm.DeployBurnFromMintTokenPoolV161(t, env, selA, QualBurnFromMintAV1)
		poolBV1 := evm.DeployBurnFromMintTokenPoolV161(t, env, selB, QualBurnFromMintBV1)
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
		poolAV2 := evm.DeployTokenPoolV200(t, env, cciputils.BurnFromMintTokenPool.String(), QualBurnFromMintAV2, poolAV1, tokenpool.DefaultFinalityConfig())
		poolBV2 := evm.DeployTokenPoolV200(t, env, cciputils.BurnFromMintTokenPool.String(), QualBurnFromMintBV2, poolBV1, tokenpool.DefaultFinalityConfig())
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

	// BurnWithFromMintTokenPool is a custom burn-mint variant: it burns via burn(pool, amount),
	// the legacy alias for burnFrom, again relying on its constructor's max self-allowance.
	t.Run("BurnWithFromMintTokenPool Migration", func(t *testing.T) {
		// Part 1: deploy legacy pools and ensure token transfers work
		poolAV1 := evm.DeployBurnWithFromMintTokenPoolV161(t, env, selA, QualBurnWithFromMintAV1)
		poolBV1 := evm.DeployBurnWithFromMintTokenPoolV161(t, env, selB, QualBurnWithFromMintBV1)
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
		poolAV2 := evm.DeployTokenPoolV200(t, env, cciputils.BurnWithFromMintTokenPool.String(), QualBurnWithFromMintAV2, poolAV1, tokenpool.DefaultFinalityConfig())
		poolBV2 := evm.DeployTokenPoolV200(t, env, cciputils.BurnWithFromMintTokenPool.String(), QualBurnWithFromMintBV2, poolBV1, tokenpool.DefaultFinalityConfig())
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

	// SiloedLockReleaseTokenPool is a custom lock-release variant that keeps liquidity isolated per
	// remote chain. The two versions model that differently, which is what makes this migration worth
	// covering: v1.6.1 tracks each silo in internal accounting, whereas v2.0.0 holds no balance at all
	// and routes each remote chain to its own ERC20LockBox.
	t.Run("SiloedLockReleaseTokenPool Migration", func(t *testing.T) {
		// Part 1: deploy legacy pools and ensure token transfers work
		poolAV1 := evm.DeploySiloedLockReleaseTokenPoolV161(t, env, selA, QualSiloedAV1)
		poolBV1 := evm.DeploySiloedLockReleaseTokenPoolV161(t, env, selB, QualSiloedBV1)
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
		// Siloing has to come after ConnectAll: updateSiloDesignations rejects a chain that the pool
		// does not already support. A plain token transfer would not register as liquidity either,
		// since a siloed pool releases against its internal per-silo accounting.
		evm.ProvideSiloedLiquidity(t, env, poolAV1, selB, SiloedLiquidity)
		evm.ProvideSiloedLiquidity(t, env, poolBV1, selA, SiloedLiquidity)
		require.NotEmpty(t, poolAV1.Address())
		require.NotEmpty(t, poolBV1.Address())
		require.NotEmpty(t, poolAV1.Token())
		require.NotEmpty(t, poolBV1.Token())
		tokenpool.RunBidirectionalTokenTransfer(t, lib, poolAV1, poolBV1, TokensToSend, fCfg, "pre-migration")

		// Part 2: migrate and ensure token transfers still work. Each pool serves a single remote
		// chain, so one lock box group per pool covers it; the liquidity migration drains each v1.6.1
		// silo into the matching lock box.
		poolAV2 := evm.DeployTokenPoolV200(t, env, cciputils.SiloedLockReleaseTokenPool.String(), QualSiloedAV2, poolAV1, tokenpool.DefaultFinalityConfig(), []uint64{selB})
		poolBV2 := evm.DeployTokenPoolV200(t, env, cciputils.SiloedLockReleaseTokenPool.String(), QualSiloedBV2, poolBV1, tokenpool.DefaultFinalityConfig(), []uint64{selA})
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
