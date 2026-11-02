package e2e

import (
	"math/big"
	"testing"

	"github.com/Masterminds/semver/v3"
	"github.com/stretchr/testify/require"

	chainsel "github.com/smartcontractkit/chain-selectors"
	cciputils "github.com/smartcontractkit/chainlink-ccip/deployment/utils"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"

	ccv "github.com/smartcontractkit/chainlink-ccv/build/devenv"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/testutils/chains/evm"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/testutils/mcms"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/testutils/tokenpool"
	"github.com/smartcontractkit/chainlink-ccv/protocol"

	_ "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_2_0/adapters"
	_ "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_4_0/adapters"
	_ "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_5_0/adapters"
	_ "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/adapters"
)

// legacyPool is a pool deployed by a legacyMigrationCase, with the address that holds its
// lock-release liquidity: the pool itself, or the previous pool behind a v1.5.0 proxy.
type legacyPool struct {
	tokenpool.TokenPool
	liquidityHolder string
}

// legacyMigrationCase is one pre-v1.6 pool shape that gets migrated to v2.0.0.
type legacyMigrationCase struct {
	name string
	// qualifier is unique per case; the pools of a case are qualified from it.
	qualifier string
	// deploy deploys the legacy pool for a new token on sel; remote is the chain its lane will
	// connect to.
	deploy      func(t *testing.T, env *deployment.Environment, sel uint64, qual string, remote uint64) legacyPool
	newPoolType string
	lockRelease bool
}

func plainV150(deploy func(*testing.T, *deployment.Environment, uint64, string) tokenpool.TokenPool) func(*testing.T, *deployment.Environment, uint64, string, uint64) legacyPool {
	return func(t *testing.T, env *deployment.Environment, sel uint64, qual string, _ uint64) legacyPool {
		pool := deploy(t, env, sel, qual)
		return legacyPool{TokenPool: pool, liquidityHolder: pool.Address()}
	}
}

func behindProxy(
	deploy func(*testing.T, *deployment.Environment, uint64, string, *semver.Version, []uint64) *evm.ProxiedTokenPool,
	previousVersion *semver.Version,
) func(*testing.T, *deployment.Environment, uint64, string, uint64) legacyPool {
	return func(t *testing.T, env *deployment.Environment, sel uint64, qual string, remote uint64) legacyPool {
		pool := deploy(t, env, sel, qual, previousVersion, []uint64{remote})
		return legacyPool{TokenPool: pool, liquidityHolder: pool.Previous()}
	}
}

// TestE2ESmoke_LegacyTokenPoolMigrationEVM2EVM migrates the oldest pool shapes still on CCIP to
// v2.0.0, for both burn-mint and lock-release:
//
//   - a plain v1.5.0 pool, with no proxy in front of it;
//   - a v1.4.0 pool behind a v1.5.0 *TokenPoolAndProxy;
//   - a v1.2.0 pool behind a v1.5.0 *TokenPoolAndProxy.
//
// Each case connects a legacy pool pair across two chains and sends tokens both ways, then migrates
// one chain at a time. A migrated pool is activated with AutoMigrateRemoteChains alone, so the test
// checks on-chain that its lane was imported from the legacy pool and that the remote legacy pool was
// repointed at it (reverse propagation), then sends tokens both ways again. Lock-release cases also
// migrate the liquidity first, naming the registered pool as the operator would: for a proxy, the
// migration finds the liquidity in the previous pool and drains it from there.
func TestE2ESmoke_LegacyTokenPoolMigrationEVM2EVM(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode; requires a running devenv environment")
	}

	const (
		TokensToSend = 1
		// Liquidity is the lock-release liquidity each legacy pool starts with, in whole tokens.
		Liquidity = 100
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

	cases := []legacyMigrationCase{
		{
			name:        "v1.5.0 BurnMintTokenPool",
			qualifier:   "EVM_POOL_LEGACY_BNM_V150",
			deploy:      plainV150(evm.DeployBurnMintTokenPoolV150),
			newPoolType: cciputils.BurnMintTokenPool.String(),
		},
		{
			name:        "v1.5.0 LockReleaseTokenPool",
			qualifier:   "EVM_POOL_LEGACY_LNR_V150",
			deploy:      plainV150(evm.DeployLockReleaseTokenPoolV150),
			newPoolType: cciputils.LockReleaseTokenPool.String(),
			lockRelease: true,
		},
		{
			name:        "v1.4.0 BurnMintTokenPool behind v1.5.0 proxy",
			qualifier:   "EVM_POOL_LEGACY_BNM_V140_PROXY",
			deploy:      behindProxy(evm.DeployBurnMintTokenPoolBehindProxy, cciputils.Version_1_4_0),
			newPoolType: cciputils.BurnMintTokenPool.String(),
		},
		{
			name:        "v1.4.0 LockReleaseTokenPool behind v1.5.0 proxy",
			qualifier:   "EVM_POOL_LEGACY_LNR_V140_PROXY",
			deploy:      behindProxy(evm.DeployLockReleaseTokenPoolBehindProxy, cciputils.Version_1_4_0),
			newPoolType: cciputils.LockReleaseTokenPool.String(),
			lockRelease: true,
		},
		{
			name:        "v1.2.0 BurnMintTokenPool behind v1.5.0 proxy",
			qualifier:   "EVM_POOL_LEGACY_BNM_V120_PROXY",
			deploy:      behindProxy(evm.DeployBurnMintTokenPoolBehindProxy, cciputils.Version_1_2_0),
			newPoolType: cciputils.BurnMintTokenPool.String(),
		},
		{
			name:        "v1.2.0 LockReleaseTokenPool behind v1.5.0 proxy",
			qualifier:   "EVM_POOL_LEGACY_LNR_V120_PROXY",
			deploy:      behindProxy(evm.DeployLockReleaseTokenPoolBehindProxy, cciputils.Version_1_2_0),
			newPoolType: cciputils.LockReleaseTokenPool.String(),
			lockRelease: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			qual := func(chain, version string) string {
				return tc.qualifier + "_" + chain + "_" + version
			}
			rl := tokenpool.BidirectionalRateLimitPair{
				AB: tokenpool.DefaultOutboundRateLimit(),
				BA: tokenpool.DefaultOutboundRateLimit(),
			}

			// Part 1: deploy and connect the legacy pair and ensure token transfers work. A
			// lock-release pool releases from held liquidity, so its holder is funded up front.
			poolA1 := tc.deploy(t, env, selA, qual("A", "V1"), selB)
			poolB1 := tc.deploy(t, env, selB, qual("B", "V1"), selA)
			if tc.lockRelease {
				evm.TransferTokens(t, env, selA, poolA1.Token(), poolA1.liquidityHolder, Liquidity)
				evm.TransferTokens(t, env, selB, poolB1.Token(), poolB1.liquidityHolder, Liquidity)
			}
			tokenpool.ConnectAll(t, env, cciputils.Version_1_5_0, []tokenpool.Connection{
				{PoolA: poolA1, PoolB: poolB1, RateLimits: rl},
			})
			tokenpool.RunBidirectionalTokenTransfer(t, lib, poolA1, poolB1, TokensToSend, fCfg, "pre-migration")

			// Part 2: migrate A while B stays legacy. B's pool only learns about A's new pool through
			// reverse propagation.
			poolA2 := migrateLegacyPool(t, env, tc, poolA1, qual("A", "V2"))
			evm.RequireLaneImportedFromV150(t, env, poolA1, poolA2, poolB1)
			evm.RequireRemotePoolV150(t, env, poolB1, poolA2)
			tokenpool.RunBidirectionalTokenTransfer(t, lib, poolA2, poolB1, TokensToSend, fCfg, "migrate-A")

			// Part 3: migrate B. Its lane to A is imported from the legacy pool B, which by now
			// points at A's new pool, and A's new pool learns B's new pool by reverse propagation.
			poolB2 := migrateLegacyPool(t, env, tc, poolB1, qual("B", "V2"))
			evm.RequireLaneImportedFromV150(t, env, poolB1, poolB2, poolA2)
			tokenpool.RunBidirectionalTokenTransfer(t, lib, poolA2, poolB2, TokensToSend, fCfg, "migrate-B")
		})
	}
}

// migrateLegacyPool deploys the v2.0.0 successor to legacy, moves any lock-release liquidity into
// it, and activates it. The liquidity is migrated before activation so the new pool can release as
// soon as it is live; the migration names the registered pool, which for a proxy delegates to the
// previous pool holding the liquidity.
func migrateLegacyPool(t *testing.T, env *deployment.Environment, tc legacyMigrationCase, legacy legacyPool, qual string) tokenpool.TokenPool {
	t.Helper()

	migrated := evm.DeployTokenPoolV200(t, env, tc.newPoolType, qual, legacy, tokenpool.DefaultFinalityConfig())
	require.NotEqual(t, legacy.Address(), migrated.Address())
	require.Equal(t, legacy.Token(), migrated.Token())

	if tc.lockRelease {
		liquidity := evm.TokenBalance(t, env, legacy, legacy.liquidityHolder)
		require.Positive(t, liquidity.Sign(), "legacy pool %s holds no liquidity to migrate", legacy.Address())

		tokenpool.MigrateLiquidity(t, env, legacy, migrated, tokenpool.MigrateAllLiquidity)

		zero := big.NewInt(0)
		require.Equal(t, 0, zero.Cmp(evm.TokenBalance(t, env, legacy, legacy.liquidityHolder)), "liquidity holder %s should be drained", legacy.liquidityHolder)
		require.Equal(t, 0, zero.Cmp(evm.TokenBalance(t, env, legacy, legacy.Address())), "legacy pool %s should hold nothing", legacy.Address())
		lockBox := evm.LockBoxAddress(t, env, migrated)
		require.Equal(t, 0, liquidity.Cmp(evm.TokenBalance(t, env, migrated, lockBox)), "lock box %s should hold the migrated liquidity", lockBox)
	}

	tokenpool.Activate(t, env, migrated)

	return migrated
}
