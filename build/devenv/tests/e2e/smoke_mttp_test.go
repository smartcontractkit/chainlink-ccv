package e2e

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/pool_config_manager"
	"github.com/smartcontractkit/chainlink-ccip/deployment/tokens"
	cciputils "github.com/smartcontractkit/chainlink-ccip/deployment/utils"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"

	ccv "github.com/smartcontractkit/chainlink-ccv/build/devenv"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/testutils/chains/evm"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/testutils/mcms"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/testutils/tokenpool"
	"github.com/smartcontractkit/chainlink-ccv/protocol"

	_ "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_5_1/adapters"
	_ "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_6_1/adapters"
	_ "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/adapters"
)

// TestE2ESmoke_MTTPTransfers checks that one multi-token pool per chain can serve several tokens
// at once.
//
// Setup: two EVM chains (A, B), three burn-mint tokens deployed on each, and a single MTTP
// deployed per chain. Every token is registered on its chain's MTTP and connected to its
// counterpart on the other chain, so all traffic is MTTP to MTTP.
//
// Scenario: each token transfers A->B and B->A, and the shared helper asserts balances and
// delivery. This proves one pool can route several tokens through the registry and the full
// pipeline. All three tokens share the same policy set here, so per-token policy isolation is
// covered by the Foundry tests, not this one.
func TestE2ESmoke_MTTPTransfers(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode; requires a running devenv environment")
	}

	lib, env, chains := mttpEnvironment(t)
	require.GreaterOrEqual(t, len(chains), 2, "expected at least 2 EVM chains")
	selA := chains[0].ChainSelector()
	selB := chains[1].ChainSelector()

	const tokenCount = 3
	tokensA := deployMTTPTokens(t, env, selA, "mttp-a", tokenCount)
	tokensB := deployMTTPTokens(t, env, selB, "mttp-b", tokenCount)

	mttpA := evm.DeployMTTP(t, env, selA)
	mttpB := evm.DeployMTTP(t, env, selB)
	for i := range tokenCount {
		mttpA.AddToken(t, env, tokensA[i], evm.TokenDecimals, selB, tokensB[i], mttpB.Pool, false, false)
		mttpB.AddToken(t, env, tokensB[i], evm.TokenDecimals, selA, tokensA[i], mttpA.Pool, false, false)
	}

	for i := range tokenCount {
		poolA := mttpA.AsTokenPool(tokensA[i], evm.TokenDecimals)
		poolB := mttpB.AsTokenPool(tokensB[i], evm.TokenDecimals)
		tokenpool.RunBidirectionalTokenTransfer(t, lib, poolA, poolB, 1, protocol.Finality(0), fmt.Sprintf("t%d", i+1))
	}
}

// TestE2ESmoke_MTTPMigration checks that tokens can move from legacy single-token pools to the
// MTTP one chain at a time without breaking transfers, including while the two sides differ.
//
// Setup: two EVM chains (A, B) with three tokens (T1-T3), each with a legacy pool on both chains,
// connected with rate limits and proven with an initial round trip.
//
// Scenario:
//  1. T1 on A moves to the MTTP while B keeps its legacy pool. The MTTP uses the legacy pool data
//     format and B's pool is told to accept the MTTP as a remote. Transfers must still work.
//  2. T1 on B moves too, so both sides are MTTP and use the native format. Transfers must work.
//  3. T2 goes through the same two steps, reusing the MTTPs already deployed.
//  4. T3 is never migrated and must keep working on its legacy pools alongside the migrated tokens.
func TestE2ESmoke_MTTPMigration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode; requires a running devenv environment")
	}

	lib, env, chains := mttpEnvironment(t)
	require.GreaterOrEqual(t, len(chains), 2, "expected at least 2 EVM chains")
	selA := chains[0].ChainSelector()
	selB := chains[1].ChainSelector()
	fCfg := protocol.Finality(0)
	capacity, rate := scaledLegacyRateLimit()

	const tokenCount = 3
	poolsA := make([]tokenpool.TokenPool, tokenCount)
	poolsB := make([]tokenpool.TokenPool, tokenCount)
	conns := make([]tokenpool.Connection, tokenCount)
	for i := range tokenCount {
		poolsA[i] = evm.DeployBurnMintTokenPoolV161(t, env, selA, fmt.Sprintf("mig-a-%d", i))
		poolsB[i] = evm.DeployBurnMintTokenPoolV161(t, env, selB, fmt.Sprintf("mig-b-%d", i))
		conns[i] = tokenpool.Connection{
			PoolA: poolsA[i],
			PoolB: poolsB[i],
			RateLimits: tokenpool.BidirectionalRateLimitPair{
				AB: tokenpool.DefaultOutboundRateLimit(),
				BA: tokenpool.DefaultOutboundRateLimit(),
			},
		}
	}
	tokenpool.ConnectAll(t, env, cciputils.Version_1_6_1, conns)
	for i := range tokenCount {
		tokenpool.RunBidirectionalTokenTransfer(t, lib, poolsA[i], poolsB[i], 1, fCfg, fmt.Sprintf("initial t%d", i+1))
	}

	t1a := common.HexToAddress(poolsA[0].Token())
	t1b := common.HexToAddress(poolsB[0].Token())
	t2a := common.HexToAddress(poolsA[1].Token())
	t2b := common.HexToAddress(poolsB[1].Token())

	// Step 1: A's MTTP takes over T1 and talks to B's legacy pool. The two true flags make the MTTP
	// send and accept the legacy 32-byte pool data that B's pool understands, and the MTTP carries the
	// legacy lane's rate limits. Configure everything, let B's legacy pool trust the MTTP, then switch
	// A's registry last so no transfer can land in a half-configured state.
	mttpA := evm.DeployMTTP(t, env, selA)
	mttpA.SetRateLimitPolicy(t, env, capacity, rate)
	mttpA.ConfigureToken(t, env, t1a, evm.TokenDecimals, selB, t1b, common.HexToAddress(poolsB[0].Address()), true, true)
	evm.AddLegacyPoolRemotePool(t, env, selB, poolsB[0].Address(), selA, mttpA.Pool)
	mttpA.SwitchPool(t, env, t1a)
	poolMttpA1 := mttpA.AsTokenPool(t1a, evm.TokenDecimals)
	tokenpool.RunBidirectionalTokenTransfer(t, lib, poolMttpA1, poolsB[0], 1, fCfg, "T1 canary A")
	assertLaneRateLimit(t, mttpA.RateLimiterState(t, env, t1a, selB), capacity, rate)

	// Step 2: B's MTTP takes over T1. B is configured to send the native format but keeps accepting
	// A's legacy-format sends until A flips. A keeps trusting B's legacy pool for messages already in
	// flight and adds B's MTTP. A B->A transfer is sent by the legacy pool, then B switches while it is
	// in flight, so the message settles against A's MTTP with the legacy pool still trusted.
	mttpB := evm.DeployMTTP(t, env, selB)
	mttpB.SetRateLimitPolicy(t, env, capacity, rate)
	mttpB.ConfigureToken(t, env, t1b, evm.TokenDecimals, selA, t1a, mttpA.Pool, false, true)
	mttpA.SetRemotePools(
		t,
		env,
		t1a,
		selB,
		true,
		evm.RemotePool{Address: common.HexToAddress(poolsB[0].Address()), AllowLegacy: true},
		evm.RemotePool{Address: mttpB.Pool, AllowLegacy: false},
	)
	poolMttpB1 := mttpB.AsTokenPool(t1b, evm.TokenDecimals)
	tokenpool.RunTokenTransfer(t, lib, poolsB[0], poolMttpA1, 1, fCfg, "T1 B->A across switch", func() {
		mttpB.SwitchPool(t, env, t1b)
	})
	assertLaneRateLimit(t, mttpB.RateLimiterState(t, env, t1b, selA), capacity, rate)

	// Both sides are now MTTP, so drop the legacy pool and the legacy receive flags and run the native
	// format end to end.
	mttpA.SetRemotePools(t, env, t1a, selB, false, evm.RemotePool{Address: mttpB.Pool, AllowLegacy: false})
	mttpB.SetRemotePools(t, env, t1b, selA, false, evm.RemotePool{Address: mttpA.Pool, AllowLegacy: false})
	tokenpool.RunBidirectionalTokenTransfer(t, lib, poolMttpA1, poolMttpB1, 1, fCfg, "T1 canary complete")

	// Step 3: T2 repeats the migration on the MTTPs that are already serving T1.
	mttpA.ConfigureToken(t, env, t2a, evm.TokenDecimals, selB, t2b, common.HexToAddress(poolsB[1].Address()), true, true)
	evm.AddLegacyPoolRemotePool(t, env, selB, poolsB[1].Address(), selA, mttpA.Pool)
	mttpA.SwitchPool(t, env, t2a)
	poolMttpA2 := mttpA.AsTokenPool(t2a, evm.TokenDecimals)
	tokenpool.RunBidirectionalTokenTransfer(t, lib, poolMttpA2, poolsB[1], 1, fCfg, "T2 canary A")

	mttpB.ConfigureToken(t, env, t2b, evm.TokenDecimals, selA, t2a, mttpA.Pool, false, true)
	mttpA.SetRemotePools(
		t,
		env,
		t2a,
		selB,
		true,
		evm.RemotePool{Address: common.HexToAddress(poolsB[1].Address()), AllowLegacy: true},
		evm.RemotePool{Address: mttpB.Pool, AllowLegacy: false},
	)
	poolMttpB2 := mttpB.AsTokenPool(t2b, evm.TokenDecimals)
	tokenpool.RunTokenTransfer(t, lib, poolsB[1], poolMttpA2, 1, fCfg, "T2 B->A across switch", func() {
		mttpB.SwitchPool(t, env, t2b)
	})
	mttpA.SetRemotePools(t, env, t2a, selB, false, evm.RemotePool{Address: mttpB.Pool, AllowLegacy: false})
	mttpB.SetRemotePools(t, env, t2b, selA, false, evm.RemotePool{Address: mttpA.Pool, AllowLegacy: false})
	tokenpool.RunBidirectionalTokenTransfer(t, lib, poolMttpA2, poolMttpB2, 1, fCfg, "T2 migrated")

	// Step 4: T3 was never migrated, so this checks the MTTP deployment did not disturb legacy pools.
	tokenpool.RunBidirectionalTokenTransfer(t, lib, poolsA[2], poolsB[2], 1, fCfg, "T3 control")
}

// mttpEnvironment loads the running devenv and returns the lib, the CLDF environment and the EVM
// chains. It also deploys MCMS with the CLL qualifier on every chain, because token admin and pool
// ownership sit with the timelock and the helpers execute those writes through it.
func mttpEnvironment(t *testing.T) (ccv.Lib, *deployment.Environment, []ccv.ChainImpl) {
	t.Helper()

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

	return lib, env, chains
}

// deployMTTPTokens deploys n burn-mint tokens on one chain and returns their addresses. The tokens
// have no legacy pool: they go straight onto the MTTP.
func deployMTTPTokens(t *testing.T, env *deployment.Environment, sel uint64, qual string, n int) []common.Address {
	t.Helper()

	out := make([]common.Address, n)
	for i := range n {
		out[i] = evm.DeployMTTPToken(t, env, sel, fmt.Sprintf("%s-%d", qual, i))
	}
	return out
}

// scaledLegacyRateLimit returns the legacy pools' default outbound rate limit scaled to the token
// decimals, the values an MTTP lane should carry after migration.
func scaledLegacyRateLimit() (capacity, rate *big.Int) {
	rl := tokenpool.DefaultOutboundRateLimit()
	return tokens.ScaleTokenAmount(big.NewInt(int64(rl.Capacity)), evm.TokenDecimals),
		tokens.ScaleTokenAmount(big.NewInt(int64(rl.Rate)), evm.TokenDecimals)
}

// assertLaneRateLimit checks that a lane's outbound and inbound buckets carry the migrated limits.
func assertLaneRateLimit(
	t *testing.T,
	state pool_config_manager.IPoolConfigManagerLaneRateLimiterState,
	capacity, rate *big.Int,
) {
	t.Helper()

	require.True(t, state.Outbound.IsEnabled, "outbound rate limit enabled")
	require.Zero(t, capacity.Cmp(state.Outbound.Capacity), "outbound capacity")
	require.Zero(t, rate.Cmp(state.Outbound.Rate), "outbound rate")
	require.True(t, state.Inbound.IsEnabled, "inbound rate limit enabled")
	require.Zero(t, capacity.Cmp(state.Inbound.Capacity), "inbound capacity")
	require.Zero(t, rate.Cmp(state.Inbound.Rate), "inbound rate")
}
