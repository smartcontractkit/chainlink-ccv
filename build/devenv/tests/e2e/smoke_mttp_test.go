package e2e

import (
	"fmt"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"

	chainsel "github.com/smartcontractkit/chain-selectors"
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
// connected and proven with an initial round trip.
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

	// Step 1: A's MTTP takes over T1 and talks to B's legacy pool. The two true flags make the MTTP
	// send and accept the legacy 32-byte pool data that B's pool understands.
	// The legacy pool on B must also be told to trust the MTTP as a remote pool.
	t1a := common.HexToAddress(poolsA[0].Token())
	t1b := common.HexToAddress(poolsB[0].Token())
	mttpA := evm.DeployMTTP(t, env, selA)
	mttpA.AddToken(t, env, t1a, evm.TokenDecimals, selB, t1b, common.HexToAddress(poolsB[0].Address()), true, true)
	evm.AddLegacyPoolRemotePool(t, env, selB, poolsB[0].Address(), selA, mttpA.Pool)
	poolMttpA1 := mttpA.AsTokenPool(t1a, evm.TokenDecimals)
	tokenpool.RunBidirectionalTokenTransfer(t, lib, poolMttpA1, poolsB[0], 1, fCfg, "T1 canary A")

	// Step 2: B's MTTP takes over T1, then A's MTTP is repointed from B's legacy pool to B's MTTP
	// with the native format (false flags). Both directions now run MTTP to MTTP.
	mttpB := evm.DeployMTTP(t, env, selB)
	mttpB.AddToken(t, env, t1b, evm.TokenDecimals, selA, t1a, mttpA.Pool, false, false)
	mttpA.AddToken(t, env, t1a, evm.TokenDecimals, selB, t1b, mttpB.Pool, false, false)
	poolMttpB1 := mttpB.AsTokenPool(t1b, evm.TokenDecimals)
	tokenpool.RunBidirectionalTokenTransfer(t, lib, poolMttpA1, poolMttpB1, 1, fCfg, "T1 canary complete")

	// Step 3: T2 repeats steps 1 and 2 on the already deployed MTTPs, showing a second token can be
	// added to a pool that is already serving a migrated token.
	t2a := common.HexToAddress(poolsA[1].Token())
	t2b := common.HexToAddress(poolsB[1].Token())
	mttpA.AddToken(t, env, t2a, evm.TokenDecimals, selB, t2b, common.HexToAddress(poolsB[1].Address()), true, true)
	evm.AddLegacyPoolRemotePool(t, env, selB, poolsB[1].Address(), selA, mttpA.Pool)
	poolMttpA2 := mttpA.AsTokenPool(t2a, evm.TokenDecimals)
	tokenpool.RunBidirectionalTokenTransfer(t, lib, poolMttpA2, poolsB[1], 1, fCfg, "T2 canary A")
	mttpB.AddToken(t, env, t2b, evm.TokenDecimals, selA, t2a, mttpA.Pool, false, false)
	mttpA.AddToken(t, env, t2a, evm.TokenDecimals, selB, t2b, mttpB.Pool, false, false)
	poolMttpB2 := mttpB.AsTokenPool(t2b, evm.TokenDecimals)
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

// deployMTTPTokens deploys n burn-mint tokens on one chain and returns their addresses. Token
// deployment also creates a legacy pool per token; MTTP registration later replaces it in the TAR.
func deployMTTPTokens(t *testing.T, env *deployment.Environment, sel uint64, qual string, n int) []common.Address {
	t.Helper()

	out := make([]common.Address, n)
	for i := range n {
		pool := evm.DeployBurnMintTokenPoolV161(t, env, sel, fmt.Sprintf("%s-%d", qual, i))
		out[i] = common.HexToAddress(pool.Token())
	}
	return out
}
