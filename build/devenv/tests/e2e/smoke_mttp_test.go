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

// TestE2ESmoke_MTTPTransfers covers the native multi-token path: three tokens transfer both ways
// through the MTTP stacks on two chains. It exercises the pool, pool config manager, policy stores,
// token registry, verifiers and executor together.
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
	for i := 0; i < tokenCount; i++ {
		mttpA.AddToken(t, env, tokensA[i], evm.TokenDecimals, selB, tokensB[i], mttpB.Pool, false, false)
		mttpB.AddToken(t, env, tokensB[i], evm.TokenDecimals, selA, tokensA[i], mttpA.Pool, false, false)
	}

	for i := 0; i < tokenCount; i++ {
		poolA := mttpA.AsTokenPool(tokensA[i], evm.TokenDecimals)
		poolB := mttpB.AsTokenPool(tokensB[i], evm.TokenDecimals)
		tokenpool.RunBidirectionalTokenTransfer(t, lib, poolA, poolB, 1, protocol.Finality(0), fmt.Sprintf("t%d", i+1))
	}
}

// TestE2ESmoke_MTTPMigration covers the migration path: start with normal single-token pools on both
// chains, move T1 on A to the MTTP while B is still normal, then move T1 on B and finish with MTTP
// on both sides. T2 migrates next; T3 stays on the normal pools as a control.
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
	for i := 0; i < tokenCount; i++ {
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
	for i := 0; i < tokenCount; i++ {
		tokenpool.RunBidirectionalTokenTransfer(t, lib, poolsA[i], poolsB[i], 1, fCfg, fmt.Sprintf("initial t%d", i+1))
	}

	// T1 canary on A: the MTTP takes over T1a and talks to B's normal pool. A sends and accepts the
	// legacy 32-byte pool data while B is still normal.
	t1a := common.HexToAddress(poolsA[0].Token())
	t1b := common.HexToAddress(poolsB[0].Token())
	mttpA := evm.DeployMTTP(t, env, selA)
	mttpA.AddToken(t, env, t1a, evm.TokenDecimals, selB, t1b, common.HexToAddress(poolsB[0].Address()), true, true)
	evm.AddLegacyPoolRemotePool(t, env, selB, poolsB[0].Address(), selA, mttpA.Pool)
	poolMttpA1 := mttpA.AsTokenPool(t1a, evm.TokenDecimals)
	tokenpool.RunBidirectionalTokenTransfer(t, lib, poolMttpA1, poolsB[0], 1, fCfg, "T1 canary A")

	// T1 canary on B: B's MTTP takes over T1b, then both directions run MTTP to MTTP.
	mttpB := evm.DeployMTTP(t, env, selB)
	mttpB.AddToken(t, env, t1b, evm.TokenDecimals, selA, t1a, mttpA.Pool, false, false)
	mttpA.AddToken(t, env, t1a, evm.TokenDecimals, selB, t1b, mttpB.Pool, false, false)
	poolMttpB1 := mttpB.AsTokenPool(t1b, evm.TokenDecimals)
	tokenpool.RunBidirectionalTokenTransfer(t, lib, poolMttpA1, poolMttpB1, 1, fCfg, "T1 canary complete")

	// T2 migrates on both chains the same way.
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

	// T3 stays on the normal pools.
	tokenpool.RunBidirectionalTokenTransfer(t, lib, poolsA[2], poolsB[2], 1, fCfg, "T3 control")
}

// mttpEnvironment loads the running devenv and returns the lib, the CLDF environment and the EVM
// chains.
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

// deployMTTPTokens deploys n burn-mint tokens on one chain and returns their addresses. The token
// expansion also deploys a legacy pool for each, which the MTTP registration then replaces in the
// token admin registry.
func deployMTTPTokens(t *testing.T, env *deployment.Environment, sel uint64, qual string, n int) []common.Address {
	t.Helper()

	out := make([]common.Address, n)
	for i := 0; i < n; i++ {
		pool := evm.DeployBurnMintTokenPoolV161(t, env, sel, fmt.Sprintf("%s-%d", qual, i))
		out[i] = common.HexToAddress(pool.Token())
	}
	return out
}
