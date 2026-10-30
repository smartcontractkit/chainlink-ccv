package evm

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi/bind/v2"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"

	tpap_v150 "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_5_0/operations/token_pool_and_proxy"
	lnr_v200 "github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/v2_0_0/lock_release_token_pool"
	tp_v200 "github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/v2_0_0/token_pool"
	"github.com/smartcontractkit/chainlink-deployments-framework/chain/evm"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-evm/gethwrappers/shared/generated/initial/erc20"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/testutils/tokenpool"
)

// RequireLaneImportedFromV150 checks that migrated, a v2.0.0 pool activated with
// AutoMigrateRemoteChains alone (see tokenpool.Activate), took over legacy's lane to remote. legacy
// is the v1.5.0 pool migrated took over from, plain or *AndProxy, and remote is the pool on the other
// side of the lane. The activation input names neither a remote token, a remote pool nor a rate
// limit, so each one found on migrated was imported from legacy.
//
// The expected rate limits are legacy's own. For a proxy that is only the effective limit because
// the previous pools in these tests have their limits disabled (see deployTokenPoolBehindProxy);
// the import takes the tighter of the proxy's and the previous pool's limits.
func RequireLaneImportedFromV150(t *testing.T, env *deployment.Environment, legacy, migrated, remote tokenpool.TokenPool) {
	t.Helper()

	chain := evmChain(t, env, migrated.Selector())
	opts := &bind.CallOpts{Context: t.Context()}
	remoteSel := remote.Selector()

	newPool, err := tp_v200.NewTokenPool(common.HexToAddress(migrated.Address()), chain.Client)
	require.NoError(t, err)
	oldPool, err := tpap_v150.NewTokenPoolAndProxyContract(common.HexToAddress(legacy.Address()), chain.Client)
	require.NoError(t, err)

	supported, err := newPool.IsSupportedChain(opts, remoteSel)
	require.NoError(t, err)
	require.True(t, supported, "migrated pool %s should support chain %d", migrated.Address(), remoteSel)

	remoteToken, err := newPool.GetRemoteToken(opts, remoteSel)
	require.NoError(t, err)
	require.Equal(t, padAddress(remote.Token()), remoteToken, "migrated pool %s: remote token for chain %d", migrated.Address(), remoteSel)

	remotePools, err := newPool.GetRemotePools(opts, remoteSel)
	require.NoError(t, err)
	require.Contains(t, remotePools, padAddress(remote.Address()), "migrated pool %s: remote pools for chain %d", migrated.Address(), remoteSel)

	limits, err := newPool.GetCurrentRateLimiterState(opts, remoteSel, false)
	require.NoError(t, err)
	oldOutbound, err := oldPool.GetCurrentOutboundRateLimiterState(opts, remoteSel)
	require.NoError(t, err)
	oldInbound, err := oldPool.GetCurrentInboundRateLimiterState(opts, remoteSel)
	require.NoError(t, err)
	requireSameLimits(t, oldOutbound, limits.OutboundRateLimiterState, "outbound", migrated.Address(), remoteSel)
	requireSameLimits(t, oldInbound, limits.InboundRateLimiterState, "inbound", migrated.Address(), remoteSel)
}

// RequireRemotePoolV150 checks that the v1.5.0 pool, plain or *AndProxy, accepts only want's pool
// for its lane to want's chain. A v1.5.0 pool stores a single remote pool per lane, so reverse
// propagation replaces the old remote pool rather than adding the new one next to it.
func RequireRemotePoolV150(t *testing.T, env *deployment.Environment, pool, want tokenpool.TokenPool) {
	t.Helper()

	chain := evmChain(t, env, pool.Selector())
	contract, err := tpap_v150.NewTokenPoolAndProxyContract(common.HexToAddress(pool.Address()), chain.Client)
	require.NoError(t, err)
	got, err := contract.GetRemotePool(&bind.CallOpts{Context: t.Context()}, want.Selector())
	require.NoError(t, err)
	require.Equal(t, padAddress(want.Address()), got, "v1.5.0 pool %s: remote pool for chain %d", pool.Address(), want.Selector())
}

// LockBoxAddress returns the ERC20LockBox a v2.0.0 LockReleaseTokenPool holds its liquidity in.
func LockBoxAddress(t *testing.T, env *deployment.Environment, pool tokenpool.TokenPool) string {
	t.Helper()

	chain := evmChain(t, env, pool.Selector())
	contract, err := lnr_v200.NewLockReleaseTokenPool(common.HexToAddress(pool.Address()), chain.Client)
	require.NoError(t, err)
	lockBox, err := contract.GetLockBox(&bind.CallOpts{Context: t.Context()})
	require.NoError(t, err)
	require.NotEqual(t, common.Address{}, lockBox, "v2.0.0 pool %s has no lock box", pool.Address())

	return lockBox.Hex()
}

// TokenBalance returns holder's balance of pool's token, in the token's smallest unit.
func TokenBalance(t *testing.T, env *deployment.Environment, pool tokenpool.TokenPool, holder string) *big.Int {
	t.Helper()

	chain := evmChain(t, env, pool.Selector())
	token, err := erc20.NewERC20(common.HexToAddress(pool.Token()), chain.Client)
	require.NoError(t, err)
	balance, err := token.BalanceOf(&bind.CallOpts{Context: t.Context()}, common.HexToAddress(holder))
	require.NoError(t, err)

	return balance
}

func requireSameLimits(t *testing.T, want tpap_v150.TokenBucket, got tp_v200.RateLimiterTokenBucket, direction, pool string, remoteSel uint64) {
	t.Helper()

	require.Equal(t, want.IsEnabled, got.IsEnabled, "migrated pool %s: %s limit enabled for chain %d", pool, direction, remoteSel)
	require.Equal(t, 0, want.Capacity.Cmp(got.Capacity), "migrated pool %s: %s capacity for chain %d: want %s, got %s", pool, direction, remoteSel, want.Capacity, got.Capacity)
	require.Equal(t, 0, want.Rate.Cmp(got.Rate), "migrated pool %s: %s rate for chain %d: want %s, got %s", pool, direction, remoteSel, want.Rate, got.Rate)
}

// padAddress encodes an EVM address the way pools store remote tokens and pools: left-padded to
// 32 bytes.
func padAddress(addr string) []byte {
	return common.LeftPadBytes(common.HexToAddress(addr).Bytes(), 32)
}

func evmChain(t *testing.T, env *deployment.Environment, sel uint64) evm.Chain {
	t.Helper()

	chain, ok := env.BlockChains.EVMChains()[sel]
	require.True(t, ok, "evm chain not found for selector %d", sel)

	return chain
}
