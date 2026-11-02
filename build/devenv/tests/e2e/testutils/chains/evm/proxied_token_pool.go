package evm

import (
	"math/big"
	"testing"

	"github.com/Masterminds/semver/v3"
	"github.com/ethereum/go-ethereum/accounts/abi/bind/v2"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/tokens/tokenimpl"
	evmadapters "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_0_0/adapters"
	bnm_drip_v1_0 "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_0_0/operations/burn_mint_erc20_with_drip"
	bnm_v120 "github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/v1_2_0/burn_mint_token_pool"
	lnr_v120 "github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/v1_2_0/lock_release_token_pool"
	bnm_v140 "github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/v1_4_0/burn_mint_token_pool"
	lnr_v140 "github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/v1_4_0/lock_release_token_pool"
	bnm_proxy_v150 "github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/v1_5_0/burn_mint_token_pool_and_proxy"
	cciputils "github.com/smartcontractkit/chainlink-ccip/deployment/utils"
	ccipdatastore "github.com/smartcontractkit/chainlink-ccip/deployment/utils/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/chain/evm"
	evm_contract "github.com/smartcontractkit/chainlink-deployments-framework/chain/evm/operations/contract"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"
	mcmsevm "github.com/smartcontractkit/mcms/sdk/evm"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/testutils/dsutils"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/testutils/mcms"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/testutils/tokenpool"
)

var _ tokenpool.TokenPool = (*ProxiedTokenPool)(nil)

// ProxiedTokenPool is a v1.5.0 *TokenPoolAndProxy fronting a v1.4.0 or v1.2.0 previous pool, the
// shape every surviving pre-v1.5 pool has on CCIP today:
//
//	TokenAdminRegistry -> *TokenPoolAndProxy 1.5.0      (the registered pool: Address())
//	                        └─ getPreviousPool() -> *TokenPool 1.4.0 or 1.2.0 (Previous())
//
// The proxy validates every transfer against its own lane config (remote pool, rate limits) and
// then has the previous pool lock/burn or release/mint the tokens. The previous pool therefore needs
// its own lane config too, and for lock-release it is the contract that holds the liquidity.
type ProxiedTokenPool struct {
	*TokenPool
	previous        common.Address
	previousVersion *semver.Version
}

// Previous returns the address of the previous pool the proxy routes through.
func (p *ProxiedTokenPool) Previous() string {
	return p.previous.Hex()
}

// PreviousVersion returns the version of the previous pool, v1.4.0 or v1.2.0.
func (p *ProxiedTokenPool) PreviousVersion() *semver.Version {
	return p.previousVersion
}

// DeployBurnMintTokenPoolBehindProxy deploys a BurnMintTokenPoolAndProxy v1.5.0 fronting a
// BurnMintTokenPool at previousVersion (v1.4.0 or v1.2.0). See deployTokenPoolBehindProxy.
func DeployBurnMintTokenPoolBehindProxy(t *testing.T, env *deployment.Environment, sel uint64, qual string, previousVersion *semver.Version, remoteSelectors []uint64) *ProxiedTokenPool {
	t.Helper()

	return deployTokenPoolBehindProxy(t, env, sel, qual, cciputils.BurnMintTokenPoolAndProxy, previousVersion, remoteSelectors)
}

// DeployLockReleaseTokenPoolBehindProxy deploys a LockReleaseTokenPoolAndProxy v1.5.0 fronting a
// LockReleaseTokenPool at previousVersion (v1.4.0 or v1.2.0). Neither pool accepts liquidity
// providers: fund the previous pool by transferring tokens to Previous(). See
// deployTokenPoolBehindProxy.
func DeployLockReleaseTokenPoolBehindProxy(t *testing.T, env *deployment.Environment, sel uint64, qual string, previousVersion *semver.Version, remoteSelectors []uint64) *ProxiedTokenPool {
	t.Helper()

	return deployTokenPoolBehindProxy(t, env, sel, qual, cciputils.LockReleaseTokenPoolAndProxy, previousVersion, remoteSelectors)
}

// deployTokenPoolBehindProxy deploys a new token and a v1.5.0 proxy pool for it through
// TokenExpansion, then deploys the previous pool and wires it in. CLD only migrates away from
// v1.4.0 and v1.2.0 pools and has no operation to deploy one, so the previous pool is deployed and
// wired with its gobindings:
//
//   - v1.4.0: its router is the proxy, which answers the pool's onRamp/offRamp checks with itself,
//     and it gets a chain update (rate limits disabled) for each of remoteSelectors;
//   - v1.2.0: it is ramp-keyed, so the proxy is registered as its only onRamp and offRamp (rate
//     limits disabled) and remoteSelectors is not used.
//
// With the previous pool's limits disabled, the effective limits are the proxy's, which keeps the
// imported v2.0.0 limits equal to what the proxy is configured with. The previous pool is then
// handed to the timelock together with, for burn-mint, the token's mint and burn roles.
//
// The proxy is left with no lanes and owned by the deployer, like any pool TokenExpansion just
// deployed; connecting it (tokenpool.ConnectPair) configures its lanes and hands it to the timelock.
func deployTokenPoolBehindProxy(
	t *testing.T,
	env *deployment.Environment,
	sel uint64,
	qual string,
	proxyType deployment.ContractType,
	previousVersion *semver.Version,
	remoteSelectors []uint64,
) *ProxiedTokenPool {
	t.Helper()

	lockRelease := proxyType == cciputils.LockReleaseTokenPoolAndProxy
	var presets *PoolSpecificPresets
	if lockRelease {
		presets = &PoolSpecificPresets{AcceptLiquidity: new(false)}
	}
	deployed := deployTokenPoolWithPresets(t, env, sel, qual, proxyType.String(), cciputils.Version_1_5_0, presets)
	proxy, ok := deployed.(*TokenPool)
	require.True(t, ok, "unexpected token pool implementation %T", deployed)

	chain, ok := env.BlockChains.EVMChains()[sel]
	require.True(t, ok, "evm chain not found for selector %d", sel)
	token := common.HexToAddress(proxy.Token())
	proxyAddr := common.HexToAddress(proxy.Address())
	// The legacy pools check curses through their ARM proxy, so it must be the chain's real RMN
	// proxy: a stand-in would make every transfer through the previous pool revert.
	rmnProxy, err := (&evmadapters.EVMTokenBase{}).GetRMNProxyAddress(env.DataStore, sel)
	require.NoError(t, err, "failed to resolve the RMN proxy on chain %d", sel)
	timelock := timelockAddress(t, env, sel)

	var (
		previous     common.Address
		previousType deployment.ContractType
	)
	switch {
	case previousVersion.Equal(cciputils.Version_1_4_0):
		previous, previousType = deployPreviousPoolV140(t, chain, lockRelease, token, rmnProxy, proxyAddr, timelock, remoteSelectors)
	case previousVersion.Equal(cciputils.Version_1_2_0):
		previous, previousType = deployPreviousPoolV120(t, chain, lockRelease, token, rmnProxy, proxyAddr, timelock)
	default:
		require.FailNow(t, "unsupported previous pool version", "%s; expected 1.4.0 or 1.2.0", previousVersion)
	}

	// setPreviousPool shares one signature across both proxy types.
	proxyContract, err := bnm_proxy_v150.NewBurnMintTokenPoolAndProxy(proxyAddr, chain.Client)
	require.NoError(t, err)
	confirm(t, chain, "setPreviousPool", func() (*types.Transaction, error) {
		return proxyContract.SetPreviousPool(chain.DeployerKey, previous)
	})
	gotPrevious, err := proxyContract.GetPreviousPool(&bind.CallOpts{Context: t.Context()})
	require.NoError(t, err)
	require.Equal(t, previous, gotPrevious, "proxy %s should route through previous pool %s", proxyAddr.Hex(), previous.Hex())

	// Record the previous pool the way an operator would find it in CLD.
	ds := datastore.NewMemoryDataStore()
	require.NoError(t, ds.Addresses().Add(datastore.AddressRef{
		ChainSelector: sel,
		Address:       previous.Hex(),
		Type:          datastore.ContractType(previousType),
		Version:       previousVersion,
		Qualifier:     qual + "_PREVIOUS",
	}))
	dsutils.MergeDataStore(t, env, ds.Seal())

	handPreviousPoolToTimelock(t, env, chain, lockRelease, token, previous, timelock)

	return &ProxiedTokenPool{
		TokenPool:       proxy,
		previous:        previous,
		previousVersion: previousVersion,
	}
}

func deployPreviousPoolV140(
	t *testing.T,
	chain evm.Chain,
	lockRelease bool,
	token, rmnProxy, proxy, timelock common.Address,
	remoteSelectors []uint64,
) (common.Address, deployment.ContractType) {
	t.Helper()

	disabled := bnm_v140.RateLimiterConfig{IsEnabled: false, Capacity: big.NewInt(0), Rate: big.NewInt(0)}
	updates := make([]bnm_v140.TokenPoolChainUpdate, 0, len(remoteSelectors))
	for _, remote := range remoteSelectors {
		updates = append(updates, bnm_v140.TokenPoolChainUpdate{
			RemoteChainSelector:       remote,
			Allowed:                   true,
			OutboundRateLimiterConfig: disabled,
			InboundRateLimiterConfig:  disabled,
		})
	}

	if lockRelease {
		addr, tx, pool, err := lnr_v140.DeployLockReleaseTokenPool(chain.DeployerKey, chain.Client, token, []common.Address{}, rmnProxy, false, proxy)
		require.NoError(t, err, "failed to deploy v1.4.0 LockReleaseTokenPool on chain %d", chain.Selector)
		confirm(t, chain, "deploy v1.4.0 LockReleaseTokenPool", func() (*types.Transaction, error) { return tx, nil })
		// The two pool types share the TokenPool chain update; convert to this binding's type.
		lnrUpdates := make([]lnr_v140.TokenPoolChainUpdate, 0, len(updates))
		for _, u := range updates {
			lnrUpdates = append(lnrUpdates, lnr_v140.TokenPoolChainUpdate{
				RemoteChainSelector:       u.RemoteChainSelector,
				Allowed:                   u.Allowed,
				OutboundRateLimiterConfig: lnr_v140.RateLimiterConfig(u.OutboundRateLimiterConfig),
				InboundRateLimiterConfig:  lnr_v140.RateLimiterConfig(u.InboundRateLimiterConfig),
			})
		}
		confirm(t, chain, "applyChainUpdates", func() (*types.Transaction, error) {
			return pool.ApplyChainUpdates(chain.DeployerKey, lnrUpdates)
		})
		confirm(t, chain, "transferOwnership", func() (*types.Transaction, error) {
			return pool.TransferOwnership(chain.DeployerKey, timelock)
		})

		return addr, cciputils.LockReleaseTokenPool
	}

	addr, tx, pool, err := bnm_v140.DeployBurnMintTokenPool(chain.DeployerKey, chain.Client, token, []common.Address{}, rmnProxy, proxy)
	require.NoError(t, err, "failed to deploy v1.4.0 BurnMintTokenPool on chain %d", chain.Selector)
	confirm(t, chain, "deploy v1.4.0 BurnMintTokenPool", func() (*types.Transaction, error) { return tx, nil })
	confirm(t, chain, "applyChainUpdates", func() (*types.Transaction, error) {
		return pool.ApplyChainUpdates(chain.DeployerKey, updates)
	})
	confirm(t, chain, "transferOwnership", func() (*types.Transaction, error) {
		return pool.TransferOwnership(chain.DeployerKey, timelock)
	})

	return addr, cciputils.BurnMintTokenPool
}

func deployPreviousPoolV120(
	t *testing.T,
	chain evm.Chain,
	lockRelease bool,
	token, rmnProxy, proxy, timelock common.Address,
) (common.Address, deployment.ContractType) {
	t.Helper()

	if lockRelease {
		// acceptLiquidity stays false: the v1.2.0 liquidity migration refuses a pool that accepts
		// liquidity, since provider credits could then exist that a migration would strand.
		addr, tx, pool, err := lnr_v120.DeployLockReleaseTokenPool(chain.DeployerKey, chain.Client, token, []common.Address{}, rmnProxy, false)
		require.NoError(t, err, "failed to deploy v1.2.0 LockReleaseTokenPool on chain %d", chain.Selector)
		confirm(t, chain, "deploy v1.2.0 LockReleaseTokenPool", func() (*types.Transaction, error) { return tx, nil })
		ramp := []lnr_v120.TokenPoolRampUpdate{{
			Ramp:              proxy,
			Allowed:           true,
			RateLimiterConfig: lnr_v120.RateLimiterConfig{IsEnabled: false, Capacity: big.NewInt(0), Rate: big.NewInt(0)},
		}}
		confirm(t, chain, "applyRampUpdates", func() (*types.Transaction, error) {
			return pool.ApplyRampUpdates(chain.DeployerKey, ramp, ramp)
		})
		confirm(t, chain, "transferOwnership", func() (*types.Transaction, error) {
			return pool.TransferOwnership(chain.DeployerKey, timelock)
		})

		return addr, cciputils.LockReleaseTokenPool
	}

	addr, tx, pool, err := bnm_v120.DeployBurnMintTokenPool(chain.DeployerKey, chain.Client, token, []common.Address{}, rmnProxy)
	require.NoError(t, err, "failed to deploy v1.2.0 BurnMintTokenPool on chain %d", chain.Selector)
	confirm(t, chain, "deploy v1.2.0 BurnMintTokenPool", func() (*types.Transaction, error) { return tx, nil })
	ramp := []bnm_v120.TokenPoolRampUpdate{{
		Ramp:              proxy,
		Allowed:           true,
		RateLimiterConfig: bnm_v120.RateLimiterConfig{IsEnabled: false, Capacity: big.NewInt(0), Rate: big.NewInt(0)},
	}}
	confirm(t, chain, "applyRampUpdates", func() (*types.Transaction, error) {
		return pool.ApplyRampUpdates(chain.DeployerKey, ramp, ramp)
	})
	confirm(t, chain, "transferOwnership", func() (*types.Transaction, error) {
		return pool.TransferOwnership(chain.DeployerKey, timelock)
	})

	return addr, cciputils.BurnMintTokenPool
}

// handPreviousPoolToTimelock completes the previous pool's two-step ownership transfer and, for a
// burn-mint pool, grants it the token's mint and burn roles, in one timelock proposal. The token
// admin role already sits with the timelock once TokenExpansion has deployed the pool, so the grant
// goes through the same token implementation and caller routing that deployment used.
func handPreviousPoolToTimelock(t *testing.T, env *deployment.Environment, chain evm.Chain, lockRelease bool, token, previous, timelock common.Address) {
	t.Helper()

	// acceptOwnership() is the same ConfirmedOwner function on every legacy pool.
	writes := []evm_contract.WriteOutput{{
		ChainSelector: chain.Selector,
		Tx:            mcmsevm.NewTransaction(previous, crypto.Keccak256([]byte("acceptOwnership()"))[:4], big.NewInt(0), "TokenPool", nil),
	}}
	if !lockRelease {
		impl, ok := tokenimpl.Get(bnm_drip_v1_0.ContractType)
		require.True(t, ok, "no token implementation registered for %s", bnm_drip_v1_0.ContractType)
		env.OperationsBundle = operations.NewBundle(env.OperationsBundle.GetContext, env.OperationsBundle.Logger, operations.NewMemoryReporter())
		grants, err := impl.GrantPoolRoles(env.OperationsBundle, chain, token, previous, common.Address{})
		require.NoError(t, err, "failed to grant mint and burn roles to previous pool %s", previous.Hex())
		writes = append(writes, grants...)
	}
	mcms.ExecuteWrites(t, env, "Hand previous pool "+previous.Hex()+" to the timelock", writes)

	// owner() is likewise shared, so one binding reads it for every previous pool type.
	ownable, err := bnm_v140.NewBurnMintTokenPool(previous, chain.Client)
	require.NoError(t, err)
	gotOwner, err := ownable.Owner(&bind.CallOpts{Context: t.Context()})
	require.NoError(t, err)
	require.Equal(t, timelock, gotOwner, "previous pool %s should be owned by the timelock", previous.Hex())
}

// timelockAddress returns the CLL timelock on chain sel, which owns every pool once it is connected.
func timelockAddress(t *testing.T, env *deployment.Environment, sel uint64) common.Address {
	t.Helper()

	ref := ccipdatastore.GetAddressRef(env.DataStore.Addresses().Filter(), sel, cciputils.RBACTimelock, cciputils.Version_1_0_0, cciputils.CLLQualifier)
	require.True(t, common.IsHexAddress(ref.Address), "no CLL timelock found on chain %d", sel)

	return common.HexToAddress(ref.Address)
}

// confirm sends a transaction and requires it to be mined successfully. label names the call in
// failure messages.
func confirm(t *testing.T, chain evm.Chain, label string, send func() (*types.Transaction, error)) {
	t.Helper()

	tx, err := send()
	require.NoError(t, err, "%s on chain %d", label, chain.Selector)
	receipt, err := bind.WaitMined(t.Context(), chain.Client, tx.Hash())
	require.NoError(t, err, "%s on chain %d: failed to wait for tx %s", label, chain.Selector, tx.Hash().Hex())
	require.Equal(t, types.ReceiptStatusSuccessful, receipt.Status, "%s on chain %d: tx %s reverted", label, chain.Selector, tx.Hash().Hex())
}
