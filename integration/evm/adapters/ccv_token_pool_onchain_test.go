package adapters_test

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/stretchr/testify/require"

	chainsel "github.com/smartcontractkit/chain-selectors"
	cldfevm "github.com/smartcontractkit/chainlink-deployments-framework/chain/evm"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/engine/test/environment"
	cldf_ops "github.com/smartcontractkit/chainlink-deployments-framework/operations"

	taregops "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_5_0/operations/token_admin_registry"
	token_admin_registry "github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/v1_5_0/token_admin_registry"
	factory_burn_mint_erc20 "github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/v1_6_2/factory_burn_mint_erc20"
	burn_mint_token_pool "github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/v2_0_0/burn_mint_token_pool"

	ccvdeploymentadapters "github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
	ccvchangesets "github.com/smartcontractkit/chainlink-ccv/deployment/changesets"
	adapters "github.com/smartcontractkit/chainlink-ccv/integration/evm/adapters"
)

var (
	dummyRMNProxy = common.HexToAddress("0x1111111111111111111111111111111111111111")
	dummyRouter   = common.HexToAddress("0x2222222222222222222222222222222222222222")
	otherPool     = common.HexToAddress("0x00000000000000000000000000000000000A11CE")
	targetPool    = common.HexToAddress("0x00000000000000000000000000000000000BEEF0")
	remoteToken   = common.HexToAddress("0x00000000000000000000000000000000C0FFEE00")
)

func confirmTx(t *testing.T, chain cldfevm.Chain, tx *types.Transaction, err error) {
	t.Helper()
	require.NoError(t, err)
	_, err = chain.Confirm(tx)
	require.NoError(t, err)
}

// deployTokenAndPool deploys a FactoryBurnMintERC20 token and a v2 BurnMint token
// pool for it, owned by the deployer key.
func deployTokenAndPool(t *testing.T, chain cldfevm.Chain) (tokenAddr, poolAddr common.Address, pool *burn_mint_token_pool.BurnMintTokenPool) {
	t.Helper()
	tokenAddr, tx, _, err := factory_burn_mint_erc20.DeployFactoryBurnMintERC20(
		chain.DeployerKey, chain.Client, "Test Token", "TST", 18, big.NewInt(0), big.NewInt(0), chain.DeployerKey.From,
	)
	confirmTx(t, chain, tx, err)

	poolAddr, tx, pool, err = burn_mint_token_pool.DeployBurnMintTokenPool(
		chain.DeployerKey, chain.Client, tokenAddr, 18, common.Address{}, dummyRMNProxy, dummyRouter,
	)
	confirmTx(t, chain, tx, err)
	return tokenAddr, poolAddr, pool
}

// deployRegistryAndSetPool deploys a TokenAdminRegistry and registers poolAddr as
// the pool for tokenAddr (deployer becomes the token administrator).
func deployRegistryAndSetPool(t *testing.T, chain cldfevm.Chain, tokenAddr, poolAddr common.Address) common.Address {
	t.Helper()
	regAddr, tx, reg, err := token_admin_registry.DeployTokenAdminRegistry(chain.DeployerKey, chain.Client)
	confirmTx(t, chain, tx, err)

	tx, err = reg.ProposeAdministrator(chain.DeployerKey, tokenAddr, chain.DeployerKey.From)
	confirmTx(t, chain, tx, err)
	tx, err = reg.AcceptAdminRole(chain.DeployerKey, tokenAddr)
	confirmTx(t, chain, tx, err)
	tx, err = reg.SetPool(chain.DeployerKey, tokenAddr, poolAddr)
	confirmTx(t, chain, tx, err)
	return regAddr
}

// addRemoteChainWithPool makes remoteSel a supported remote chain on pool with
// remotePool configured as a remote pool (rate limits disabled).
func addRemoteChainWithPool(t *testing.T, chain cldfevm.Chain, pool *burn_mint_token_pool.BurnMintTokenPool, remoteSel uint64, remotePool, remoteTok common.Address) {
	t.Helper()
	disabled := burn_mint_token_pool.RateLimiterConfig{IsEnabled: false, Capacity: big.NewInt(0), Rate: big.NewInt(0)}
	tx, err := pool.ApplyChainUpdates(chain.DeployerKey, nil, []burn_mint_token_pool.TokenPoolChainUpdate{{
		RemoteChainSelector:       remoteSel,
		RemotePoolAddresses:       [][]byte{common.LeftPadBytes(remotePool.Bytes(), 32)},
		RemoteTokenAddress:        common.LeftPadBytes(remoteTok.Bytes(), 32),
		OutboundRateLimiterConfig: disabled,
		InboundRateLimiterConfig:  disabled,
	}})
	confirmTx(t, chain, tx, err)
}

// setupPoolWithRemotePools deploys a token + pool with remoteSel supported and both
// otherPool and targetPool configured as remote pools, plus a registry that maps the
// token to the pool. Returns the pool binding, token address and registry address.
func setupPoolWithRemotePools(t *testing.T, chain cldfevm.Chain, remoteSel uint64) (*burn_mint_token_pool.BurnMintTokenPool, common.Address, common.Address) {
	t.Helper()
	tokenAddr, poolAddr, pool := deployTokenAndPool(t, chain)
	addRemoteChainWithPool(t, chain, pool, remoteSel, otherPool, remoteToken)

	tx, err := pool.AddRemotePool(chain.DeployerKey, remoteSel, common.LeftPadBytes(targetPool.Bytes(), 32))
	confirmTx(t, chain, tx, err)

	regAddr := deployRegistryAndSetPool(t, chain, tokenAddr, poolAddr)
	return pool, tokenAddr, regAddr
}

func remotePoolsContain(t *testing.T, pool *burn_mint_token_pool.BurnMintTokenPool, remoteSel uint64, addr common.Address) bool {
	t.Helper()
	pools, err := pool.GetRemotePools(&bind.CallOpts{}, remoteSel)
	require.NoError(t, err)
	target := common.LeftPadBytes(addr.Bytes(), 32)
	for _, p := range pools {
		if bytes.Equal(p, target) {
			return true
		}
	}
	return false
}

// registryRef builds the datastore AddressRef that the adapter uses to resolve a
// chain's TokenAdminRegistry.
func registryRef(chainSelector uint64, regAddr common.Address) datastore.AddressRef {
	return datastore.AddressRef{
		ChainSelector: chainSelector,
		Type:          datastore.ContractType(taregops.ContractType),
		Version:       taregops.Version,
		Address:       regAddr.Hex(),
	}
}

// TestEVMCCVTokenPoolOnchainAdapter_RemoveRemotePool_HappyPath deploys a pool with
// two remote pools configured, removes one via the sequence (explicit address), and
// asserts only the targeted pool is gone.
func TestEVMCCVTokenPoolOnchainAdapter_RemoveRemotePool_HappyPath(t *testing.T) {
	e, err := environment.New(t.Context(),
		environment.WithEVMSimulated(t, []uint64{testChainSelector}),
	)
	require.NoError(t, err)
	chain := e.BlockChains.EVMChains()[testChainSelector]
	remoteSel := chainsel.TEST_90000002.Selector

	pool, tokenAddr, regAddr := setupPoolWithRemotePools(t, chain, remoteSel)

	require.True(t, remotePoolsContain(t, pool, remoteSel, targetPool), "precondition: target pool configured")
	require.True(t, remotePoolsContain(t, pool, remoteSel, otherPool), "precondition: other pool configured")

	adapter := &adapters.EVMCCVTokenPoolOnchainAdapter{}
	_, err = cldf_ops.ExecuteSequence(
		e.OperationsBundle, adapter.RemoveRemotePool(), e.BlockChains,
		ccvdeploymentadapters.RemoveRemotePoolInput{
			ChainSelector:       testChainSelector,
			TokenAddress:        tokenAddr.Hex(),
			RemoteChainSelector: remoteSel,
			RemotePoolAddress:   targetPool.Bytes(),
			RegistryAddress:     regAddr.Hex(),
		},
	)
	require.NoError(t, err)

	require.False(t, remotePoolsContain(t, pool, remoteSel, targetPool), "target pool should be removed")
	require.True(t, remotePoolsContain(t, pool, remoteSel, otherPool), "other pool should remain")
}

// TestEVMCCVTokenPoolOnchainAdapter_RemoveRemotePool_NotConfigured asserts a clear
// error when the requested remote pool is not currently configured.
func TestEVMCCVTokenPoolOnchainAdapter_RemoveRemotePool_NotConfigured(t *testing.T) {
	e, err := environment.New(t.Context(),
		environment.WithEVMSimulated(t, []uint64{testChainSelector}),
	)
	require.NoError(t, err)
	chain := e.BlockChains.EVMChains()[testChainSelector]
	remoteSel := chainsel.TEST_90000002.Selector

	_, tokenAddr, regAddr := setupPoolWithRemotePools(t, chain, remoteSel)

	notConfigured := common.HexToAddress("0x000000000000000000000000000000000000DEAD")
	adapter := &adapters.EVMCCVTokenPoolOnchainAdapter{}
	_, err = cldf_ops.ExecuteSequence(
		e.OperationsBundle, adapter.RemoveRemotePool(), e.BlockChains,
		ccvdeploymentadapters.RemoveRemotePoolInput{
			ChainSelector:       testChainSelector,
			TokenAddress:        tokenAddr.Hex(),
			RemoteChainSelector: remoteSel,
			RemotePoolAddress:   notConfigured.Bytes(),
			RegistryAddress:     regAddr.Hex(),
		},
	)
	require.ErrorContains(t, err, "is not configured")
}

// TestEVMCCVTokenPoolOnchainAdapter_RemoveRemotePool_NoActivePool asserts a clear
// error when the token has no pool registered in the TokenAdminRegistry.
func TestEVMCCVTokenPoolOnchainAdapter_RemoveRemotePool_NoActivePool(t *testing.T) {
	e, err := environment.New(t.Context(),
		environment.WithEVMSimulated(t, []uint64{testChainSelector}),
	)
	require.NoError(t, err)
	chain := e.BlockChains.EVMChains()[testChainSelector]

	regAddr, tx, _, err := token_admin_registry.DeployTokenAdminRegistry(chain.DeployerKey, chain.Client)
	confirmTx(t, chain, tx, err)

	adapter := &adapters.EVMCCVTokenPoolOnchainAdapter{}
	_, err = cldf_ops.ExecuteSequence(
		e.OperationsBundle, adapter.RemoveRemotePool(), e.BlockChains,
		ccvdeploymentadapters.RemoveRemotePoolInput{
			ChainSelector:       testChainSelector,
			TokenAddress:        "0x000000000000000000000000000000000000F00D",
			RemoteChainSelector: chainsel.TEST_90000002.Selector,
			RemotePoolAddress:   targetPool.Bytes(),
			RegistryAddress:     regAddr.Hex(),
		},
	)
	require.ErrorContains(t, err, "no active pool registered")
}

// TestEVMCCVTokenPoolOnchainAdapter_ResolveRemotePoolAddress confirms the adapter
// resolves the token's active pool address from the TokenAdminRegistry (the value a
// counterpart chain stores as this chain's remote pool).
func TestEVMCCVTokenPoolOnchainAdapter_ResolveRemotePoolAddress(t *testing.T) {
	e, err := environment.New(t.Context(),
		environment.WithEVMSimulated(t, []uint64{testChainSelector}),
	)
	require.NoError(t, err)
	chain := e.BlockChains.EVMChains()[testChainSelector]

	tokenAddr, poolAddr, _ := deployTokenAndPool(t, chain)
	regAddr := deployRegistryAndSetPool(t, chain, tokenAddr, poolAddr)

	ds := datastore.NewMemoryDataStore()
	require.NoError(t, ds.Addresses().Add(registryRef(testChainSelector, regAddr)))
	e.DataStore = ds.Seal()

	adapter := &adapters.EVMCCVTokenPoolOnchainAdapter{}
	got, err := adapter.ResolveRemotePoolAddress(*e, testChainSelector, tokenAddr.Hex())
	require.NoError(t, err)
	require.Equal(t, poolAddr.Bytes(), got)
}

// TestEVMCCVTokenPoolOnchainAdapter_RemoveRemotePool_ResolvedFromRemoteToken is the
// full changeset path across two chains: chain A's pool has chain B's pool configured
// as a remote pool; the changeset resolves B's pool address via B's adapter (from the
// remote token) and removes it from A — no hand-specified remote pool address.
func TestEVMCCVTokenPoolOnchainAdapter_RemoveRemotePool_ResolvedFromRemoteToken(t *testing.T) {
	chainA := testChainSelector
	chainB := chainsel.TEST_90000002.Selector

	e, err := environment.New(t.Context(),
		environment.WithEVMSimulated(t, []uint64{chainA, chainB}),
	)
	require.NoError(t, err)
	evmA := e.BlockChains.EVMChains()[chainA]
	evmB := e.BlockChains.EVMChains()[chainB]

	// Chain B: token + pool + registry mapping the token to the pool.
	tokenB, poolBAddr, _ := deployTokenAndPool(t, evmB)
	regB := deployRegistryAndSetPool(t, evmB, tokenB, poolBAddr)

	// Chain A: token + pool that has chain B's pool configured as a remote pool.
	tokenA, poolAAddr, poolA := deployTokenAndPool(t, evmA)
	addRemoteChainWithPool(t, evmA, poolA, chainB, poolBAddr, tokenB)
	regA := deployRegistryAndSetPool(t, evmA, tokenA, poolAAddr)

	require.True(t, remotePoolsContain(t, poolA, chainB, poolBAddr), "precondition: pool B configured as remote on pool A")

	// Only chain B's registry needs to be discoverable via the datastore; chain A's
	// registry is passed as an explicit override on the changeset input.
	ds := datastore.NewMemoryDataStore()
	require.NoError(t, ds.Addresses().Add(registryRef(chainB, regB)))
	e.DataStore = ds.Seal()

	_, err = ccvchangesets.RemoveRemotePool().Apply(*e, ccvchangesets.RemoveRemotePoolInput{
		ChainSelector:       chainA,
		TokenAddress:        tokenA.Hex(),
		RemoteChainSelector: chainB,
		RemoteTokenAddress:  tokenB.Hex(),
		RegistryAddress:     regA.Hex(),
	})
	require.NoError(t, err)

	require.False(t, remotePoolsContain(t, poolA, chainB, poolBAddr),
		"pool B should be removed as a remote pool on pool A after changeset resolution")
}
