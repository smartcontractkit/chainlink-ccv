package evm

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/stretchr/testify/require"

	evmadapters "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_0_0/adapters"
	tarops "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_5_0/operations/token_admin_registry"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/burn_mint_multi_token_pool"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/connection_policy_store"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/fee_policy_store"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/pool_config_manager"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/security_policy_store"
	tp_v200 "github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/v2_0_0/token_pool"
	"github.com/smartcontractkit/chainlink-ccip/deployment/testhelpers"
	"github.com/smartcontractkit/chainlink-ccip/deployment/utils/changesets"
	"github.com/smartcontractkit/chainlink-deployments-framework/chain/evm/operations/contract"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	cldf_ops "github.com/smartcontractkit/chainlink-deployments-framework/operations"
	bnm_drip "github.com/smartcontractkit/chainlink-evm/gethwrappers/shared/generated/initial/burn_mint_erc20_with_drip"
	mcms_types "github.com/smartcontractkit/mcms/types"

	devenvmcms "github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/testutils/mcms"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/testutils/tokenpool"
)

// MTTP is a test-local deployment of the multi-token pool stack on one chain: the pool, its pool
// config manager and the three policy stores. Tests configure tokens on it directly instead of
// going through a CLD changeset, which does not exist for MTTP yet.
type MTTP struct {
	Selector        uint64
	Pool            common.Address
	PCM             common.Address
	ConnectionStore common.Address
	FeeStore        common.Address
	SecurityStore   common.Address
}

// Policy names. One per type so a swapped field shows up in assertions.
const (
	policyFee          = "FEE"
	policyRateLimit    = "RATE_LIMIT"
	policyDestOverhead = "DEST_OVERHEAD"
	policySecurity     = "SECURITY"
)

const (
	defaultDestGasOverhead   = uint32(90_000)
	defaultDestBytesOverhead = uint32(192)
)

// policyKey turns a policy name into the bytes32 the contracts use.
func policyKey(name string) [32]byte {
	var b [32]byte
	copy(b[:], []byte(name))
	return b
}

// evmAddressBytes abi-encodes an address the way the pool config manager stores remote tokens and pools.
func evmAddressBytes(addr common.Address) []byte {
	return common.LeftPadBytes(addr.Bytes(), 32)
}

// DeployMTTP deploys a BurnMintMultiTokenPool, its PoolConfigManager and the three policy stores on
// one chain, authorizes the manager on its stores, grants the deployer CONFIG_ROLE, and creates a
// default fee, rate limit, destination overhead and security policy. Call from a test after the
// chain contracts exist (router, RMN proxy, token admin registry).
func DeployMTTP(t *testing.T, env *deployment.Environment, sel uint64) *MTTP {
	t.Helper()

	chain, ok := env.BlockChains.EVMChains()[sel]
	require.True(t, ok, "evm chain not found for selector %d", sel)

	base := &evmadapters.EVMTokenBase{}
	rmnProxy, err := base.GetRMNProxyAddress(env.DataStore, sel)
	require.NoError(t, err, "rmn proxy on chain %d", sel)
	router, err := base.ResolveRouterAddress(env.DataStore, sel, nil)
	require.NoError(t, err, "router on chain %d", sel)
	tar, err := base.GetTokenAdminRegistryAddress(env.DataStore, sel)
	require.NoError(t, err, "token admin registry on chain %d", sel)

	connAddr, connTx, connStore, err := connection_policy_store.DeployConnectionPolicyStore(chain.DeployerKey, chain.Client, nil)
	require.NoError(t, err, "deploy ConnectionPolicyStore on chain %d", sel)
	confirm(t, chain, "deploy ConnectionPolicyStore", func() (*types.Transaction, error) { return connTx, nil })

	feeAddr, feeTx, feeStore, err := fee_policy_store.DeployFeePolicyStore(chain.DeployerKey, chain.Client, nil)
	require.NoError(t, err, "deploy FeePolicyStore on chain %d", sel)
	confirm(t, chain, "deploy FeePolicyStore", func() (*types.Transaction, error) { return feeTx, nil })

	secAddr, secTx, secStore, err := security_policy_store.DeploySecurityPolicyStore(chain.DeployerKey, chain.Client, nil)
	require.NoError(t, err, "deploy SecurityPolicyStore on chain %d", sel)
	confirm(t, chain, "deploy SecurityPolicyStore", func() (*types.Transaction, error) { return secTx, nil })

	pcmAddr, pcmTx, pcm, err := pool_config_manager.DeployPoolConfigManager(
		chain.DeployerKey, chain.Client, tar, connAddr, feeAddr, secAddr, chain.DeployerKey.From,
	)
	require.NoError(t, err, "deploy PoolConfigManager on chain %d", sel)
	confirm(t, chain, "deploy PoolConfigManager", func() (*types.Transaction, error) { return pcmTx, nil })

	confirm(t, chain, "authorize PCM on ConnectionPolicyStore", func() (*types.Transaction, error) {
		return connStore.ApplyAuthorizedCallerUpdates(chain.DeployerKey, connection_policy_store.AuthorizedCallersAuthorizedCallerArgs{
			AddedCallers: []common.Address{pcmAddr},
		})
	})
	confirm(t, chain, "authorize PCM on FeePolicyStore", func() (*types.Transaction, error) {
		return feeStore.ApplyAuthorizedCallerUpdates(chain.DeployerKey, fee_policy_store.AuthorizedCallersAuthorizedCallerArgs{
			AddedCallers: []common.Address{pcmAddr},
		})
	})
	confirm(t, chain, "authorize PCM on SecurityPolicyStore", func() (*types.Transaction, error) {
		return secStore.ApplyAuthorizedCallerUpdates(chain.DeployerKey, security_policy_store.AuthorizedCallersAuthorizedCallerArgs{
			AddedCallers: []common.Address{pcmAddr},
		})
	})

	configRole, err := pcm.CONFIGROLE(&bind.CallOpts{Context: t.Context()})
	require.NoError(t, err, "read CONFIG_ROLE on chain %d", sel)
	confirm(t, chain, "grant CONFIG_ROLE", func() (*types.Transaction, error) {
		return pcm.GrantRole(chain.DeployerKey, configRole, chain.DeployerKey.From)
	})

	poolAddr, poolTx, _, err := burn_mint_multi_token_pool.DeployBurnMintMultiTokenPool(
		chain.DeployerKey, chain.Client, rmnProxy, router, pcmAddr,
	)
	require.NoError(t, err, "deploy BurnMintMultiTokenPool on chain %d", sel)
	confirm(t, chain, "deploy BurnMintMultiTokenPool", func() (*types.Transaction, error) { return poolTx, nil })

	confirm(t, chain, "set fee policy default", func() (*types.Transaction, error) {
		return pcm.ApplyFeePolicyConfigUpdates(chain.DeployerKey, nil, nil, []pool_config_manager.FeePolicyStoreFeePolicyConfigArgs{{
			PolicyName:          policyKey(policyFee),
			RemoteChainSelector: 0,
			FeeConfig: pool_config_manager.FeePolicyStoreFeeConfig{
				FinalityTransferFeeBps:     100,
				FastFinalityTransferFeeBps: 200,
			},
		}})
	})
	confirm(t, chain, "set rate limit policy default", func() (*types.Transaction, error) {
		disabled := pool_config_manager.RateLimiterConfig{IsEnabled: false, Capacity: big.NewInt(0), Rate: big.NewInt(0)}
		return pcm.ApplyRateLimitPolicyConfigUpdates(chain.DeployerKey, nil, nil, []pool_config_manager.SecurityPolicyStoreRateLimitPolicyConfigArgs{{
			PolicyName:          policyKey(policyRateLimit),
			RemoteChainSelector: 0,
			LocalDecimals:       18,
			RateLimitConfig: pool_config_manager.SecurityPolicyStoreRateLimitConfig{
				Outbound: disabled, Inbound: disabled, FastFinalityOutbound: disabled, FastFinalityInbound: disabled,
			},
		}})
	})
	confirm(t, chain, "set dest overhead policy default", func() (*types.Transaction, error) {
		return pcm.ApplyDestOverheadPolicyConfigUpdates(chain.DeployerKey, nil, nil, []pool_config_manager.FeePolicyStoreDestOverheadPolicyConfigArgs{{
			PolicyName:          policyKey(policyDestOverhead),
			RemoteChainSelector: 0,
			DestOverheadConfig: pool_config_manager.FeePolicyStoreDestOverheadConfig{
				DestGasOverhead: defaultDestGasOverhead, DestBytesOverhead: defaultDestBytesOverhead,
			},
		}})
	})
	confirm(t, chain, "set security policy default", func() (*types.Transaction, error) {
		return pcm.ApplySecurityPolicyConfigUpdates(chain.DeployerKey, nil, nil, []pool_config_manager.SecurityPolicyStoreSecurityPolicyConfigArgs{{
			PolicyName:          policyKey(policySecurity),
			RemoteChainSelector: 0,
			SecurityConfig: pool_config_manager.SecurityPolicyStoreSecurityConfig{
				OutboundCCVs: []common.Address{}, InboundCCVs: []common.Address{}, Hook: common.Address{},
			},
		}})
	})

	return &MTTP{
		Selector:        sel,
		Pool:            poolAddr,
		PCM:             pcmAddr,
		ConnectionStore: connAddr,
		FeeStore:        feeAddr,
		SecurityStore:   secAddr,
	}
}

// AddToken registers a token on this MTTP stack and wires it to a remote chain: it sets the token
// profile, an inline connection and remote pool, assigns the default policies, gives the pool the
// token's mint/burn roles, and points the token admin registry at the pool.
func (m *MTTP) AddToken(
	t *testing.T,
	env *deployment.Environment,
	token common.Address,
	decimals uint8,
	remoteChain uint64,
	remoteToken common.Address,
	remotePool common.Address,
	useLegacyOnSend bool,
	allowLegacyOnReceive bool,
) {
	t.Helper()

	chain, ok := env.BlockChains.EVMChains()[m.Selector]
	require.True(t, ok, "evm chain not found for selector %d", m.Selector)
	pcm, err := pool_config_manager.NewPoolConfigManager(m.PCM, chain.Client)
	require.NoError(t, err, "bind PoolConfigManager on chain %d", m.Selector)

	confirm(t, chain, "set token profile", func() (*types.Transaction, error) {
		return pcm.ApplyTokenProfileUpdates(chain.DeployerKey, nil, []pool_config_manager.PolicyConfigTokenProfileArgs{{
			LocalToken:            token,
			LocalDecimals:         decimals,
			LockOrBurnFlavor:      0, // Burn
			AllowedFinalityConfig: [4]byte{},
		}})
	})

	confirm(t, chain, "set inline remote pool", func() (*types.Transaction, error) {
		return pcm.ApplyInlineRemotePoolConfigUpdates(chain.DeployerKey, nil, []pool_config_manager.ConnectionPolicyStoreInlineRemotePoolConfigArgs{{
			LocalToken:             token,
			RemoteChainSelector:    remoteChain,
			TrustPolicyRemotePools: false,
			RemotePoolConfig: pool_config_manager.ConnectionPolicyStoreRemotePoolConfig{
				UseLegacyPoolDataOnSend: useLegacyOnSend,
				RemotePools: []pool_config_manager.IPoolConfigManagerRemotePool{{
					RemotePoolAddress:            evmAddressBytes(remotePool),
					AllowLegacyPoolDataOnReceive: allowLegacyOnReceive,
				}},
			},
		}})
	})

	for _, p := range []struct {
		label string
		apply func() (*types.Transaction, error)
	}{
		{"assign rate limit policy", func() (*types.Transaction, error) {
			return pcm.ApplyTokenRateLimitPolicyUpdates(chain.DeployerKey, tokenPolicies(token, policyRateLimit))
		}},
		{"assign fee policy", func() (*types.Transaction, error) {
			return pcm.ApplyTokenFeePolicyUpdates(chain.DeployerKey, tokenPolicies(token, policyFee))
		}},
		{"assign dest overhead policy", func() (*types.Transaction, error) {
			return pcm.ApplyTokenDestOverheadPolicyUpdates(chain.DeployerKey, tokenPolicies(token, policyDestOverhead))
		}},
		{"assign security policy", func() (*types.Transaction, error) {
			return pcm.ApplyTokenSecurityPolicyUpdates(chain.DeployerKey, tokenPolicies(token, policySecurity))
		}},
	} {
		confirm(t, chain, p.label, p.apply)
	}

	// The connection setter runs checkLaneRecords, which needs the remote pool record and the fee
	// and security records to already exist, so it comes after both.
	confirm(t, chain, "set inline connection", func() (*types.Transaction, error) {
		return pcm.ApplyInlineConnectionConfigUpdates(chain.DeployerKey, nil, []pool_config_manager.ConnectionPolicyStoreInlineConnectionConfigArgs{{
			LocalToken:          token,
			RemoteChainSelector: remoteChain,
			RemoteToken:         evmAddressBytes(remoteToken),
		}})
	})

	// The token's TAR admin is the CLL timelock, so the pool change goes through MCMS.
	tarAddr, err := (&evmadapters.EVMTokenBase{}).GetTokenAdminRegistryAddress(env.DataStore, m.Selector)
	require.NoError(t, err, "token admin registry on chain %d", m.Selector)
	env.OperationsBundle = cldf_ops.NewBundle(env.OperationsBundle.GetContext, env.OperationsBundle.Logger, cldf_ops.NewMemoryReporter())
	setPoolReport, err := cldf_ops.ExecuteOperation(env.OperationsBundle, tarops.SetPool, chain, contract.FunctionInput[tarops.SetPoolArgs]{
		ChainSelector: m.Selector,
		Address:       tarAddr,
		Args:          tarops.SetPoolArgs{TokenAddress: token, TokenPoolAddress: m.Pool},
	})
	require.NoError(t, err, "build setPool for token %s on chain %d", token.Hex(), m.Selector)
	batchOp, err := contract.NewBatchOperationFromWrites([]contract.WriteOutput{setPoolReport.Output})
	require.NoError(t, err, "build setPool batch op for token %s", token.Hex())
	out, err := changesets.NewOutputBuilder(*env, changesets.GetRegistry()).
		WithBatchOps([]mcms_types.BatchOperation{batchOp}).
		Build(devenvmcms.DefaultInput("Set MTTP pool in TAR " + token.Hex()))
	require.NoError(t, err, "build setPool timelock proposal for token %s", token.Hex())
	testhelpers.ProcessTimelockProposals(t, *env, out.MCMSTimelockProposals, true)

	grantMintAndBurnRoles(t, env, m.Selector, token, m.Pool)
}

// AsTokenPool exposes the stack as a token pool so the shared transfer helpers can use it.
func (m *MTTP) AsTokenPool(token common.Address, decimals uint8) tokenpool.TokenPool {
	return &TokenPool{
		selector: m.Selector,
		decimals: decimals,
		address:  m.Pool.Hex(),
		token:    token.Hex(),
		kind:     "BurnMintMultiTokenPool",
	}
}

func tokenPolicies(token common.Address, name string) []pool_config_manager.PolicyConfigTokenPolicyArgs {
	return []pool_config_manager.PolicyConfigTokenPolicyArgs{{LocalToken: token, PolicyName: policyKey(name)}}
}

// AddLegacyPoolRemotePool adds a remote pool to an existing single-token pool, so a legacy pool
// trusts a migrated MTTP on the other side during the canary phase.
func AddLegacyPoolRemotePool(t *testing.T, env *deployment.Environment, sel uint64, poolAddr string, remoteChain uint64, remotePool common.Address) {
	t.Helper()

	chain, ok := env.BlockChains.EVMChains()[sel]
	require.True(t, ok, "evm chain not found for selector %d", sel)

	pool, err := tp_v200.NewTokenPool(common.HexToAddress(poolAddr), chain.Client)
	require.NoError(t, err, "bind legacy pool on chain %d", sel)
	confirm(t, chain, "legacy pool add remote pool", func() (*types.Transaction, error) {
		return pool.AddRemotePool(chain.DeployerKey, remoteChain, evmAddressBytes(remotePool))
	})
}

// grantMintAndBurnRoles gives the pool the token's mint and burn roles. The deployer holds the
// token's burn-mint admin role, which the call needs.
func grantMintAndBurnRoles(t *testing.T, env *deployment.Environment, sel uint64, token, pool common.Address) {
	t.Helper()

	chain, ok := env.BlockChains.EVMChains()[sel]
	require.True(t, ok, "evm chain not found for selector %d", sel)

	tok, err := bnm_drip.NewBurnMintERC20(token, chain.Client)
	require.NoError(t, err, "bind token on chain %d", sel)
	confirm(t, chain, "grant mint/burn roles to pool", func() (*types.Transaction, error) {
		return tok.GrantMintAndBurnRoles(chain.DeployerKey, pool)
	})
}
