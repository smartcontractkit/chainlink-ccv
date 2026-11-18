package evm

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/stretchr/testify/require"

	tokenimpl "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/tokens/tokenimpl"
	evmadapters "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_0_0/adapters"
	bnm_drip_v1_0 "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_0_0/operations/burn_mint_erc20_with_drip"
	tarseq "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_5_0/sequences"
	tokenpoolops "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/operations/token_pool"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/burn_mint_multi_token_pool"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/connection_policy_store"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/fee_policy_store"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/pool_config_manager"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/latest/security_policy_store"
	"github.com/smartcontractkit/chainlink-ccip/deployment/testhelpers"
	"github.com/smartcontractkit/chainlink-ccip/deployment/utils/changesets"
	"github.com/smartcontractkit/chainlink-deployments-framework/chain/evm/operations/contract"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	cldf_ops "github.com/smartcontractkit/chainlink-deployments-framework/operations"

	devenvmcms "github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/testutils/mcms"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/testutils/tokenpool"
)

// MTTP is a test-local deployment of the stack on one chain: the pool, its pool config manager
// (PCM) and the connection, fee and security stores the PCM writes to. Tests configure it
// directly with the helpers below because no CLD changeset exists for it yet.
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

// Destination overhead of the default policy, applied to every token.
const (
	defaultDestGasOverhead   = uint32(250_000)
	defaultDestBytesOverhead = uint32(192)
)

// policyKey right-pads a policy name into the bytes32 key the contracts index policies by.
func policyKey(name string) [32]byte {
	var b [32]byte
	copy(b[:], []byte(name))
	return b
}

// evmAddressBytes left-pads an address to 32 bytes, the form the PCM stores remote tokens and pools in.
func evmAddressBytes(addr common.Address) []byte {
	return common.LeftPadBytes(addr.Bytes(), 32)
}

// DeployMTTP deploys the stores, PCM and pool on one chain, authorizes the PCM on the stores,
// grants the deployer CONFIG_ROLE, and creates default policies: zero fee, rate limits off and no
// extra CCVs or hook. Router, RMN proxy and token admin registry must already be deployed.
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
			// No token fee, so the shared transfer helper's exact balance checks hold. Fee behavior is
			// covered by the Foundry tests.
			FeeConfig: pool_config_manager.FeePolicyStoreFeeConfig{},
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

// AddToken configures a token on this pool and switches the token admin registry to the pool. Use
// ConfigureToken and SwitchPool separately when something else, like a legacy pool's trust, must be
// in place before the registry switch.
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

	m.ConfigureToken(t, env, token, decimals, remoteChain, remoteToken, remotePool, useLegacyOnSend, allowLegacyOnReceive)
	m.SwitchPool(t, env, token)
}

// ConfigureToken onboards a token onto this pool and connects it to one remote chain: token profile,
// remote pool, default policies, connection, then mint/burn roles for the pool. It does not touch the
// token admin registry. useLegacyOnSend and allowLegacyOnReceive select the legacy pool data format
// and must be true while the remote is still a legacy pool; use false once the remote is an MTTP.
func (m *MTTP) ConfigureToken(
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

	// Must come last of the config writes: the connection setter validates that the remote pool
	// and the policy assignments above already exist.
	confirm(t, chain, "set inline connection", func() (*types.Transaction, error) {
		return pcm.ApplyInlineConnectionConfigUpdates(chain.DeployerKey, nil, []pool_config_manager.ConnectionPolicyStoreInlineConnectionConfigArgs{{
			LocalToken:          token,
			RemoteChainSelector: remoteChain,
			RemoteToken:         evmAddressBytes(remoteToken),
		}})
	})

	grantMintAndBurnRoles(t, env, m.Selector, token, m.Pool)
}

// SwitchPool points the token admin registry at the MTTP. The TAR admin is the CLL timelock, so
// register with the token expansion's sequence (propose admin, accept, setPool) and execute those
// writes through MCMS. When the token already has a legacy pool, this replaces it in the TAR.
func (m *MTTP) SwitchPool(
	t *testing.T,
	env *deployment.Environment,
	token common.Address,
) {
	t.Helper()

	chain, ok := env.BlockChains.EVMChains()[m.Selector]
	require.True(t, ok, "evm chain not found for selector %d", m.Selector)
	tarAddr, err := (&evmadapters.EVMTokenBase{}).GetTokenAdminRegistryAddress(env.DataStore, m.Selector)
	require.NoError(t, err, "token admin registry on chain %d", m.Selector)
	env.OperationsBundle = cldf_ops.NewBundle(env.OperationsBundle.GetContext, env.OperationsBundle.Logger, cldf_ops.NewMemoryReporter())
	registerReport, err := cldf_ops.ExecuteSequence(env.OperationsBundle, tarseq.RegisterToken, chain, tarseq.RegisterTokenInput{
		ChainSelector:             m.Selector,
		TokenAddress:              token,
		TokenPoolAddress:          m.Pool,
		TokenAdminRegistryAddress: tarAddr,
	})
	require.NoError(t, err, "build register token for %s on chain %d", token.Hex(), m.Selector)
	out, err := changesets.NewOutputBuilder(*env, changesets.GetRegistry()).
		WithBatchOps(registerReport.Output.BatchOps).
		Build(devenvmcms.DefaultInput("Register MTTP pool " + token.Hex()))
	require.NoError(t, err, "build register token proposal for %s", token.Hex())
	testhelpers.ProcessTimelockProposals(t, *env, out.MCMSTimelockProposals, true)
}

// AsTokenPool returns a per-token view of the shared pool, since the transfer helpers expect one
// pool per token.
func (m *MTTP) AsTokenPool(token common.Address, decimals uint8) tokenpool.TokenPool {
	return &TokenPool{
		selector: m.Selector,
		decimals: decimals,
		address:  m.Pool.Hex(),
		token:    token.Hex(),
		kind:     "BurnMintMultiTokenPool",
	}
}

// tokenPolicies builds the args that assign the named policy to a token.
func tokenPolicies(token common.Address, name string) []pool_config_manager.PolicyConfigTokenPolicyArgs {
	return []pool_config_manager.PolicyConfigTokenPolicyArgs{{LocalToken: token, PolicyName: policyKey(name)}}
}

// RemotePool is one entry in a token's inline remote-pool list. AllowLegacy marks whether that pool
// sends legacy 32-byte pool data, so it can be set per pool while a migration is in progress.
type RemotePool struct {
	Address     common.Address
	AllowLegacy bool
}

// SetRemotePools replaces the inline remote-pool record for a token and chain with the given pools.
// Use it to keep an old pool trusted while adding the migrated MTTP, without replaying onboarding.
func (m *MTTP) SetRemotePools(
	t *testing.T,
	env *deployment.Environment,
	token common.Address,
	remoteChain uint64,
	useLegacyOnSend bool,
	remotePools ...RemotePool,
) {
	t.Helper()

	chain, ok := env.BlockChains.EVMChains()[m.Selector]
	require.True(t, ok, "evm chain not found for selector %d", m.Selector)
	pcm, err := pool_config_manager.NewPoolConfigManager(m.PCM, chain.Client)
	require.NoError(t, err, "bind PoolConfigManager on chain %d", m.Selector)

	pools := make([]pool_config_manager.IPoolConfigManagerRemotePool, len(remotePools))
	for i, p := range remotePools {
		pools[i] = pool_config_manager.IPoolConfigManagerRemotePool{
			RemotePoolAddress:            evmAddressBytes(p.Address),
			AllowLegacyPoolDataOnReceive: p.AllowLegacy,
		}
	}
	confirm(t, chain, "set inline remote pools", func() (*types.Transaction, error) {
		return pcm.ApplyInlineRemotePoolConfigUpdates(chain.DeployerKey, nil, []pool_config_manager.ConnectionPolicyStoreInlineRemotePoolConfigArgs{{
			LocalToken:             token,
			RemoteChainSelector:    remoteChain,
			TrustPolicyRemotePools: false,
			RemotePoolConfig: pool_config_manager.ConnectionPolicyStoreRemotePoolConfig{
				UseLegacyPoolDataOnSend: useLegacyOnSend,
				RemotePools:             pools,
			},
		}})
	})
}

// SetRateLimitPolicy sets the default rate-limit policy for the tokens on this pool. Call as OWNER.
func (m *MTTP) SetRateLimitPolicy(
	t *testing.T,
	env *deployment.Environment,
	capacity *big.Int,
	rate *big.Int,
) {
	t.Helper()

	chain, ok := env.BlockChains.EVMChains()[m.Selector]
	require.True(t, ok, "evm chain not found for selector %d", m.Selector)
	pcm, err := pool_config_manager.NewPoolConfigManager(m.PCM, chain.Client)
	require.NoError(t, err, "bind PoolConfigManager on chain %d", m.Selector)
	config := pool_config_manager.RateLimiterConfig{IsEnabled: true, Capacity: capacity, Rate: rate}
	confirm(t, chain, "set rate limit policy default", func() (*types.Transaction, error) {
		return pcm.ApplyRateLimitPolicyConfigUpdates(chain.DeployerKey, nil, nil, []pool_config_manager.SecurityPolicyStoreRateLimitPolicyConfigArgs{{
			PolicyName:          policyKey(policyRateLimit),
			RemoteChainSelector: 0,
			LocalDecimals:       TokenDecimals,
			RateLimitConfig: pool_config_manager.SecurityPolicyStoreRateLimitConfig{
				Outbound: config, Inbound: config, FastFinalityOutbound: config, FastFinalityInbound: config,
			},
		}})
	})
}

// RateLimiterState reads the current rate limit buckets for a token and chain.
func (m *MTTP) RateLimiterState(
	t *testing.T,
	env *deployment.Environment,
	token common.Address,
	remoteChain uint64,
) pool_config_manager.IPoolConfigManagerLaneRateLimiterState {
	t.Helper()

	chain, ok := env.BlockChains.EVMChains()[m.Selector]
	require.True(t, ok, "evm chain not found for selector %d", m.Selector)
	pcm, err := pool_config_manager.NewPoolConfigManager(m.PCM, chain.Client)
	require.NoError(t, err, "bind PoolConfigManager on chain %d", m.Selector)
	states, err := pcm.GetCurrentRateLimiterStateBatch(&bind.CallOpts{Context: t.Context()}, []pool_config_manager.IPoolConfigManagerLaneKey{{
		LocalToken: token, RemoteChainSelector: remoteChain,
	}})
	require.NoError(t, err, "read rate limiter state on chain %d", m.Selector)
	return states[0]
}

// AddLegacyPoolRemotePool makes a legacy pool accept an MTTP as a remote pool, so it can receive
// from the migrated side while it is not migrated itself. The timelock owns the pool, so the write
// goes through MCMS.
func AddLegacyPoolRemotePool(t *testing.T, env *deployment.Environment, sel uint64, poolAddr string, remoteChain uint64, remotePool common.Address) {
	t.Helper()

	chain, ok := env.BlockChains.EVMChains()[sel]
	require.True(t, ok, "evm chain not found for selector %d", sel)

	env.OperationsBundle = cldf_ops.NewBundle(env.OperationsBundle.GetContext, env.OperationsBundle.Logger, cldf_ops.NewMemoryReporter())
	addReport, err := cldf_ops.ExecuteOperation(env.OperationsBundle, tokenpoolops.AddRemotePool, chain, contract.FunctionInput[tokenpoolops.AddRemotePoolArgs]{
		ChainSelector: sel,
		Address:       common.HexToAddress(poolAddr),
		Args: tokenpoolops.AddRemotePoolArgs{
			RemoteChainSelector: remoteChain,
			RemotePoolAddress:   evmAddressBytes(remotePool),
		},
	})
	require.NoError(t, err, "build addRemotePool for legacy pool on chain %d", sel)
	devenvmcms.ExecuteWrites(t, env, "Add remote pool to legacy pool", []contract.WriteOutput{addReport.Output})
}

// grantMintAndBurnRoles lets the pool mint and burn the token. The token admin is the CLL timelock,
// so the grants go through MCMS.
func grantMintAndBurnRoles(t *testing.T, env *deployment.Environment, sel uint64, token, pool common.Address) {
	t.Helper()

	chain, ok := env.BlockChains.EVMChains()[sel]
	require.True(t, ok, "evm chain not found for selector %d", sel)

	impl, ok := tokenimpl.Get(bnm_drip_v1_0.ContractType)
	require.True(t, ok, "no token implementation registered for %s", bnm_drip_v1_0.ContractType)
	env.OperationsBundle = cldf_ops.NewBundle(env.OperationsBundle.GetContext, env.OperationsBundle.Logger, cldf_ops.NewMemoryReporter())
	grants, err := impl.GrantPoolRoles(env.OperationsBundle, chain, token, pool, common.Address{})
	require.NoError(t, err, "build mint/burn role grants for pool on chain %d", sel)
	devenvmcms.ExecuteWrites(t, env, "Grant mint/burn roles to MTTP pool", grants)
}
