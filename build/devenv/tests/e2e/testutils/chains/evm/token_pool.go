package evm

import (
	"testing"

	"github.com/Masterminds/semver/v3"
	chainsel "github.com/smartcontractkit/chain-selectors"
	bnm_drip_v1_0 "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_0_0/operations/burn_mint_erc20_with_drip"
	"github.com/smartcontractkit/chainlink-ccip/deployment/finality"
	"github.com/smartcontractkit/chainlink-ccip/deployment/testhelpers"
	"github.com/smartcontractkit/chainlink-ccip/deployment/tokens"
	cciputils "github.com/smartcontractkit/chainlink-ccip/deployment/utils"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/testutils/dsutils"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/testutils/mcms"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/testutils/tokenpool"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"
	"github.com/stretchr/testify/require"
)

var _ tokenpool.TokenPool = (*TokenPool)(nil)

const (
	DefaultPreMint = uint64(1_000_000)
	TokenDecimals  = uint8(18)
)

type TokenPool struct {
	selector uint64
	decimals uint8
	address  string
	token    string
	kind     string
}

func (tp *TokenPool) Selector() uint64 {
	return tp.selector
}

func (tp *TokenPool) Decimals() uint8 {
	return tp.decimals
}

func (tp *TokenPool) Address() string {
	return tp.address
}

func (tp *TokenPool) Family() string {
	return chainsel.FamilyEVM
}

func (tp *TokenPool) Token() string {
	return tp.token
}

func (tp *TokenPool) Kind() string {
	return tp.kind
}

func DeployTokenPoolV200(t *testing.T, env *deployment.Environment, poolType, qual string, legacyPool tokenpool.TokenPool, finalityConfig finality.Config) tokenpool.TokenPool {
	t.Helper()

	env.OperationsBundle = operations.NewBundle(env.OperationsBundle.GetContext, env.OperationsBundle.Logger, operations.NewMemoryReporter())
	out, err := tokens.TokenExpansion().Apply(*env, tokens.TokenExpansionInput{
		ChainAdapterVersion: cciputils.Version_2_0_0,
		MCMS:                mcms.DefaultInput("Deploy Token Pool " + qual),
		TokenExpansionInputPerChain: map[uint64]tokens.TokenExpansionInputPerChain{
			legacyPool.Selector(): {
				SkipOwnershipTransfer: false,
				TokenPoolVersion:      cciputils.Version_2_0_0,
				DeployTokenPoolInput: &tokens.DeployTokenPoolInput{
					AllowedFinalityConfig: finalityConfig,
					TokenPoolQualifier:    qual,
					TokenRef:              &datastore.AddressRef{Address: legacyPool.Token()},
					PoolType:              poolType,
				},
			},
		},
	})
	require.NoError(t, err)
	testhelpers.ProcessTimelockProposals(t, *env, out.MCMSTimelockProposals, true)
	dsutils.MergeDataStore(t, env, out.DataStore.Seal())

	poolAddr := MustGetDatastoreAddress(
		t,
		env.DataStore,
		datastore.NewAddressRefKey(
			legacyPool.Selector(),
			datastore.ContractType(poolType),
			cciputils.Version_2_0_0,
			qual,
		),
	)

	return &TokenPool{
		selector: legacyPool.Selector(),
		decimals: legacyPool.Decimals(),
		address:  poolAddr.Hex(),
		token:    legacyPool.Token(),
		kind:     poolType,
	}
}

func DeployLockReleaseTokenPoolV161(t *testing.T, env *deployment.Environment, sel uint64, qual string) tokenpool.TokenPool {
	t.Helper()

	return deployTokenPoolWithPresets(t, env, sel, qual, cciputils.LockReleaseTokenPool.String(), cciputils.Version_1_6_1)
}

func DeployBurnMintTokenPoolV161(t *testing.T, env *deployment.Environment, sel uint64, qual string) tokenpool.TokenPool {
	t.Helper()

	return deployTokenPoolWithPresets(t, env, sel, qual, cciputils.BurnMintTokenPool.String(), cciputils.Version_1_6_1)
}

func DeployBurnMintTokenPoolV151(t *testing.T, env *deployment.Environment, sel uint64, qual string) tokenpool.TokenPool {
	t.Helper()

	return deployTokenPoolWithPresets(t, env, sel, qual, cciputils.BurnMintTokenPool.String(), cciputils.Version_1_5_1)
}

func deployTokenPoolWithPresets(t *testing.T, env *deployment.Environment, sel uint64, qual string, poolType string, poolVersion *semver.Version) tokenpool.TokenPool {
	t.Helper()

	env.OperationsBundle = operations.NewBundle(env.OperationsBundle.GetContext, env.OperationsBundle.Logger, operations.NewMemoryReporter())
	out, err := tokens.TokenExpansion().Apply(*env, tokens.TokenExpansionInput{
		ChainAdapterVersion: poolVersion,
		MCMS:                mcms.DefaultInput("Deploy Token Pool " + qual),
		TokenExpansionInputPerChain: map[uint64]tokens.TokenExpansionInputPerChain{
			sel: {
				SkipOwnershipTransfer: false,
				TokenPoolVersion:      poolVersion,
				DeployTokenInput: &tokens.DeployTokenInput{
					Name:          "Migration Token " + qual,
					Decimals:      TokenDecimals,
					Symbol:        qual,
					Type:          bnm_drip_v1_0.ContractType,
					ExternalAdmin: MustDeployerAddress(t, env, sel),
					PreMint:       new(DefaultPreMint),
				},
				DeployTokenPoolInput: &tokens.DeployTokenPoolInput{
					TokenPoolQualifier: qual,
					PoolType:           poolType,
				},
			},
		},
	})
	require.NoError(t, err)
	testhelpers.ProcessTimelockProposals(t, *env, out.MCMSTimelockProposals, true)
	dsutils.MergeDataStore(t, env, out.DataStore.Seal())

	tokenAddr := MustGetDatastoreAddress(
		t,
		env.DataStore,
		datastore.NewAddressRefKey(
			sel,
			datastore.ContractType(bnm_drip_v1_0.ContractType.String()),
			cciputils.Version_1_0_0,
			qual,
		),
	)

	poolAddr := MustGetDatastoreAddress(
		t,
		env.DataStore,
		datastore.NewAddressRefKey(
			sel,
			datastore.ContractType(poolType),
			poolVersion,
			qual,
		),
	)

	return &TokenPool{
		selector: sel,
		decimals: TokenDecimals,
		address:  poolAddr.Hex(),
		token:    tokenAddr.Hex(),
		kind:     poolType,
	}
}
