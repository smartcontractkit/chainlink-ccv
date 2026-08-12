package tokenpool

import (
	"testing"

	"github.com/Masterminds/semver/v3"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccip/deployment/finality"
	"github.com/smartcontractkit/chainlink-ccip/deployment/testhelpers"
	"github.com/smartcontractkit/chainlink-ccip/deployment/tokens"
	"github.com/smartcontractkit/chainlink-ccip/deployment/utils/changesets"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/testutils/dsutils"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/testutils/mcms"
)

var MigrateAllLiquidity = new(uint16(10_000))

type BidirectionalRateLimitPair struct {
	AB *tokens.RateLimiterConfigFloatInput
	BA *tokens.RateLimiterConfigFloatInput
}

type Connection struct {
	RateLimits BidirectionalRateLimitPair
	PoolA      TokenPool
	PoolB      TokenPool
}

type TokenPool interface {
	Selector() uint64
	Decimals() uint8
	Address() string
	Family() string
	Token() string
	Kind() string
}

func DefaultOutboundRateLimit() *tokens.RateLimiterConfigFloatInput {
	return &tokens.RateLimiterConfigFloatInput{IsEnabled: true, Capacity: 100, Rate: 10}
}

func DefaultFinalityConfig() finality.Config {
	return finality.Config{BlockDepth: 1, WaitForSafe: true}
}

func ConnectAll(t *testing.T, env *deployment.Environment, version *semver.Version, connections []Connection) {
	t.Helper()

	for _, conn := range connections {
		ConnectPair(t, env, version, conn)
	}
}

func ConnectPair(t *testing.T, env *deployment.Environment, version *semver.Version, connection Connection) {
	t.Helper()

	env.OperationsBundle = operations.NewBundle(env.OperationsBundle.GetContext, env.OperationsBundle.Logger, operations.NewMemoryReporter())
	out, err := tokens.TokenExpansion().Apply(*env, tokens.TokenExpansionInput{
		ChainAdapterVersion: version,
		MCMS:                mcms.DefaultInput("Connect Pool Pair"),
		TokenExpansionInputPerChain: map[uint64]tokens.TokenExpansionInputPerChain{
			connection.PoolA.Selector(): {
				SkipOwnershipTransfer: false,
				TokenTransferConfig: &tokens.TokenTransferConfig{
					AutoMigrateRemoteChains: true,
					TokenPoolRef:            datastore.AddressRef{Address: connection.PoolA.Address()},
					TokenRef:                datastore.AddressRef{Address: connection.PoolA.Token()},
					RemoteChains: map[uint64]tokens.RemoteChainConfig[*datastore.AddressRef, datastore.AddressRef]{
						connection.PoolB.Selector(): {OutboundRateLimiterConfig: connection.RateLimits.AB},
					},
				},
			},
			connection.PoolB.Selector(): {
				SkipOwnershipTransfer: false,
				TokenTransferConfig: &tokens.TokenTransferConfig{
					AutoMigrateRemoteChains: true,
					TokenPoolRef:            datastore.AddressRef{Address: connection.PoolB.Address()},
					TokenRef:                datastore.AddressRef{Address: connection.PoolB.Token()},
					RemoteChains: map[uint64]tokens.RemoteChainConfig[*datastore.AddressRef, datastore.AddressRef]{
						connection.PoolA.Selector(): {OutboundRateLimiterConfig: connection.RateLimits.BA},
					},
				},
			},
		},
	})
	require.NoError(t, err)
	testhelpers.ProcessTimelockProposals(t, *env, out.MCMSTimelockProposals, true)
	dsutils.MergeDataStore(t, env, out.DataStore.Seal())
}

func MigrateLiquidity(t *testing.T, env *deployment.Environment, oldPool, newPool TokenPool, basisPoints *uint16) {
	t.Helper()

	env.OperationsBundle = operations.NewBundle(env.OperationsBundle.GetContext, env.OperationsBundle.Logger, operations.NewMemoryReporter())
	out, err := tokens.MigrateLockReleasePoolLiquidity(tokens.GetTokenAdapterRegistry(), changesets.GetRegistry()).Apply(*env, tokens.MigrateLockReleasePoolLiquidityConfig{
		Migrations: []tokens.LockReleasePoolMigration{
			{
				ChainSelector: newPool.Selector(),
				OldPoolRef:    datastore.AddressRef{Address: oldPool.Address()},
				NewPoolRef:    datastore.AddressRef{Address: newPool.Address()},
				BasisPoints:   basisPoints,
			},
		},
		MCMS: mcms.DefaultInput("Migrate Liquidity"),
	})
	require.NoError(t, err)
	testhelpers.ProcessTimelockProposals(t, *env, out.MCMSTimelockProposals, true)
}
