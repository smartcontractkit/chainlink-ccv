package changesets

import (
	"context"
	"errors"
	"testing"

	"github.com/Masterminds/semver/v3"
	"github.com/stretchr/testify/require"

	chainsel "github.com/smartcontractkit/chain-selectors"
	mcmstypes "github.com/smartcontractkit/mcms/types"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	cldf_chain "github.com/smartcontractkit/chainlink-deployments-framework/chain"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"

	"github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
)

// stubTokenPoolOnchainAdapter implements adapters.TokenPoolOnchainAdapter for tests.
// Its sequence behavior is driven by package-level vars so individual tests can set
// the returned output or an error before running.
type stubTokenPoolOnchainAdapter struct{}

var _ adapters.TokenPoolOnchainAdapter = (*stubTokenPoolOnchainAdapter)(nil)

var (
	stubRemoveRemotePoolCalls   int
	stubRemoveRemotePoolErr     error
	stubRemoveRemotePoolOutput  adapters.RemoveRemotePoolOutput
	stubRemoveRemotePoolGotAddr []byte

	// stubResolveRemotePoolAddr controls what the stub adapter resolves a remote
	// pool to; stubResolveRemotePoolErr forces a resolution error.
	stubResolveRemotePoolAddr  []byte
	stubResolveRemotePoolErr   error
	stubResolveRemotePoolCalls int
	stubResolveRemotePoolToken string
)

var stubRemoveRemotePoolSequence = operations.NewSequence(
	"stub-remove-remote-pool",
	semver.MustParse("1.0.0"),
	"stub sequence used by RemoveRemotePool changeset tests",
	func(_ operations.Bundle, _ cldf_chain.BlockChains, in adapters.RemoveRemotePoolInput) (adapters.RemoveRemotePoolOutput, error) {
		stubRemoveRemotePoolCalls++
		stubRemoveRemotePoolGotAddr = in.RemotePoolAddress
		if stubRemoveRemotePoolErr != nil {
			return adapters.RemoveRemotePoolOutput{}, stubRemoveRemotePoolErr
		}
		return stubRemoveRemotePoolOutput, nil
	},
)

func (s *stubTokenPoolOnchainAdapter) RemoveRemotePool() *operations.Sequence[adapters.RemoveRemotePoolInput, adapters.RemoveRemotePoolOutput, cldf_chain.BlockChains] {
	return stubRemoveRemotePoolSequence
}

func (s *stubTokenPoolOnchainAdapter) ResolveRemotePoolAddress(_ deployment.Environment, _ uint64, tokenAddress string) ([]byte, error) {
	stubResolveRemotePoolCalls++
	stubResolveRemotePoolToken = tokenAddress
	if stubResolveRemotePoolErr != nil {
		return nil, stubResolveRemotePoolErr
	}
	return stubResolveRemotePoolAddr, nil
}

func registerTokenPoolOnchainAdapter() {
	stubRemoveRemotePoolCalls = 0
	stubRemoveRemotePoolErr = nil
	stubRemoveRemotePoolOutput = adapters.RemoveRemotePoolOutput{}
	stubResolveRemotePoolAddr = []byte{0x22, 0x33}
	stubResolveRemotePoolErr = nil
	stubResolveRemotePoolCalls = 0
	stubResolveRemotePoolToken = ""
	stubRemoveRemotePoolGotAddr = nil
	adapters.GetTokenPoolOnchainRegistry().Register(chainsel.FamilyEVM, &stubTokenPoolOnchainAdapter{})
}

const testRemoteTokenAddress = "0x4444444444444444444444444444444444444444"

// validRemoveRemotePoolInput uses the default resolution path: the remote pool is
// resolved from RemoteTokenAddress via the remote chain's adapter.
func validRemoveRemotePoolInput(local, remote uint64) RemoveRemotePoolInput {
	return RemoveRemotePoolInput{
		ChainSelector:       local,
		TokenAddress:        "0x1111111111111111111111111111111111111111",
		RemoteChainSelector: remote,
		RemoteTokenAddress:  testRemoteTokenAddress,
	}
}

func newRemoveRemotePoolApplyEnv(t *testing.T, selectors []uint64) deployment.Environment {
	t.Helper()
	lggr := logger.Test(t)
	return deployment.Environment{
		Logger:      lggr,
		BlockChains: newTestBlockChains(selectors),
		DataStore:   datastore.NewMemoryDataStore().Seal(),
		GetContext:  func() context.Context { return context.Background() },
		OperationsBundle: operations.NewBundle(
			func() context.Context { return context.Background() },
			lggr,
			operations.NewMemoryReporter(),
		),
	}
}

func TestRemoveRemotePool_Validation_MissingChain(t *testing.T) {
	remote := chainsel.TEST_90000002.Selector
	registerTokenPoolOnchainAdapter()
	err := RemoveRemotePool().VerifyPreconditions(newLaneTestEnv([]uint64{remote}), RemoveRemotePoolInput{
		TokenAddress:        "0x1111111111111111111111111111111111111111",
		RemoteChainSelector: remote,
		RemoteTokenAddress:  testRemoteTokenAddress,
	})
	require.ErrorContains(t, err, "chain selector is required")
}

func TestRemoveRemotePool_Validation_MissingToken(t *testing.T) {
	local := chainsel.TEST_90000001.Selector
	remote := chainsel.TEST_90000002.Selector
	registerTokenPoolOnchainAdapter()
	err := RemoveRemotePool().VerifyPreconditions(newLaneTestEnv([]uint64{local, remote}), RemoveRemotePoolInput{
		ChainSelector:       local,
		RemoteChainSelector: remote,
		RemoteTokenAddress:  testRemoteTokenAddress,
	})
	require.ErrorContains(t, err, "token address is required")
}

func TestRemoveRemotePool_Validation_MissingRemoteSelector(t *testing.T) {
	local := chainsel.TEST_90000001.Selector
	registerTokenPoolOnchainAdapter()
	err := RemoveRemotePool().VerifyPreconditions(newLaneTestEnv([]uint64{local}), RemoveRemotePoolInput{
		ChainSelector:      local,
		TokenAddress:       "0x1111111111111111111111111111111111111111",
		RemoteTokenAddress: testRemoteTokenAddress,
	})
	require.ErrorContains(t, err, "remote chain selector is required")
}

func TestRemoveRemotePool_Validation_MissingRemoteIdentifier(t *testing.T) {
	local := chainsel.TEST_90000001.Selector
	remote := chainsel.TEST_90000002.Selector
	registerTokenPoolOnchainAdapter()
	err := RemoveRemotePool().VerifyPreconditions(newLaneTestEnv([]uint64{local, remote}), RemoveRemotePoolInput{
		ChainSelector:       local,
		TokenAddress:        "0x1111111111111111111111111111111111111111",
		RemoteChainSelector: remote,
	})
	require.ErrorContains(t, err, "either remote token address or remote pool address is required")
}

// TestRemoveRemotePool_Validation_OverrideSkipsRemoteEnv confirms that supplying an
// explicit RemotePoolAddress override does not require the remote chain to be in the
// environment (no remote-adapter resolution needed).
func TestRemoveRemotePool_Validation_OverrideSkipsRemoteEnv(t *testing.T) {
	local := chainsel.TEST_90000001.Selector
	remote := chainsel.TEST_90000002.Selector
	registerTokenPoolOnchainAdapter()
	err := RemoveRemotePool().VerifyPreconditions(newLaneTestEnv([]uint64{local}), RemoveRemotePoolInput{
		ChainSelector:       local,
		TokenAddress:        "0x1111111111111111111111111111111111111111",
		RemoteChainSelector: remote,
		RemotePoolAddress:   []byte{0x22, 0x33},
	})
	require.NoError(t, err)
}

func TestRemoveRemotePool_Validation_SameChain(t *testing.T) {
	local := chainsel.TEST_90000001.Selector
	registerTokenPoolOnchainAdapter()
	err := RemoveRemotePool().VerifyPreconditions(newLaneTestEnv([]uint64{local}), validRemoveRemotePoolInput(local, local))
	require.ErrorContains(t, err, "must be different")
}

func TestRemoveRemotePool_Validation_ChainNotInEnv(t *testing.T) {
	local := chainsel.TEST_90000001.Selector
	remote := chainsel.TEST_90000002.Selector
	registerTokenPoolOnchainAdapter()
	err := RemoveRemotePool().VerifyPreconditions(newLaneTestEnv([]uint64{remote}), validRemoveRemotePoolInput(local, remote))
	require.ErrorContains(t, err, "is not available in environment")
}

func TestRemoveRemotePool_Validation_HappyPath(t *testing.T) {
	local := chainsel.TEST_90000001.Selector
	remote := chainsel.TEST_90000002.Selector
	registerTokenPoolOnchainAdapter()
	require.NoError(t, RemoveRemotePool().VerifyPreconditions(
		newLaneTestEnv([]uint64{local, remote}), validRemoveRemotePoolInput(local, remote)))
}

// TestRemoveRemotePool_Apply_DeployerKey exercises the deployer-key path: the
// adapter sequence returns no batch ops (the write was executed directly), so the
// changeset produces a plain output with no proposal.
func TestRemoveRemotePool_Apply_DeployerKey(t *testing.T) {
	local := chainsel.TEST_90000001.Selector
	remote := chainsel.TEST_90000002.Selector
	registerTokenPoolOnchainAdapter()
	env := newRemoveRemotePoolApplyEnv(t, []uint64{local, remote})

	out, err := RemoveRemotePool().Apply(env, validRemoveRemotePoolInput(local, remote))
	require.NoError(t, err)
	require.Equal(t, 1, stubRemoveRemotePoolCalls)
	require.Empty(t, out.MCMSTimelockProposals)
}

// TestRemoveRemotePool_Apply_ResolvesRemotePool confirms the changeset resolves the
// remote pool via the remote chain's adapter (from the remote token) and passes the
// resolved bytes into the local removal sequence.
func TestRemoveRemotePool_Apply_ResolvesRemotePool(t *testing.T) {
	local := chainsel.TEST_90000001.Selector
	remote := chainsel.TEST_90000002.Selector
	registerTokenPoolOnchainAdapter()
	stubResolveRemotePoolAddr = []byte{0xAB, 0xCD, 0xEF}
	env := newRemoveRemotePoolApplyEnv(t, []uint64{local, remote})

	_, err := RemoveRemotePool().Apply(env, validRemoveRemotePoolInput(local, remote))
	require.NoError(t, err)
	require.Equal(t, 1, stubResolveRemotePoolCalls, "remote pool should be resolved via the remote adapter")
	require.Equal(t, testRemoteTokenAddress, stubResolveRemotePoolToken)
	require.Equal(t, []byte{0xAB, 0xCD, 0xEF}, stubRemoveRemotePoolGotAddr, "resolved bytes should flow into the removal sequence")
}

// TestRemoveRemotePool_Apply_ExplicitOverride confirms an explicit RemotePoolAddress
// bypasses remote-adapter resolution and is passed through unchanged.
func TestRemoveRemotePool_Apply_ExplicitOverride(t *testing.T) {
	local := chainsel.TEST_90000001.Selector
	remote := chainsel.TEST_90000002.Selector
	registerTokenPoolOnchainAdapter()
	env := newRemoveRemotePoolApplyEnv(t, []uint64{local, remote})

	_, err := RemoveRemotePool().Apply(env, RemoveRemotePoolInput{
		ChainSelector:       local,
		TokenAddress:        "0x1111111111111111111111111111111111111111",
		RemoteChainSelector: remote,
		RemotePoolAddress:   []byte{0x01, 0x02},
	})
	require.NoError(t, err)
	require.Equal(t, 0, stubResolveRemotePoolCalls, "override should skip remote-adapter resolution")
	require.Equal(t, []byte{0x01, 0x02}, stubRemoveRemotePoolGotAddr)
}

func TestRemoveRemotePool_Apply_ResolveError(t *testing.T) {
	local := chainsel.TEST_90000001.Selector
	remote := chainsel.TEST_90000002.Selector
	registerTokenPoolOnchainAdapter()
	stubResolveRemotePoolErr = errors.New("cannot resolve")
	env := newRemoveRemotePoolApplyEnv(t, []uint64{local, remote})

	_, err := RemoveRemotePool().Apply(env, validRemoveRemotePoolInput(local, remote))
	require.ErrorContains(t, err, "resolve remote pool")
	require.Equal(t, 0, stubRemoveRemotePoolCalls, "removal should not run when resolution fails")
}

func TestRemoveRemotePool_Apply_AdapterError(t *testing.T) {
	local := chainsel.TEST_90000001.Selector
	remote := chainsel.TEST_90000002.Selector
	registerTokenPoolOnchainAdapter()
	stubRemoveRemotePoolErr = errors.New("boom")
	env := newRemoveRemotePoolApplyEnv(t, []uint64{local, remote})

	_, err := RemoveRemotePool().Apply(env, validRemoveRemotePoolInput(local, remote))
	require.ErrorContains(t, err, "RemoveRemotePool failed")
}

// TestRemoveRemotePool_Apply_EmptyBatchOpFiltered confirms an empty batch operation
// returned by the adapter (deployer-key mode) is filtered out and yields no proposal.
func TestRemoveRemotePool_Apply_EmptyBatchOpFiltered(t *testing.T) {
	local := chainsel.TEST_90000001.Selector
	remote := chainsel.TEST_90000002.Selector
	registerTokenPoolOnchainAdapter()
	stubRemoveRemotePoolOutput = adapters.RemoveRemotePoolOutput{
		BatchOps: []mcmstypes.BatchOperation{{
			ChainSelector: mcmstypes.ChainSelector(local),
			Transactions:  nil, // no transactions => filtered
		}},
	}
	env := newRemoveRemotePoolApplyEnv(t, []uint64{local, remote})

	out, err := RemoveRemotePool().Apply(env, validRemoveRemotePoolInput(local, remote))
	require.NoError(t, err)
	require.Empty(t, out.MCMSTimelockProposals)
}
