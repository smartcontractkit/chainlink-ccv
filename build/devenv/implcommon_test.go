package ccv

import (
	"testing"

	"github.com/Masterminds/semver/v3"
	"github.com/stretchr/testify/require"

	tokenscore "github.com/smartcontractkit/chainlink-ccip/deployment/tokens"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
)

func TestBuildTokenTransferBatchesMultipleTokensSameSelectors(t *testing.T) {
	aFoo := testTokenPoolRef(1, "foo")
	bFoo := testTokenPoolRef(2, "foo")
	aBar := testTokenPoolRef(1, "bar")
	bBar := testTokenPoolRef(2, "bar")

	batches, err := buildTokenTransferBatches([]tokenscore.TokenTransferConfig{
		testTokenTransferConfig(aFoo, bFoo),
		testTokenTransferConfig(bFoo, aFoo),
		testTokenTransferConfig(aBar, bBar),
		testTokenTransferConfig(bBar, aBar),
	})
	require.NoError(t, err)
	require.Len(t, batches, 2)

	for _, batch := range batches {
		require.Len(t, batch, 2)
		requireNoDuplicateTokenTransferSelectors(t, batch)

		qualifier := batch[0].TokenPoolRef.Qualifier
		for _, cfg := range batch {
			require.Equal(t, qualifier, cfg.TokenPoolRef.Qualifier)
		}
	}
}

func TestBuildTokenTransferBatchesSymmetricTokenAcrossAllLanes(t *testing.T) {
	pool1 := testTokenPoolRef(1, "burn")
	pool2 := testTokenPoolRef(2, "burn")
	pool3 := testTokenPoolRef(3, "burn")

	batches, err := buildTokenTransferBatches([]tokenscore.TokenTransferConfig{
		testTokenTransferConfig(pool1, pool2, pool3),
		testTokenTransferConfig(pool2, pool1, pool3),
		testTokenTransferConfig(pool3, pool1, pool2),
	})
	require.NoError(t, err)
	require.Len(t, batches, 1)

	require.Len(t, batches[0], 3)
	requireNoDuplicateTokenTransferSelectors(t, batches[0])
	for _, cfg := range batches[0] {
		require.Len(t, cfg.RemoteChains, 2)
		requireBatchContainsRemoteSelectors(t, batches[0], cfg)
	}
}

func TestBuildTokenTransferBatchesAsymmetricPoolsSplitByLocalPoolInstance(t *testing.T) {
	burn1 := testTokenPoolRef(1, "TEST (burn, lock)::burn")
	burn2 := testTokenPoolRef(2, "TEST (burn, lock)::burn")
	burn3 := testTokenPoolRef(3, "TEST (burn, lock)::burn")
	lock1 := testTokenPoolRef(1, "TEST (burn, lock)::lock")
	lock2 := testTokenPoolRef(2, "TEST (burn, lock)::lock")
	lock3 := testTokenPoolRef(3, "TEST (burn, lock)::lock")

	batches, err := buildTokenTransferBatches([]tokenscore.TokenTransferConfig{
		testTokenTransferConfig(burn1, lock2, lock3),
		testTokenTransferConfig(burn2, lock1, lock3),
		testTokenTransferConfig(burn3, lock1, lock2),
		testTokenTransferConfig(lock1, burn2, burn3),
		testTokenTransferConfig(lock2, burn1, burn3),
		testTokenTransferConfig(lock3, burn1, burn2),
	})
	require.NoError(t, err)
	require.Len(t, batches, 2)

	for _, batch := range batches {
		require.Len(t, batch, 3)
		requireNoDuplicateTokenTransferSelectors(t, batch)
		qualifier := batch[0].TokenPoolRef.Qualifier
		for _, cfg := range batch {
			require.Equal(t, qualifier, cfg.TokenPoolRef.Qualifier)
			require.Len(t, cfg.RemoteChains, 2)
			requireBatchContainsRemoteSelectors(t, batch, cfg)
		}
	}
}

// TestBuildTokenTransferBatchesCrossTypePools verifies that an EVM
// BurnMintTokenPool and a Canton LockReleaseTokenPool for the same token pair
// land in the same batch even though their pool types differ.
func TestBuildTokenTransferBatchesCrossTypePools(t *testing.T) {
	const pairQualifier = "TEST (BurnMintTokenPool 2.0.0 [default], LockReleaseTokenPool 2.0.0 [default])"
	evmPool := datastore.AddressRef{
		ChainSelector: 1,
		Type:          datastore.ContractType("BurnMintTokenPool"),
		Version:       semver.MustParse("2.0.0"),
		Qualifier:     pairQualifier + "::BurnMintTokenPool 2.0.0 [default]",
	}
	cantonPool := datastore.AddressRef{
		ChainSelector: 2,
		Type:          datastore.ContractType("LockReleaseTokenPool"),
		Version:       semver.MustParse("2.0.0"),
		Qualifier:     pairQualifier + "::LockReleaseTokenPool 2.0.0 [default]",
	}

	batches, err := buildTokenTransferBatches([]tokenscore.TokenTransferConfig{
		testTokenTransferConfig(evmPool, cantonPool),
		testTokenTransferConfig(cantonPool, evmPool),
	})
	require.NoError(t, err)
	require.Len(t, batches, 1)
	require.Len(t, batches[0], 2)
	requireNoDuplicateTokenTransferSelectors(t, batches[0])
	requireReciprocalTokenTransferBatch(t, batches[0])
}

func TestBuildTokenTransferBatchesCrossTypePoolsSupportsDirectionalQualifiers(t *testing.T) {
	evmPool := datastore.AddressRef{
		ChainSelector: 1,
		Type:          datastore.ContractType("BurnMintTokenPool"),
		Version:       semver.MustParse("2.0.0"),
		Qualifier:     "TEST (BurnMintTokenPool 2.0.0 [default] to LockReleaseTokenPool 2.0.0 [default])",
	}
	cantonPool := datastore.AddressRef{
		ChainSelector: 2,
		Type:          datastore.ContractType("LockReleaseTokenPool"),
		Version:       semver.MustParse("2.0.0"),
		Qualifier:     "TEST (LockReleaseTokenPool 2.0.0 [default] to BurnMintTokenPool 2.0.0 [default])",
	}

	batches, err := buildTokenTransferBatches([]tokenscore.TokenTransferConfig{
		testTokenTransferConfig(evmPool, cantonPool),
		testTokenTransferConfig(cantonPool, evmPool),
	})

	require.NoError(t, err)
	require.Len(t, batches, 1)
	require.Len(t, batches[0], 2)
	requireNoDuplicateTokenTransferSelectors(t, batches[0])
	requireReciprocalTokenTransferBatch(t, batches[0])
}

func TestBuildTokenTransferBatchesCrossTypePoolsSplitDuplicateSelectors(t *testing.T) {
	const pairQualifier = "TEST (BurnMintTokenPool 2.0.0 [default], LockReleaseTokenPool 2.0.0 [default])"
	burn1 := datastore.AddressRef{
		ChainSelector: 1,
		Type:          datastore.ContractType("BurnMintTokenPool"),
		Version:       semver.MustParse("2.0.0"),
		Qualifier:     pairQualifier + "::BurnMintTokenPool 2.0.0 [default]",
	}
	lock1 := datastore.AddressRef{
		ChainSelector: 1,
		Type:          datastore.ContractType("LockReleaseTokenPool"),
		Version:       semver.MustParse("2.0.0"),
		Qualifier:     pairQualifier + "::LockReleaseTokenPool 2.0.0 [default]",
	}
	burn2 := datastore.AddressRef{
		ChainSelector: 2,
		Type:          datastore.ContractType("BurnMintTokenPool"),
		Version:       semver.MustParse("2.0.0"),
		Qualifier:     pairQualifier + "::BurnMintTokenPool 2.0.0 [default]",
	}
	lock2 := datastore.AddressRef{
		ChainSelector: 2,
		Type:          datastore.ContractType("LockReleaseTokenPool"),
		Version:       semver.MustParse("2.0.0"),
		Qualifier:     pairQualifier + "::LockReleaseTokenPool 2.0.0 [default]",
	}

	batches, err := buildTokenTransferBatches([]tokenscore.TokenTransferConfig{
		testTokenTransferConfig(burn1, lock2),
		testTokenTransferConfig(lock1, burn2),
		testTokenTransferConfig(burn2, lock1),
		testTokenTransferConfig(lock2, burn1),
	})

	require.NoError(t, err)
	require.Len(t, batches, 2)
	for _, batch := range batches {
		require.Len(t, batch, 2)
		requireNoDuplicateTokenTransferSelectors(t, batch)
		for _, cfg := range batch {
			require.Len(t, cfg.RemoteChains, 1)
			requireBatchContainsRemoteSelectors(t, batch, cfg)
		}
	}
}

// TestBuildTokenTransferBatchesSameTypeVersionsSplitByLocalVersion verifies that
// BurnMint 1.6.1 <-> BurnMint 2.0.0 configs stay in separate batches. Both pool
// versions exist on each chain, and the upstream changeset can only take one
// config per selector in a call.
func TestBuildTokenTransferBatchesSameTypeVersionsSplitByLocalVersion(t *testing.T) {
	const pairQualifier = "TEST (BurnMintTokenPool 1.6.1 [], BurnMintTokenPool 2.0.0 [default])"
	chain1v161 := datastore.AddressRef{
		ChainSelector: 1,
		Type:          datastore.ContractType("BurnMintTokenPool"),
		Version:       semver.MustParse("1.6.1"),
		Qualifier:     pairQualifier + "::BurnMintTokenPool 1.6.1 []",
	}
	chain2v200 := datastore.AddressRef{
		ChainSelector: 2,
		Type:          datastore.ContractType("BurnMintTokenPool"),
		Version:       semver.MustParse("2.0.0"),
		Qualifier:     pairQualifier + "::BurnMintTokenPool 2.0.0 [default]",
	}
	chain1v200 := datastore.AddressRef{
		ChainSelector: 1,
		Type:          datastore.ContractType("BurnMintTokenPool"),
		Version:       semver.MustParse("2.0.0"),
		Qualifier:     pairQualifier + "::BurnMintTokenPool 2.0.0 [default]",
	}
	chain2v161 := datastore.AddressRef{
		ChainSelector: 2,
		Type:          datastore.ContractType("BurnMintTokenPool"),
		Version:       semver.MustParse("1.6.1"),
		Qualifier:     pairQualifier + "::BurnMintTokenPool 1.6.1 []",
	}

	batches, err := buildTokenTransferBatches([]tokenscore.TokenTransferConfig{
		testTokenTransferConfig(chain1v161, chain2v200),
		testTokenTransferConfig(chain2v161, chain1v200),
		testTokenTransferConfig(chain1v200, chain2v161),
		testTokenTransferConfig(chain2v200, chain1v161),
	})
	require.NoError(t, err)
	require.Len(t, batches, 2)
	for _, batch := range batches {
		require.Len(t, batch, 2)
		requireNoDuplicateTokenTransferSelectors(t, batch)
		for _, cfg := range batch {
			require.Len(t, cfg.RemoteChains, 1)
			requireBatchContainsRemoteSelectors(t, batch, cfg)
		}
	}
}

func testTokenPoolRef(selector uint64, qualifier string) datastore.AddressRef {
	return datastore.AddressRef{
		ChainSelector: selector,
		Type:          datastore.ContractType("TokenPool"),
		Version:       semver.MustParse("1.0.0"),
		Qualifier:     qualifier,
	}
}

func testTokenTransferConfig(local datastore.AddressRef, remotes ...datastore.AddressRef) tokenscore.TokenTransferConfig {
	remoteChains := make(map[uint64]tokenscore.RemoteChainConfig[*datastore.AddressRef, datastore.AddressRef], len(remotes))
	for _, remote := range remotes {
		remoteChains[remote.ChainSelector] = tokenscore.RemoteChainConfig[*datastore.AddressRef, datastore.AddressRef]{
			RemotePool: &remote,
		}
	}
	return tokenscore.TokenTransferConfig{
		ChainSelector: local.ChainSelector,
		TokenPoolRef:  local,
		RemoteChains:  remoteChains,
	}
}

func requireNoDuplicateTokenTransferSelectors(t *testing.T, batch []tokenscore.TokenTransferConfig) {
	t.Helper()

	seen := make(map[uint64]bool, len(batch))
	for _, cfg := range batch {
		require.False(t, seen[cfg.ChainSelector], "duplicate selector %d in token transfer batch", cfg.ChainSelector)
		seen[cfg.ChainSelector] = true
	}
}

func requireReciprocalTokenTransferBatch(t *testing.T, batch []tokenscore.TokenTransferConfig) {
	t.Helper()

	bySelector := make(map[uint64]tokenscore.TokenTransferConfig, len(batch))
	for _, cfg := range batch {
		bySelector[cfg.ChainSelector] = cfg
	}
	for _, cfg := range batch {
		for remoteSelector, remoteCfg := range cfg.RemoteChains {
			require.NotNil(t, remoteCfg.RemotePool)
			counterpart, ok := bySelector[remoteSelector]
			require.True(t, ok, "batch is missing remote selector %d", remoteSelector)
			require.Equal(t, tokenTransferRefKey(counterpart.TokenPoolRef), tokenTransferRefKey(*remoteCfg.RemotePool))
		}
	}
}

func requireBatchContainsRemoteSelectors(t *testing.T, batch []tokenscore.TokenTransferConfig, cfg tokenscore.TokenTransferConfig) {
	t.Helper()

	selectors := make(map[uint64]struct{}, len(batch))
	for _, batchCfg := range batch {
		selectors[batchCfg.ChainSelector] = struct{}{}
	}
	for remoteSelector := range cfg.RemoteChains {
		_, ok := selectors[remoteSelector]
		require.True(t, ok, "batch is missing remote selector %d", remoteSelector)
	}
}
