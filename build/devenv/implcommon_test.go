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

	batches := buildTokenTransferBatches([]tokenscore.TokenTransferConfig{
		testTokenTransferConfig(aFoo, bFoo),
		testTokenTransferConfig(bFoo, aFoo),
		testTokenTransferConfig(aBar, bBar),
		testTokenTransferConfig(bBar, aBar),
	})
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

	batches := buildTokenTransferBatches([]tokenscore.TokenTransferConfig{
		testTokenTransferConfig(pool1, pool2, pool3),
		testTokenTransferConfig(pool2, pool1, pool3),
		testTokenTransferConfig(pool3, pool1, pool2),
	})
	require.Len(t, batches, 1)
	require.Len(t, batches[0], 3)
	requireNoDuplicateTokenTransferSelectors(t, batches[0])

	for _, cfg := range batches[0] {
		require.Len(t, cfg.RemoteChains, 2)
	}
}

func TestBuildTokenTransferBatchesAsymmetricPoolsSplitByLocalPool(t *testing.T) {
	burn1 := testTokenPoolRef(1, "burn")
	burn2 := testTokenPoolRef(2, "burn")
	burn3 := testTokenPoolRef(3, "burn")
	lock1 := testTokenPoolRef(1, "lock")
	lock2 := testTokenPoolRef(2, "lock")
	lock3 := testTokenPoolRef(3, "lock")

	batches := buildTokenTransferBatches([]tokenscore.TokenTransferConfig{
		testTokenTransferConfig(burn1, lock2, lock3),
		testTokenTransferConfig(burn2, lock1, lock3),
		testTokenTransferConfig(burn3, lock1, lock2),
		testTokenTransferConfig(lock1, burn2, burn3),
		testTokenTransferConfig(lock2, burn1, burn3),
		testTokenTransferConfig(lock3, burn1, burn2),
	})
	require.Len(t, batches, 2)

	seenQualifiers := make(map[string]bool)
	for _, batch := range batches {
		require.Len(t, batch, 3)
		requireNoDuplicateTokenTransferSelectors(t, batch)

		qualifier := batch[0].TokenPoolRef.Qualifier
		seenQualifiers[qualifier] = true
		for _, cfg := range batch {
			require.Equal(t, qualifier, cfg.TokenPoolRef.Qualifier)
			require.Len(t, cfg.RemoteChains, 2)
		}
	}
	require.Equal(t, map[string]bool{"burn": true, "lock": true}, seenQualifiers)
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
