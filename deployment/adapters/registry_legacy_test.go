package adapters

import (
	"testing"

	"github.com/stretchr/testify/require"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
)

type fakeAggregatorAdapter struct{}

func (fakeAggregatorAdapter) ResolveSourceVerifierAddress(datastore.DataStore, uint64, string) (string, error) {
	return "", nil
}

func (fakeAggregatorAdapter) ResolveDestinationVerifierAddress(datastore.DataStore, uint64, string) (string, error) {
	return "", nil
}
func (fakeAggregatorAdapter) GetDeployedChains(datastore.DataStore, string) []uint64 { return nil }

// Registering via the legacy bundled API (the one chainlink-ccip main still uses
// in its chains/evm init.go) must populate the per-type FamilyRegistry that the
// changesets actually read from. This bridge is what keeps ccv working against
// chainlink-ccip main until #2084 lands; see registry_legacy.go.
func TestLegacyRegisterBridgesToPerTypeRegistries(t *testing.T) {
	want := fakeAggregatorAdapter{}
	GetRegistry().Register(chainsel.FamilyEVM, ChainAdapters{Aggregator: want})

	// Ethereum mainnet selector resolves to the EVM family.
	got, err := GetAggregatorRegistry().Get(uint64(5009297550715157269))
	require.NoError(t, err)
	require.Equal(t, want, got)
}
