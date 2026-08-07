package deploy

import (
	"testing"

	"github.com/stretchr/testify/require"

	chainsel "github.com/smartcontractkit/chain-selectors"

	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/testsetup"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
)

const ufcTestChainSelector = uint64(5009297550715157269)

// TestSeedUltraFastCurseTimelock_MatchesUpstreamRef pins the seeded ref to the shape the EVM chain
// deploy resolves. The lookup matches on chain selector, contract type, version and qualifier, so a
// drift in any of them would not fail here at compile time - it would surface much later as
// "RBACTimelock with qualifier \"UltraFastCurse\" not found" when the devenv starts up.
//
// testsetup.UltraFastCurseMCMSRefs is upstream's own helper for producing this ref, so comparing
// against it keeps the devenv placeholder honest if upstream changes the contract.
func TestSeedUltraFastCurseTimelock_MatchesUpstreamRef(t *testing.T) {
	ds := datastore.NewMemoryDataStore()
	require.NoError(t, SeedUltraFastCurseTimelock(ds, ufcTestChainSelector, chainsel.FamilyEVM))

	got := ds.Seal().Addresses().Filter()
	require.Len(t, got, 1, "expected exactly one seeded address ref")

	want := testsetup.UltraFastCurseMCMSRefs(ufcTestChainSelector)
	require.Len(t, want, 1, "upstream helper shape changed")

	require.Equal(t, want[0].ChainSelector, got[0].ChainSelector)
	require.Equal(t, want[0].Type, got[0].Type)
	require.Equal(t, want[0].Version, got[0].Version)
	require.Equal(t, want[0].Qualifier, got[0].Qualifier)
	require.NotEmpty(t, got[0].Address, "curse admin address must be set")
	require.NotEqual(t, "0x0000000000000000000000000000000000000000", got[0].Address,
		"AuthorizedCallers rejects the zero address")
}

// TestSeedUltraFastCurseTimelock_NonEVMIsNoop covers the families that have no such requirement.
func TestSeedUltraFastCurseTimelock_NonEVMIsNoop(t *testing.T) {
	ds := datastore.NewMemoryDataStore()
	require.NoError(t, SeedUltraFastCurseTimelock(ds, ufcTestChainSelector, chainsel.FamilySolana))
	require.Empty(t, ds.Seal().Addresses().Filter(), "expected no refs seeded for a non-EVM chain")
}
