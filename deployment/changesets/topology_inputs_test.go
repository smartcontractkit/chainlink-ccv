package changesets

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	chainsel "github.com/smartcontractkit/chain-selectors"

	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
)

func TestCommitteeInputFromTopologyPerFamily_filtersChainConfigs(t *testing.T) {
	t.Parallel()
	committee := ccvdeployment.CommitteeConfig{
		Qualifier: "default",
		ChainConfigs: map[string]ccvdeployment.ChainCommitteeConfig{
			strconv.FormatUint(chainsel.SOLANA_DEVNET.Selector, 10):    {NOPAliases: []string{"nop1"}},
			strconv.FormatUint(chainsel.ETHEREUM_MAINNET.Selector, 10): {NOPAliases: []string{"nop2"}},
		},
	}

	sol := CommitteeInputFromTopologyPerFamily(committee, chainsel.FamilySolana)
	require.Len(t, sol.ChainConfigs, 1)
	_, ok := sol.ChainConfigs[chainsel.SOLANA_DEVNET.Selector]
	require.True(t, ok)

	evm := CommitteeInputFromTopologyPerFamily(committee, chainsel.FamilyEVM)
	require.Len(t, evm.ChainConfigs, 1)
	_, ok = evm.ChainConfigs[chainsel.ETHEREUM_MAINNET.Selector]
	require.True(t, ok)
}
