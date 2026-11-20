package ccv

import (
	"testing"

	"github.com/stretchr/testify/require"

	ccvchangesets "github.com/smartcontractkit/chainlink-ccv/deployment/changesets"
)

func TestDiffExecutorPool_SourceOnlyChains(t *testing.T) {
	topo := ccvchangesets.ExecutorPoolInput{SourceOnlyChains: []uint64{2, 1}}
	state := ccvchangesets.ExecutorPoolInput{SourceOnlyChains: []uint64{1, 2}}
	require.Empty(t, diffExecutorPool(topo, state))

	state.SourceOnlyChains = []uint64{1, 3}
	diffs := diffExecutorPool(topo, state)
	require.Len(t, diffs, 1)
	require.Contains(t, diffs[0], "sourceOnlyChains: topology=[1 2] state=[1 3]")
}
