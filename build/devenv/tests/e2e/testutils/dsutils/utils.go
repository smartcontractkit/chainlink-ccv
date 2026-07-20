package dsutils

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
)

// MergeDataStore merges added into env.DataStore and seals the result back onto env.
func MergeDataStore(t *testing.T, env *deployment.Environment, added datastore.DataStore) {
	t.Helper()

	merged := datastore.NewMemoryDataStore()
	require.NoError(t, merged.Merge(env.DataStore))
	require.NoError(t, merged.Merge(added))
	env.DataStore = merged.Seal()
}
