package chainaccess_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
)

// The declared-chain coverage registry is the chain-agnostic seam between bootstrap's [[chains]]
// declaration and each family's own config: bootstrap groups by family, the family's checker judges.
// These tests pin the mechanics — per-family dispatch, skip-when-unregistered, joined failures —
// with fake families, so no real family config is needed here. Family names are unique per subtest:
// registration is process-global and panics on duplicates.
func TestDeclaredChainCoverageCheckers(t *testing.T) {
	t.Parallel()

	t.Run("a family's checker receives exactly its declared chain IDs", func(t *testing.T) {
		t.Parallel()
		var got []string
		chainaccess.RegisterDeclaredChainCoverageChecker("covtest-dispatch", func(chainIDs []string) error {
			got = chainIDs
			return nil
		})

		err := chainaccess.CheckDeclaredChainCoverage(map[chainaccess.ChainFamily][]string{
			"covtest-dispatch": {"1", "137"},
			"covtest-other":    {"mainnet-beta"}, // no checker registered: skipped
		})
		require.NoError(t, err)
		assert.Equal(t, []string{"1", "137"}, got)
	})

	t.Run("a family without a checker is skipped, even with declared chains", func(t *testing.T) {
		t.Parallel()
		err := chainaccess.CheckDeclaredChainCoverage(map[chainaccess.ChainFamily][]string{
			"covtest-unregistered": {"1"},
		})
		require.NoError(t, err)
	})

	t.Run("every family's failure is returned, joined", func(t *testing.T) {
		t.Parallel()
		chainaccess.RegisterDeclaredChainCoverageChecker("covtest-fail-a", func([]string) error {
			return errors.New("alpha cannot serve its chains")
		})
		chainaccess.RegisterDeclaredChainCoverageChecker("covtest-fail-b", func([]string) error {
			return errors.New("beta cannot serve its chains")
		})

		err := chainaccess.CheckDeclaredChainCoverage(map[chainaccess.ChainFamily][]string{
			"covtest-fail-a": {"1"},
			"covtest-fail-b": {"2"},
		})
		require.ErrorContains(t, err, "family covtest-fail-a: alpha cannot serve its chains")
		require.ErrorContains(t, err, "family covtest-fail-b: beta cannot serve its chains")
	})

	t.Run("duplicate registration panics, like accessor registration", func(t *testing.T) {
		t.Parallel()
		noop := func([]string) error { return nil }
		chainaccess.RegisterDeclaredChainCoverageChecker("covtest-dupe", noop)
		assert.Panics(t, func() {
			chainaccess.RegisterDeclaredChainCoverageChecker("covtest-dupe", noop)
		})
	})
}
