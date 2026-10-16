package e2e

import (
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	_ "github.com/lib/pq"

	ccv "github.com/smartcontractkit/chainlink-ccv/build/devenv"
)

// requireLogPollerSourceReaderInUse fails the test when CL nodes are running but none of them has a
// verifier filter registered in its log poller. Only LogPollerSourceReader registers one, so a
// missing filter means the verifier fell back to the RPC reader. No-op outside CL mode.
func requireLogPollerSourceReaderInUse(t *testing.T, in *ccv.Cfg) {
	t.Helper()

	var dbURLs []string
	for _, nodeSet := range in.NodeSets {
		if nodeSet == nil || nodeSet.Out == nil {
			continue
		}
		for _, clNode := range nodeSet.Out.CLNodes {
			if clNode != nil && clNode.PostgreSQL != nil && clNode.PostgreSQL.Url != "" {
				dbURLs = append(dbURLs, clNode.PostgreSQL.Url)
			}
		}
	}
	if len(dbURLs) == 0 {
		t.Log("no CL nodes in this environment, skipping log poller source reader check")
		return
	}

	// Filters are registered in the background after the verifier starts, so allow for that.
	require.Eventuallyf(t, func() bool {
		total := 0
		for _, url := range dbURLs {
			n, err := countVerifierLogPollerFilters(url)
			if err != nil {
				t.Logf("counting log poller filters: %v", err)
				return false
			}
			t.Logf("CL node %s has %d ccv-verifier log poller filter(s)", url, n)
			total += n
		}
		return total > 0
	}, 30*time.Second, time.Second,
		"no ccv-verifier filter in any CL node's evm.log_poller_filters; "+
			"the verifier is not reading source logs through the log poller")
}

func countVerifierLogPollerFilters(dbURL string) (int, error) {
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		return 0, err
	}
	defer db.Close()

	var n int
	err = db.QueryRow(`SELECT COUNT(*) FROM evm.log_poller_filters WHERE name LIKE 'ccv-verifier - %'`).Scan(&n)
	return n, err
}
