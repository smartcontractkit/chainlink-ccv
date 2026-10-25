package verifier

import (
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	"github.com/smartcontractkit/chainlink-ccv/verifier/testutil"
)

const twoChainSpec = `
verifier_id = "test-verifier"
aggregator_address = "localhost:50051"

[on_ramp_addresses]
"5009297550715157269" = "0x0000000000000000000000000000000000000001"
"4949039107694359620" = "0x0000000000000000000000000000000000000011"

[committee_verifier_addresses]
"5009297550715157269" = "0x0000000000000000000000000000000000000002"
"4949039107694359620" = "0x0000000000000000000000000000000000000012"

[rmn_remote_addresses]
"5009297550715157269" = "0x0000000000000000000000000000000000000003"
"4949039107694359620" = "0x0000000000000000000000000000000000000013"
`

// Repeated start and stop of two chains with reporting readers leaves no goroutines or database
// connections behind.
func TestFactoryRestart_LeavesNothingBehind(t *testing.T) {
	_, dbURL := testutil.NewTestDBWithURL(t)
	setFactoryEnv(t, dbURL)
	baseline := serverConnections(t, dbURL)
	f, reg, port := &factory{}, &reporterRegistry{}, freePort(t)

	// One warm-up job first, so process-wide state created lazily by the first job is not a leak.
	start := func() error { return startServingSpec(t, f, reg, port, twoChainSpec) }
	require.NoError(t, start())
	require.NoError(t, f.Stop(t.Context()))
	opt := goleak.IgnoreCurrent()

	const restarts = 3
	for i := range restarts {
		require.NoError(t, start(), "start %d", i)
		require.NoError(t, f.Stop(t.Context()), "stop %d", i)
	}

	require.Eventually(t, func() bool { return serverConnections(t, dbURL) <= baseline },
		5*time.Second, 50*time.Millisecond, "restarts must release every database connection")
	// The message-latency cache stops its janitor goroutine from a finalizer, so collect while waiting.
	require.Eventually(t, func() bool {
		runtime.GC()
		return goleak.Find(opt) == nil
	}, 10*time.Second, 100*time.Millisecond, "goroutines leaked: %v", goleak.Find(opt))
}
