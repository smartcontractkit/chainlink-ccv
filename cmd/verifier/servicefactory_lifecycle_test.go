package verifier

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	"github.com/smartcontractkit/chainlink-common/keystore"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/commit"
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

// countingRegistry hands out accessors with a reporting reader and counts how many
// are open, as one LogPoller per chain would be.
type countingRegistry struct {
	mu        sync.Mutex
	built     int
	live      int
	accessors []*countingAccessor
}

func (r *countingRegistry) GetAccessor(context.Context, protocol.ChainSelector) (chainaccess.Accessor, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.built++
	r.live++
	a := &countingAccessor{registry: r}
	r.accessors = append(r.accessors, a)
	return a, nil
}

// closeAll closes every open accessor, as bootstrap's AccessorCloserRegistry does.
func (r *countingRegistry) closeAll() {
	r.mu.Lock()
	accessors := r.accessors
	r.accessors = nil
	r.mu.Unlock()
	for _, a := range accessors {
		_ = a.Close()
	}
}

func (r *countingRegistry) liveCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.live
}

type countingAccessor struct {
	idleAccessor
	registry *countingRegistry
}

func (a *countingAccessor) SourceReader() (chainaccess.SourceReader, error) {
	return reportingSourceReader{reported: new(atomic.Int32)}, nil
}

func (a *countingAccessor) Close() error {
	a.registry.mu.Lock()
	defer a.registry.mu.Unlock()
	a.registry.live--
	return nil
}

// Repeated start and stop with a reporting reader leaves one open accessor per chain after each start,
// none after each stop, and no goroutines or database connections behind.
func TestFactoryRestart_LeavesNothingBehind(t *testing.T) {
	_, dbURL := testutil.NewTestDBWithURL(t)
	setFactoryEnv(t, dbURL)
	baseline := serverConnections(t, dbURL)
	f, reg, port := &factory{}, &countingRegistry{}, freePort(t)

	// One warm-up job first, so process-wide state created lazily by the first job is not a leak.
	start := func() error { return startTwoChains(t, f, reg, port) }
	require.NoError(t, start())
	releaseCounting(t, f, reg)
	opt := goleak.IgnoreCurrent()

	const restarts = 3
	built := reg.built
	for i := range restarts {
		require.NoError(t, start(), "start %d", i)
		require.Equal(t, 2, reg.liveCount(), "one accessor per chain after start %d", i)
		require.Equal(t, built+2*(i+1), reg.built)

		releaseCounting(t, f, reg)
		require.Zero(t, reg.liveCount(), "every accessor closed after stop %d", i)
	}

	require.Eventually(t, func() bool { return serverConnections(t, dbURL) <= baseline },
		5*time.Second, 50*time.Millisecond, "restarts must release every database connection")
	// The message-latency cache stops its janitor goroutine from a finalizer, so collect while waiting.
	require.Eventually(t, func() bool {
		runtime.GC()
		return goleak.Find(opt) == nil
	}, 10*time.Second, 100*time.Millisecond, "goroutines leaked: %v", goleak.Find(opt))
}

func releaseCounting(t *testing.T, f *factory, reg *countingRegistry) {
	t.Helper()
	require.NoError(t, f.Stop(t.Context()))
	reg.closeAll()
	require.NoError(t, f.AfterAccessorsClosed(t.Context()))
}

func startTwoChains(t *testing.T, f *factory, reg chainaccess.Registry, port int) error {
	t.Helper()
	ks, err := keystore.LoadKeystore(t.Context(), keystore.NewMemoryStorage(), "test",
		keystore.WithScryptParams(keystore.FastScryptParams))
	require.NoError(t, err)
	_, err = ks.CreateKeys(t.Context(), keystore.CreateKeysRequest{Keys: []keystore.CreateKeyRequest{
		{KeyName: commit.DefaultECDSASigningKeyName, KeyType: keystore.ECDSA_S256},
	}})
	require.NoError(t, err)
	spec := fmt.Sprintf("signer_address = %q\nhttp_listen_port = %d\n", commit.AutoSignerAddress, port) + twoChainSpec
	return f.Start(t.Context(), bootstrap.JobSpec{AppConfig: spec}, bootstrap.ServiceDeps{
		Logger:   logger.Test(t),
		Keystore: ks,
		Registry: reg,
	})
}
