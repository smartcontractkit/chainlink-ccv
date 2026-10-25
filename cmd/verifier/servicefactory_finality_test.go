package verifier

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/testutil"
)

// reporterRegistry hands out idle accessors whose reader reports finality violations and health,
// counting every call.
type reporterRegistry struct {
	mu        sync.Mutex
	reported  atomic.Int32
	healthy   atomic.Int32
	accessors []*reporterAccessor
}

func (r *reporterRegistry) GetAccessor(context.Context, protocol.ChainSelector) (chainaccess.Accessor, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	a := &reporterAccessor{registry: r}
	r.accessors = append(r.accessors, a)
	return a, nil
}

type reporterAccessor struct {
	idleAccessor
	registry *reporterRegistry
}

func (a *reporterAccessor) SourceReader() (chainaccess.SourceReader, error) {
	return reportingSourceReader{reported: &a.registry.reported, healthy: &a.registry.healthy}, nil
}

type reportingSourceReader struct {
	idleSourceReader
	reported *atomic.Int32
	healthy  *atomic.Int32
}

func (r reportingSourceReader) Healthy() error {
	if r.healthy != nil {
		r.healthy.Add(1)
	}
	return nil
}

func (r reportingSourceReader) FinalityViolated() bool {
	r.reported.Add(1)
	return false
}

// The reporters taken from the chain's reader must reach the coordinator, whose source reader service
// then polls them in place of comparing headers.
func TestFactoryStart_PassesReaderReportersToCoordinator(t *testing.T) {
	_, dbURL := testutil.NewTestDBWithURL(t)
	setFactoryEnv(t, dbURL)
	f, reg, port := &factory{}, &reporterRegistry{}, freePort(t)

	require.NoError(t, startServing(t, f, reg, port))
	t.Cleanup(func() {
		require.NoError(t, f.Stop(t.Context()))
	})

	require.Eventually(t, func() bool { return reg.reported.Load() > 0 },
		10*time.Second, 50*time.Millisecond, "coordinator must poll the chain's finality reporter")
	require.Eventually(t, func() bool { return reg.healthy.Load() > 0 },
		10*time.Second, 50*time.Millisecond, "the service must evaluate the chain's health reporter")
}
