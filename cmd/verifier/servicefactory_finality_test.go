package verifier

import (
	"context"
	"database/sql"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/testutil"
)

// reporterRegistry hands out idle accessors that accept source reader dependencies and whose reader
// reports finality violations, counting every FinalityViolated call.
type reporterRegistry struct {
	mu        sync.Mutex
	depsDB    *sql.DB
	depsID    string
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

func (a *reporterAccessor) SetSourceReaderDeps(deps chainaccess.SourceReaderDeps) error {
	a.registry.mu.Lock()
	defer a.registry.mu.Unlock()
	a.registry.depsDB, a.registry.depsID = deps.DB, deps.VerifierID
	return nil
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

// With the flag on, the reporter selected from the chain's reader must reach the coordinator, whose
// source reader service then polls it in place of comparing headers.
func TestFactoryStart_FlagOn_PassesFinalityReporterToCoordinator(t *testing.T) {
	_, dbURL := testutil.NewTestDBWithURL(t)
	setFactoryEnv(t, dbURL)
	f, reg, port := &factory{}, &reporterRegistry{}, freePort(t)

	require.NoError(t, startServingWith(t, f, reg, port, bootstrap.Features{LogPoller: true}))
	t.Cleanup(func() {
		require.NoError(t, f.Stop(t.Context()))
		require.NoError(t, f.AfterAccessorsClosed(t.Context()))
	})

	reg.mu.Lock()
	require.Same(t, f.sharedSQLDB(), reg.depsDB, "setter must get the factory's database")
	require.Equal(t, "test-verifier", reg.depsID)
	reg.mu.Unlock()

	require.Eventually(t, func() bool { return reg.reported.Load() > 0 },
		10*time.Second, 50*time.Millisecond, "coordinator must poll the chain's finality reporter")
	require.Eventually(t, func() bool { return reg.healthy.Load() > 0 },
		10*time.Second, 50*time.Millisecond, "the service must evaluate the chain's health reporter")
}
