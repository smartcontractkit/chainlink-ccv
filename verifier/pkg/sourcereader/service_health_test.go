package sourcereader

import (
	"context"
	"errors"
	"math/big"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	verifiermonitoring "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/monitoring"
)

// fakeHealthReporter is a source health signal the test flips while the service runs.
type fakeHealthReporter struct {
	err atomic.Pointer[error]
}

func (f *fakeHealthReporter) Healthy() error {
	if err := f.err.Load(); err != nil {
		return *err
	}
	return nil
}

func (f *fakeHealthReporter) set(err error) {
	if err == nil {
		f.err.Store(nil)
		return
	}
	f.err.Store(&err)
}

var _ chainaccess.SourceHealthReporter = (*fakeHealthReporter)(nil)

// newHealthSRS builds an initialized service whose health writes go to the returned recorder.
func newHealthSRS(t *testing.T, reporter chainaccess.SourceHealthReporter) (*Service, *chainHealthRecorder) {
	t.Helper()
	srs, _, _ := newTestSRS(t, protocol.ChainSelector(1337), mocks.NewMockSourceReader(t), mocks.NewMockChainStatusManager(t), mocks.NewMockCurseCheckerService(t), time.Hour, 5000)
	health := &chainHealthRecorder{}
	fakeMonitoring := verifiermonitoring.NewFakeVerifierMonitoring()
	fakeMonitoring.ServiceMetrics = health
	srs.monitoring = fakeMonitoring
	srs.healthReporter = reporter
	srs.startBlockInitialized.Store(true)
	// Marks the state machine started without the background loop, so Ready() reflects only the health inputs.
	require.NoError(t, srs.StartOnce(srs.Name(), func() error { return nil }))
	return srs, health
}

func TestChainHealth_LoadingThenHealthyThenDegradedThenRecovered(t *testing.T) {
	reporter := &fakeHealthReporter{}
	srs, health := newHealthSRS(t, reporter)
	notLoaded := errors.New("log poller still loading")
	loader := &loadingReader{MockSourceReader: mocks.NewMockSourceReader(t), loadedErr: notLoaded}
	srs.sourceReader = loader

	srs.recordChainHealth(t.Context())
	require.ErrorIs(t, srs.chainHealth(), notLoaded)

	loader.setLoadedErr(nil)
	srs.recordChainHealth(t.Context())
	require.NoError(t, srs.Ready())

	missing := errors.New("rpc servers reported missing blocks 3 times in a row")
	reporter.set(missing)
	srs.recordChainHealth(t.Context())
	require.ErrorIs(t, srs.Ready(), missing, "/health must show the source's reason")
	require.ErrorIs(t, srs.chainHealth(), missing)

	reporter.set(nil)
	srs.recordChainHealth(t.Context())
	require.NoError(t, srs.Ready(), "recovery needs no restart")

	require.Equal(t, []bool{false, true, false, true}, health.recorded())
}

// A chain disabled without a violation is unhealthy on the gauge but stays ready on /health, as before.
func TestChainHealth_DisabledIsUnhealthyOnTheGaugeButReadyOnHealth(t *testing.T) {
	srs, health := newHealthSRS(t, nil)
	srs.recordChainHealth(t.Context())
	srs.disabled.Store(true)
	srs.recordChainHealth(t.Context())
	require.Equal(t, []bool{true, false}, health.recorded())
	require.NoError(t, srs.Ready())
}

func TestChainHealth_HandlingAViolationRecordsUnhealthy(t *testing.T) {
	srs, health := newHealthSRS(t, &fakeHealthReporter{})
	srs.recordChainHealth(t.Context())

	srs.handleFinalityViolation(t.Context())

	require.Equal(t, []bool{true, false}, health.recorded())
}

// Without a health reporter the gauge follows today's sequence: false until initialized and loaded,
// true once ready, false when disabled.
func TestChainHealth_WithoutReporterReplaysTodaysSequence(t *testing.T) {
	srs, health := newHealthSRS(t, nil)
	srs.startBlockInitialized.Store(false)

	srs.recordChainHealth(t.Context())
	srs.recordChainHealth(t.Context())
	srs.startBlockInitialized.Store(true)
	srs.recordChainHealth(t.Context())
	srs.disabled.Store(true)
	srs.recordChainHealth(t.Context())

	require.Equal(t, []bool{false, true, false}, health.recorded())
}

// Loading, finality and source health events interleave without leaving a stale value behind: once
// the inputs settle, the last write is what the health function says. The inputs change on other
// goroutines while the service records from its own, as in production.
func TestChainHealth_InterleavedEventsNeverLeaveAStaleValue(t *testing.T) {
	for run := range 10 {
		reporter := &fakeHealthReporter{}
		srs, health := newHealthSRS(t, reporter)
		loader := &loadingReader{MockSourceReader: mocks.NewMockSourceReader(t), loadedErr: errors.New("loading")}
		srs.sourceReader = loader

		var wg sync.WaitGroup
		flip := func(f func(i int)) {
			wg.Go(func() {
				for i := range 200 {
					f(i)
				}
			})
		}
		flip(func(i int) { reporter.set(errOnOdd(i)) })
		flip(func(i int) { loader.setLoadedErr(errOnOdd(i + 1)) })
		flip(func(i int) { srs.finalityBlocked.Store(i%3 == 0 && run%2 == 0) })
		flipped := make(chan struct{})
		go func() {
			wg.Wait()
			close(flipped)
		}()
		recordUntil(t, srs, flipped)

		reporter.set(nil)
		loader.setLoadedErr(nil)
		srs.finalityBlocked.Store(run%2 == 1)
		srs.recordChainHealth(t.Context())

		written := health.recorded()
		require.NotEmpty(t, written)
		require.Equal(t, srs.chainHealth() == nil, written[len(written)-1])
	}
}

func recordUntil(t *testing.T, srs *Service, done <-chan struct{}) {
	for {
		srs.recordChainHealth(t.Context())
		select {
		case <-done:
			return
		default:
		}
	}
}

func errOnOdd(i int) error {
	if i%2 == 1 {
		return errors.New("unhealthy")
	}
	return nil
}

// newLoopHealthSRS starts a service whose chain queries fail while failQueries is set, recording its gauge.
func newLoopHealthSRS(t *testing.T, failQueries *atomic.Bool, reporter chainaccess.SourceHealthReporter) (*Service, *chainHealthRecorder) {
	t.Helper()
	chain := protocol.ChainSelector(1337)
	reader := mocks.NewMockSourceReader(t)
	chainStatusMgr := mocks.NewMockChainStatusManager(t)
	curseDetector := mocks.NewMockCurseCheckerService(t)
	chainStatusMgr.EXPECT().ReadChainStatuses(mock.Anything, mock.Anything).
		Return(map[protocol.ChainSelector]*protocol.ChainStatusInfo{
			chain: {ChainSelector: chain, FinalizedBlockHeight: big.NewInt(100)},
		}, nil).Maybe()
	reader.EXPECT().LatestAndFinalizedBlock(mock.Anything).
		RunAndReturn(func(context.Context) (*protocol.BlockHeader, *protocol.BlockHeader, error) {
			if failQueries.Load() {
				return nil, nil, errors.New("RPC unreachable")
			}
			return &protocol.BlockHeader{Number: 200}, &protocol.BlockHeader{Number: 150}, nil
		}).Maybe()
	reader.EXPECT().LatestSafeBlock(mock.Anything).Return(nil, nil).Maybe()
	reader.EXPECT().FetchMessageSentEvents(mock.Anything, mock.Anything, mock.Anything).
		Return([]protocol.MessageSentEvent{}, nil).Maybe()
	curseDetector.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).
		Return(false, nil).Maybe()

	srs, _, _ := newTestSRS(t, chain, reader, chainStatusMgr, curseDetector, 20*time.Millisecond, 100)
	health := &chainHealthRecorder{}
	fakeMonitoring := verifiermonitoring.NewFakeVerifierMonitoring()
	fakeMonitoring.ServiceMetrics = health
	srs.monitoring = fakeMonitoring
	srs.healthReporter = reporter
	require.NoError(t, srs.Start(t.Context()))
	t.Cleanup(func() { require.NoError(t, srs.Close()) })
	return srs, health
}

func lastRecorded(health *chainHealthRecorder) (healthy, ok bool) {
	recorded := health.recorded()
	if len(recorded) == 0 {
		return false, false
	}
	return recorded[len(recorded)-1], true
}

// The gauge follows each chain query, as #1521 made it: down on a failed query, up on the next success.
func TestChainHealth_FailedQueryDropsTheGaugeUntilTheNextSuccess(t *testing.T) {
	var failQueries atomic.Bool
	srs, health := newLoopHealthSRS(t, &failQueries, nil)
	isHealthy := func(want bool) func() bool {
		return func() bool { got, ok := lastRecorded(health); return ok && got == want }
	}
	require.Eventually(t, isHealthy(true), 2*time.Second, 5*time.Millisecond)

	failQueries.Store(true)
	require.Eventually(t, isHealthy(false), 2*time.Second, 5*time.Millisecond)
	require.NoError(t, srs.Ready(), "/health uses the staleness window, not a single failed query")

	failQueries.Store(false)
	require.Eventually(t, isHealthy(true), 2*time.Second, 5*time.Millisecond)
}

// A successful query never marks the gauge healthy while the source reports itself unhealthy.
func TestChainHealth_SuccessfulQueryDoesNotOverrideAnUnhealthySource(t *testing.T) {
	reporter := &fakeHealthReporter{}
	reporter.set(errors.New("log poller unhealthy"))
	var failQueries atomic.Bool
	_, health := newLoopHealthSRS(t, &failQueries, reporter)

	require.Eventually(t, func() bool { return health.writes() > 5 }, 2*time.Second, 5*time.Millisecond,
		"the loop keeps querying and recording")
	require.NotContains(t, health.recorded(), true)
}
