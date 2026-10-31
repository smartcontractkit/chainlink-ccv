package sourcereader

import (
	"context"
	"errors"
	"math/big"
	"slices"
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
	verifier "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vtypes"
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
	srs, health := newHealthSRS(t, nil)
	srs.recordChainHealth(t.Context())

	srs.handleFinalityViolation(t.Context())

	require.Equal(t, []bool{true, false}, health.recorded())
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

// sourceStateRecorder records the source reader states the service sets.
type sourceStateRecorder struct {
	*verifiermonitoring.FakeVerifierMetricLabeler
	mu     sync.Mutex
	states []string
}

func (s *sourceStateRecorder) With(...string) verifier.MetricLabeler { return s }

func (s *sourceStateRecorder) SetSourceReaderState(_ context.Context, state string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.states = append(s.states, state)
}

func (s *sourceStateRecorder) recorded() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.states)
}

// stateRecordingMonitoring serves a sourceStateRecorder as the service's metrics.
type stateRecordingMonitoring struct {
	*verifiermonitoring.FakeVerifierMonitoring
	states *sourceStateRecorder
}

func (m stateRecordingMonitoring) Metrics() verifier.MetricLabeler { return m.states }

// A disabled chain's monitoring tick reports a finality violation as finality blocked, not just disabled.
func TestSRS_FinalityReporterViolation_DisabledTickReportsFinalityBlockedState(t *testing.T) {
	ctx := context.Background()
	chain := protocol.ChainSelector(1337)
	reporter := &fakeFinalityReporter{}

	srs, _, _ := newTestSRS(t, chain, mocks.NewMockSourceReader(t), mocks.NewMockChainStatusManager(t), mocks.NewMockCurseCheckerService(t), 10*time.Millisecond, 5000)
	states := &sourceStateRecorder{FakeVerifierMetricLabeler: &verifiermonitoring.FakeVerifierMetricLabeler{}}
	srs.monitoring = stateRecordingMonitoring{FakeVerifierMonitoring: verifiermonitoring.NewFakeVerifierMonitoring(), states: states}
	useLogPollerFinality(t, srs, reporter, false)
	reporter.violated.Store(true)

	require.False(t, srs.sendReadyMessages(ctx, &protocol.BlockHeader{Number: 1000}, nil, &protocol.BlockHeader{Number: 950}))
	srs.recordDisabledState(ctx)
	recordedStates := states.recorded()
	require.NotEmpty(t, recordedStates)
	require.Equal(t, verifiermonitoring.SourceReaderStateFinalityBlocked, recordedStates[len(recordedStates)-1])
}
