package sourcereader

import (
	"context"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/internal/mocks"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	verifiermonitoring "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/monitoring"
	verifier "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vtypes"
)

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

// pendingTaskAt puts one pending task for a message at blockNumber into srs.
func pendingTaskAt(t *testing.T, srs *Service, chain protocol.ChainSelector, blockNumber uint64) verifier.VerificationTask {
	t.Helper()
	msgs := createTestMessageSentEvents(t, 1, chain, defaultDestChain, []uint64{blockNumber})
	task := verifier.VerificationTask{Message: msgs[0].Message, BlockNumber: msgs[0].BlockNumber, MessageID: msgs[0].MessageID.String()}
	srs.mu.Lock()
	srs.pendingTasks[task.MessageID] = task
	srs.mu.Unlock()
	return task
}

// One chain's violation must not stop another chain's verification: each chain has its own service,
// reporter and persisted status.
func TestSRS_FinalityReporterViolation_DoesNotAffectOtherChains(t *testing.T) {
	ctx := context.Background()
	chainA, chainB := protocol.ChainSelector(1337), protocol.ChainSelector(2337)
	reporterA, reporterB := &fakeFinalityReporter{}, &fakeFinalityReporter{}

	mgrA, mgrB := mocks.NewMockChainStatusManager(t), mocks.NewMockChainStatusManager(t)
	srsA, _, _ := newTestSRS(t, chainA, mocks.NewMockSourceReader(t), mgrA, mocks.NewMockCurseCheckerService(t), 10*time.Millisecond, 5000)
	curseB := mocks.NewMockCurseCheckerService(t)
	curseB.EXPECT().IsRemoteChainCursed(mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()
	srsB, _, _ := newTestSRS(t, chainB, mocks.NewMockSourceReader(t), mgrB, curseB, 10*time.Millisecond, 5000)
	useLogPollerFinality(t, srsA, reporterA, false)
	useLogPollerFinality(t, srsB, reporterB, false)
	pendingTaskAt(t, srsA, chainA, 940)
	taskB := pendingTaskAt(t, srsB, chainB, 940)

	reporterA.violated.Store(true)
	latest, finalized := &protocol.BlockHeader{Number: 1000}, &protocol.BlockHeader{Number: 950}
	require.False(t, srsA.sendReadyMessages(ctx, latest, nil, finalized))
	require.True(t, srsB.sendReadyMessages(ctx, latest, nil, finalized))

	require.True(t, srsA.disabled.Load())
	srsA.mu.RLock()
	require.Empty(t, srsA.pendingTasks, "the violating chain's tasks are flushed")
	srsA.mu.RUnlock()
	mgrA.AssertCalled(t, "WriteChainStatuses", mock.Anything, mock.Anything)

	require.False(t, srsB.disabled.Load(), "the other chain keeps processing")
	require.Contains(t, srsB.sentTasks, taskB.MessageID, "the other chain's task is still verified")
	writesB := 0
	for _, call := range mgrB.Calls {
		if call.Method != "WriteChainStatuses" {
			continue
		}
		for _, info := range call.Arguments.Get(1).([]protocol.ChainStatusInfo) {
			writesB++
			require.False(t, info.Disabled, "the other chain is never persisted as disabled")
		}
	}
	require.Positive(t, writesB, "the other chain kept checkpointing")
}

// The violation is persisted as a disabled chain and read back on the next start, so a restart does
// not resume verifying until someone acts.
func TestSRS_FinalityReporterViolation_StaysDisabledAfterRestart(t *testing.T) {
	ctx := context.Background()
	chain := protocol.ChainSelector(1337)
	reporter := &fakeFinalityReporter{}

	var persisted protocol.ChainStatusInfo
	mgr := mocks.NewMockChainStatusManager(t)
	srs, _, _ := newTestSRS(t, chain, mocks.NewMockSourceReader(t), mgr, mocks.NewMockCurseCheckerService(t), 10*time.Millisecond, 5000)
	mgr.ExpectedCalls = nil
	mgr.EXPECT().WriteChainStatuses(mock.Anything, mock.Anything).
		RunAndReturn(func(_ context.Context, infos []protocol.ChainStatusInfo) error {
			persisted = infos[0]
			return nil
		}).Once()
	useLogPollerFinality(t, srs, reporter, false)
	reporter.violated.Store(true)
	require.False(t, srs.sendReadyMessages(ctx, &protocol.BlockHeader{Number: 1000}, nil, &protocol.BlockHeader{Number: 950}))
	require.True(t, persisted.Disabled)

	// A new service, as after a restart, reads the persisted status.
	restartMgr := mocks.NewMockChainStatusManager(t)
	restartMgr.EXPECT().ReadChainStatuses(mock.Anything, mock.Anything).
		Return(map[protocol.ChainSelector]*protocol.ChainStatusInfo{chain: &persisted}, nil).Once()
	restarted, _, _ := newTestSRS(t, chain, mocks.NewMockSourceReader(t), restartMgr, mocks.NewMockCurseCheckerService(t), 10*time.Millisecond, 5000)
	_, err := restarted.initializeStartBlock(ctx)
	require.NoError(t, err)
	require.True(t, restarted.disabled.Load(), "a restart keeps the chain disabled")
}

// Until the single health writer exists, the violation path itself must report the chain unhealthy.
func TestSRS_FinalityReporterViolation_ReportsChainUnhealthy(t *testing.T) {
	ctx := context.Background()
	chain := protocol.ChainSelector(1337)
	reporter := &fakeFinalityReporter{}

	srs, _, _ := newTestSRS(t, chain, mocks.NewMockSourceReader(t), mocks.NewMockChainStatusManager(t), mocks.NewMockCurseCheckerService(t), 10*time.Millisecond, 5000)
	health := &chainHealthRecorder{}
	states := &sourceStateRecorder{FakeVerifierMetricLabeler: &verifiermonitoring.FakeVerifierMetricLabeler{}}
	fake := verifiermonitoring.NewFakeVerifierMonitoring()
	fake.ServiceMetrics = health
	srs.monitoring = stateRecordingMonitoring{FakeVerifierMonitoring: fake, states: states}
	useLogPollerFinality(t, srs, reporter, false)
	reporter.violated.Store(true)

	require.False(t, srs.sendReadyMessages(ctx, &protocol.BlockHeader{Number: 1000}, nil, &protocol.BlockHeader{Number: 950}))
	// The monitoring loop records this on every tick of a disabled chain.
	srs.recordDisabledState(ctx)
	recorded := health.recorded()
	require.NotEmpty(t, recorded)
	require.False(t, recorded[len(recorded)-1], "the per-chain healthy gauge goes false")
	recordedStates := states.recorded()
	require.NotEmpty(t, recordedStates)
	require.Equal(t, verifiermonitoring.SourceReaderStateFinalityBlocked, recordedStates[len(recordedStates)-1],
		"a finality violation shows as finality blocked, not just disabled")
}
