package policy

import (
	"context"
	"errors"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/monitoring"
	vtypes "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vtypes"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// endpointCall is one RecordPolicyHTTPRequestDuration the gate made.
type endpointCall struct {
	outcome  string
	duration time.Duration
}

// transition is one IncrementMessageTransition the gate made.
type transition struct {
	stage   string
	outcome string
	reason  string
}

// metricsSpy captures the two recordings the gate makes that the fake labeler discards: the
// stage's message transitions, and the endpoint-latency histogram. Everything else comes from the
// embedded fake, so the spy does not restate the whole MetricLabeler surface.
//
// The two belong on one spy because the interesting assertions are about how they line up: a task
// that never reached the endpoint has to be counted on the transition counter and absent from the
// histogram, and a test that sees only one of the two cannot say that.
type metricsSpy struct {
	*monitoring.FakeVerifierMetricLabeler

	mu              sync.Mutex
	endpointCalls   []endpointCall
	transitionCalls []transition
}

// With returns the spy rather than the embedded fake, which would drop the overrides below.
func (s *metricsSpy) With(...string) vtypes.MetricLabeler { return s }

func (s *metricsSpy) RecordPolicyHTTPRequestDuration(_ context.Context, outcome string, duration time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.endpointCalls = append(s.endpointCalls, endpointCall{outcome: outcome, duration: duration})
}

func (s *metricsSpy) IncrementMessageTransition(_ context.Context, stage, outcome, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.transitionCalls = append(s.transitionCalls, transition{stage: stage, outcome: outcome, reason: reason})
}

func (s *metricsSpy) timedCalls() []endpointCall {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]endpointCall(nil), s.endpointCalls...)
}

// timedOutcomes returns the histogram's outcome labels, sorted so a concurrent batch compares
// stably.
func (s *metricsSpy) timedOutcomes() []string {
	calls := s.timedCalls()
	out := make([]string, 0, len(calls))
	for _, c := range calls {
		out = append(out, c.outcome)
	}
	sort.Strings(out)
	return out
}

func (s *metricsSpy) transitions() []transition {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]transition(nil), s.transitionCalls...)
}

// spyMonitoring serves the metrics spy in place of the fake labeler.
type spyMonitoring struct {
	*monitoring.FakeVerifierMonitoring
	spy *metricsSpy
}

func (m *spyMonitoring) Metrics() vtypes.MetricLabeler { return m.spy }

func newSpyMonitoring() *spyMonitoring {
	fake := monitoring.NewFakeVerifierMonitoring()
	return &spyMonitoring{
		FakeVerifierMonitoring: fake,
		spy:                    &metricsSpy{FakeVerifierMetricLabeler: fake.Fake},
	}
}

func newGateWithMonitoring(t *testing.T, checker Checker, inner vtypes.Verifier, mon vtypes.Monitoring) *GatedVerifier {
	t.Helper()

	gate, err := NewGatedVerifier(
		logger.Test(t), "committee-verifier-1", inner, checker, mon, time.Second)
	require.NoError(t, err)
	return gate
}

// policyTransition is the stage's transition for one message, which is all these tests produce.
func policyTransition(outcome, reason string) []transition {
	return []transition{{stage: monitoring.MessageTransitionStagePolicy, outcome: outcome, reason: reason}}
}

// The histogram's label vocabulary is what a dashboard joins against the stage's transition
// counter, so a PASS, a FAIL, and an endpoint error have to land on the same three outcome
// strings the counter uses.
func TestGatedVerifier_RecordsEndpointLatencyPerOutcome(t *testing.T) {
	checker := &stubChecker{
		verdicts: map[string]Verdict{
			msgID(1): {Decision: DecisionPass},
			msgID(2): {Decision: DecisionFail, Reason: "sanctioned"},
		},
		errs: map[string]error{msgID(3): errors.New("endpoint down")},
	}
	mon := newSpyMonitoring()

	results := newGateWithMonitoring(t, checker, &stubVerifier{}, mon).VerifyMessages(
		t.Context(),
		[]vtypes.VerificationTask{newTask(msgID(1)), newTask(msgID(2)), newTask(msgID(3))},
	)
	require.Len(t, results, 3)

	assert.Equal(t, []string{
		monitoring.MessageTransitionOutcomePolicyPassed,
		monitoring.MessageTransitionOutcomePolicyRejected,
		monitoring.MessageTransitionOutcomePolicyUnavailable,
	}, mon.spy.timedOutcomes(), "one call per message, labeled by its verdict")

	for _, call := range mon.spy.timedCalls() {
		assert.Positive(t, call.duration, "a recorded call must carry the time it took")
	}
}

// A task the verifier rejects before signing never reaches the endpoint, so it must not land in
// the latency histogram. Counting it would report a call that was never made.
func TestGatedVerifier_SkippedTaskRecordsNoEndpointLatency(t *testing.T) {
	checker := &stubChecker{}
	inner := &validatingVerifier{invalid: map[string]error{msgID(1): errors.New("unsignable")}}
	mon := newSpyMonitoring()

	results := newGateWithMonitoring(t, checker, inner, mon).VerifyMessages(
		t.Context(), []vtypes.VerificationTask{newTask(msgID(1)), newTask(msgID(2))})
	require.Len(t, results, 2)

	assert.Equal(t, []string{monitoring.MessageTransitionOutcomePolicyPassed}, mon.spy.timedOutcomes(),
		"only the evaluated task is timed")
	assert.Equal(t, []string{msgID(2)}, checker.callsMade(), "a skipped task must not be called")
}

// A task the gate cannot build a request for made no call. It has to be counted as a verifier-side
// gap rather than an endpoint failure, so an operator paging on policy_endpoint_error is not woken
// by it, and it has to stay out of the endpoint's latency histogram, which would otherwise report
// a call against an endpoint that was never contacted.
func TestGatedVerifier_MissingReaderDetailsIsNotAnEndpointFailure(t *testing.T) {
	mon := newSpyMonitoring()
	task := newTask(msgID(1))
	task.MessageDetails = nil

	results := newGateWithMonitoring(t, &stubChecker{}, &stubVerifier{}, mon).VerifyMessages(
		t.Context(), []vtypes.VerificationTask{task})
	require.Len(t, results, 1)

	assert.Equal(t, policyTransition(
		monitoring.MessageTransitionOutcomePolicyUnavailable,
		monitoring.MessageTransitionReasonPolicyRequestInvalid,
	), mon.spy.transitions())
	assert.Empty(t, mon.spy.timedCalls(), "an unbuilt request must not be timed as an endpoint call")
}

// An endpoint that actually failed keeps the endpoint reason, so the two stay distinguishable, and
// it is timed because the call did go out.
func TestGatedVerifier_EndpointFailureKeepsEndpointReason(t *testing.T) {
	mon := newSpyMonitoring()
	checker := &stubChecker{errs: map[string]error{msgID(1): errors.New("endpoint down")}}

	results := newGateWithMonitoring(t, checker, &stubVerifier{}, mon).VerifyMessages(
		t.Context(), []vtypes.VerificationTask{newTask(msgID(1))})
	require.Len(t, results, 1)

	assert.Equal(t, policyTransition(
		monitoring.MessageTransitionOutcomePolicyUnavailable,
		monitoring.MessageTransitionReasonPolicyEndpointError,
	), mon.spy.transitions())
	assert.Len(t, mon.spy.timedCalls(), 1, "a call that went out and failed is still timed")
}

func TestCallOutcome(t *testing.T) {
	assert.Equal(t, monitoring.MessageTransitionOutcomePolicyUnavailable,
		callOutcome(Verdict{Decision: DecisionPass}, errors.New("boom")),
		"an error wins over whatever verdict came back with it")
	assert.Equal(t, monitoring.MessageTransitionOutcomePolicyRejected,
		callOutcome(Verdict{Decision: DecisionFail}, nil))
	assert.Equal(t, monitoring.MessageTransitionOutcomePolicyPassed,
		callOutcome(Verdict{Decision: DecisionPass}, nil))
}
