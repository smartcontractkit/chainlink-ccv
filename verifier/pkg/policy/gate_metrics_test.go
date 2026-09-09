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

// policyDurationCall is one RecordPolicyHTTPRequestDuration the gate made.
type policyDurationCall struct {
	outcome  string
	duration time.Duration
}

// durationSpy captures the policy duration calls the fake labeler discards. Everything else
// comes from the fake, so the spy does not have to track the whole MetricLabeler surface.
type durationSpy struct {
	*monitoring.FakeVerifierMetricLabeler

	mu    sync.Mutex
	calls []policyDurationCall
}

// With returns the spy rather than the embedded fake, which would drop the override.
func (s *durationSpy) With(...string) vtypes.MetricLabeler { return s }

func (s *durationSpy) RecordPolicyHTTPRequestDuration(_ context.Context, outcome string, duration time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, policyDurationCall{outcome: outcome, duration: duration})
}

func (s *durationSpy) recorded() []policyDurationCall {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]policyDurationCall(nil), s.calls...)
}

// outcomes returns the recorded outcome labels, sorted so a concurrent batch compares stably.
func (s *durationSpy) outcomes() []string {
	calls := s.recorded()
	out := make([]string, 0, len(calls))
	for _, c := range calls {
		out = append(out, c.outcome)
	}
	sort.Strings(out)
	return out
}

// spyMonitoring serves the duration spy in place of the fake labeler.
type spyMonitoring struct {
	*monitoring.FakeVerifierMonitoring
	spy *durationSpy
}

func (m *spyMonitoring) Metrics() vtypes.MetricLabeler { return m.spy }

func newSpyMonitoring() *spyMonitoring {
	fake := monitoring.NewFakeVerifierMonitoring()
	return &spyMonitoring{
		FakeVerifierMonitoring: fake,
		spy:                    &durationSpy{FakeVerifierMetricLabeler: fake.Fake},
	}
}

func newGateWithMonitoring(t *testing.T, checker Checker, inner vtypes.Verifier, mon vtypes.Monitoring) *GatedVerifier {
	t.Helper()

	gate, err := NewGatedVerifier(
		logger.Test(t), "committee-verifier-1", inner, checker, mon, time.Second)
	require.NoError(t, err)
	return gate
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
	}, mon.spy.outcomes(), "one call per message, labeled by its verdict")

	for _, call := range mon.spy.recorded() {
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

	assert.Equal(t, []string{monitoring.MessageTransitionOutcomePolicyPassed}, mon.spy.outcomes(),
		"only the evaluated task is timed")
	assert.Equal(t, []string{msgID(2)}, checker.callsMade(), "a skipped task must not be called")
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
