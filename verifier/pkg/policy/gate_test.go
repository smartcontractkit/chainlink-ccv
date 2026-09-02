package policy

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/monitoring"
	vtypes "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vtypes"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// stubChecker answers per message ID, defaulting to PASS for anything unlisted.
type stubChecker struct {
	verdicts map[string]Verdict
	errs     map[string]error
	mu       sync.Mutex
	calls    []string
	inFlight int
	maxSeen  int
}

func (s *stubChecker) Evaluate(_ context.Context, req EvaluateRequest) (Verdict, error) {
	s.mu.Lock()
	s.calls = append(s.calls, req.MessageID)
	s.inFlight++
	s.maxSeen = max(s.maxSeen, s.inFlight)
	verdict, hasVerdict := s.verdicts[req.MessageID]
	err := s.errs[req.MessageID]
	s.mu.Unlock()

	// Hold the slot briefly so concurrent calls actually overlap, which is what makes the
	// concurrency bound observable.
	time.Sleep(time.Millisecond)

	s.mu.Lock()
	s.inFlight--
	s.mu.Unlock()

	if err != nil {
		return Verdict{}, err
	}
	if !hasVerdict {
		return Verdict{Decision: DecisionPass}, nil
	}
	return verdict, nil
}

func (s *stubChecker) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}

func (s *stubChecker) callsMade() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.calls...)
}

func (s *stubChecker) peakConcurrency() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.maxSeen
}

// stubVerifier records what the gate forwarded and returns a success for each task.
type stubVerifier struct {
	mu   sync.Mutex
	seen []string
}

func (s *stubVerifier) VerifyMessages(_ context.Context, tasks []vtypes.VerificationTask) []vtypes.VerificationResult {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]vtypes.VerificationResult, 0, len(tasks))
	for _, task := range tasks {
		s.seen = append(s.seen, task.MessageID)
		out = append(out, vtypes.VerificationResult{
			Result: &protocol.VerifierNodeResult{MessageID: mustBytes32(task.MessageID)},
		})
	}
	return out
}

func (s *stubVerifier) forwarded() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.seen...)
}

// validatingVerifier is a stubVerifier that also implements vtypes.TaskValidator, which is how
// the real commit verifier tells the gate it will reject a task before signing it. Tasks listed
// in invalid come back as errors from VerifyMessages, the same way the commit verifier fails
// them, so the test sees the gate's real end-to-end behavior rather than a synthesized result.
type validatingVerifier struct {
	stubVerifier
	invalid map[string]error
}

func (v *validatingVerifier) ValidateTask(task *vtypes.VerificationTask) error {
	return v.invalid[task.MessageID]
}

func (v *validatingVerifier) VerifyMessages(_ context.Context, tasks []vtypes.VerificationTask) []vtypes.VerificationResult {
	v.mu.Lock()
	defer v.mu.Unlock()

	out := make([]vtypes.VerificationResult, 0, len(tasks))
	for _, task := range tasks {
		v.seen = append(v.seen, task.MessageID)
		if err := v.invalid[task.MessageID]; err != nil {
			verificationErr := vtypes.NewVerificationError(err, task)
			out = append(out, vtypes.VerificationResult{Error: &verificationErr})
			continue
		}
		out = append(out, vtypes.VerificationResult{
			Result: &protocol.VerifierNodeResult{MessageID: mustBytes32(task.MessageID)},
		})
	}
	return out
}

var _ vtypes.TaskValidator = (*validatingVerifier)(nil)

// lateFailingVerifier accepts every task at ValidateTask and then fails it in VerifyMessages.
// It stands for the checks the real verifier can only make while signing — resolving the
// signable payload, or the signer itself erroring — which the precheck by construction cannot
// report. It is the shape that puts a task in front of the endpoint and still refuses to sign it.
type lateFailingVerifier struct {
	stubVerifier
	failVerification map[string]error
}

func (v *lateFailingVerifier) ValidateTask(*vtypes.VerificationTask) error { return nil }

func (v *lateFailingVerifier) VerifyMessages(_ context.Context, tasks []vtypes.VerificationTask) []vtypes.VerificationResult {
	v.mu.Lock()
	defer v.mu.Unlock()

	out := make([]vtypes.VerificationResult, 0, len(tasks))
	for _, task := range tasks {
		v.seen = append(v.seen, task.MessageID)
		if err := v.failVerification[task.MessageID]; err != nil {
			verificationErr := vtypes.NewVerificationError(err, task)
			out = append(out, vtypes.VerificationResult{Error: &verificationErr})
			continue
		}
		out = append(out, vtypes.VerificationResult{
			Result: &protocol.VerifierNodeResult{MessageID: mustBytes32(task.MessageID)},
		})
	}
	return out
}

var _ vtypes.TaskValidator = (*lateFailingVerifier)(nil)

func mustBytes32(id string) protocol.Bytes32 {
	b, err := protocol.NewBytes32FromString(id)
	if err != nil {
		panic(err)
	}
	return b
}

// msgID builds a full 32-byte message ID. A short form like "0x01" would not survive the
// Bytes32 round trip the task verifier does when it maps results back to queue jobs, so tests
// use the same shape production does.
func msgID(n byte) string {
	return protocol.Bytes32{31: n}.String()
}

func newTask(messageID string) vtypes.VerificationTask {
	return vtypes.VerificationTask{
		MessageID: messageID,
		Message: protocol.Message{
			SourceChainSelector: 1,
			DestChainSelector:   2,
		},
	}
}

func newGate(t *testing.T, checker Checker, inner vtypes.Verifier) *GatedVerifier {
	t.Helper()

	gate, err := NewGatedVerifier(
		logger.Test(t), "committee-verifier-1", inner, checker,
		monitoring.NewFakeVerifierMonitoring(), time.Second,
	)
	require.NoError(t, err)
	return gate
}

// resultsByMessageID indexes results the way the task verifier does, by message ID.
func resultsByMessageID(t *testing.T, results []vtypes.VerificationResult) map[string]vtypes.VerificationResult {
	t.Helper()

	out := make(map[string]vtypes.VerificationResult, len(results))
	for _, r := range results {
		switch {
		case r.Error != nil:
			out[r.Error.Task.MessageID] = r
		case r.Result != nil:
			out[r.Result.MessageID.String()] = r
		default:
			t.Fatalf("result carries neither a value nor an error: %+v", r)
		}
	}
	return out
}

func TestGatedVerifier_PassIsForwarded(t *testing.T) {
	checker := &stubChecker{}
	inner := &stubVerifier{}
	gate := newGate(t, checker, inner)

	results := gate.VerifyMessages(t.Context(), []vtypes.VerificationTask{newTask(msgID(1))})

	require.Len(t, results, 1)
	require.NotNil(t, results[0].Result)
	assert.Equal(t, []string{msgID(1)}, inner.forwarded())
}

func TestGatedVerifier_FailIsDroppedPermanently(t *testing.T) {
	checker := &stubChecker{verdicts: map[string]Verdict{
		msgID(2): {Decision: DecisionFail, Reason: "sanctioned sender"},
	}}
	inner := &stubVerifier{}
	gate := newGate(t, checker, inner)

	results := gate.VerifyMessages(t.Context(), []vtypes.VerificationTask{newTask(msgID(2))})

	require.Len(t, results, 1)
	require.NotNil(t, results[0].Error)
	assert.False(t, results[0].Error.Retryable,
		"a FAIL must be permanent: a retryable error would re-ask the endpoint forever instead of dropping")
	assert.Contains(t, results[0].Error.Error.Error(), "policy hook rejected message "+msgID(2))
	assert.Contains(t, results[0].Error.Error.Error(), "sanctioned sender")
	assert.Empty(t, inner.forwarded(), "a rejected message is never signed")
}

func TestGatedVerifier_FailWithoutReason(t *testing.T) {
	checker := &stubChecker{verdicts: map[string]Verdict{msgID(3): {Decision: DecisionFail}}}
	gate := newGate(t, checker, &stubVerifier{})

	results := gate.VerifyMessages(t.Context(), []vtypes.VerificationTask{newTask(msgID(3))})

	require.Len(t, results, 1)
	require.NotNil(t, results[0].Error)
	assert.Equal(t, "policy hook rejected message "+msgID(3), results[0].Error.Error.Error())
}

func TestGatedVerifier_EndpointErrorIsRetried(t *testing.T) {
	checker := &stubChecker{errs: map[string]error{
		msgID(4): errors.New("policy endpoint returned status 503"),
	}}
	inner := &stubVerifier{}
	gate := newGate(t, checker, inner)

	results := gate.VerifyMessages(t.Context(), []vtypes.VerificationTask{newTask(msgID(4))})

	require.Len(t, results, 1)
	require.NotNil(t, results[0].Error)
	assert.True(t, results[0].Error.Retryable,
		"an endpoint outage must retry: treating it as a rejection would drop traffic during an outage")
	delay := results[0].Error.DelayOrDefault()
	assert.GreaterOrEqual(t, delay, 500*time.Millisecond,
		"a jittered retry never lands below half the configured delay")
	assert.LessOrEqual(t, delay, 1500*time.Millisecond,
		"a jittered retry never lands above one and a half times the configured delay")
	assert.Empty(t, inner.forwarded(), "a message with an unknown verdict is not signed yet")
}

// TestGatedVerifier_RetryDelayIsJittered pins the spread. An outage holds every message the
// verifier has in flight, and a fixed delay would reschedule all of them onto the same tick, so
// the entire backlog would arrive at the endpoint together on every retry for as long as the
// outage lasted.
func TestGatedVerifier_RetryDelayIsJittered(t *testing.T) {
	gate := newGate(t, &stubChecker{}, &stubVerifier{})

	seen := make(map[time.Duration]struct{})
	for range 500 {
		delay := gate.retryDelayWithJitter()
		require.GreaterOrEqual(t, delay, 500*time.Millisecond)
		require.LessOrEqual(t, delay, 1500*time.Millisecond)
		seen[delay] = struct{}{}
	}
	assert.Greater(t, len(seen), 1, "a fixed delay would synchronize every held message onto one tick")
}

func TestGatedVerifier_MixedBatch(t *testing.T) {
	checker := &stubChecker{
		verdicts: map[string]Verdict{msgID(2): {Decision: DecisionFail, Reason: "blocked"}},
		errs:     map[string]error{msgID(3): errors.New("policy endpoint unreachable")},
	}
	inner := &stubVerifier{}
	gate := newGate(t, checker, inner)

	tasks := []vtypes.VerificationTask{
		newTask(msgID(1)), newTask(msgID(2)), newTask(msgID(3)), newTask(msgID(4)),
	}
	results := gate.VerifyMessages(t.Context(), tasks)

	// The task verifier maps every result back to a queue job by message ID, so each task must
	// produce exactly one result. A missing one leaves its job stuck until the lock goes stale.
	require.Len(t, results, len(tasks))
	byID := resultsByMessageID(t, results)
	require.Len(t, byID, len(tasks))

	require.NotNil(t, byID[msgID(1)].Result)
	require.NotNil(t, byID[msgID(4)].Result)

	require.NotNil(t, byID[msgID(2)].Error)
	assert.False(t, byID[msgID(2)].Error.Retryable)

	require.NotNil(t, byID[msgID(3)].Error)
	assert.True(t, byID[msgID(3)].Error.Retryable)

	assert.ElementsMatch(t, []string{msgID(1), msgID(4)}, inner.forwarded())
	assert.Equal(t, len(tasks), checker.callCount(), "one endpoint call per message")
}

func TestGatedVerifier_EmptyBatch(t *testing.T) {
	checker := &stubChecker{}
	gate := newGate(t, checker, &stubVerifier{})

	assert.Nil(t, gate.VerifyMessages(t.Context(), nil))
	assert.Nil(t, gate.VerifyMessages(t.Context(), []vtypes.VerificationTask{}))
	assert.Zero(t, checker.callCount(), "an empty batch does not touch the endpoint")
}

func TestGatedVerifier_BoundsConcurrency(t *testing.T) {
	checker := &stubChecker{}
	gate := newGate(t, checker, &stubVerifier{})

	tasks := make([]vtypes.VerificationTask, 0, 40)
	for i := range 40 {
		tasks = append(tasks, newTask(msgID(byte(i+1))))
	}

	results := gate.VerifyMessages(t.Context(), tasks)

	require.Len(t, results, len(tasks))
	assert.Equal(t, len(tasks), checker.callCount())
	assert.LessOrEqual(t, checker.peakConcurrency(), maxConcurrentEvaluations,
		"a batch must not fan out past the configured width onto an operator's endpoint")
}

func TestNewGatedVerifier_RequiresDependencies(t *testing.T) {
	lggr := logger.Test(t)
	mon := monitoring.NewFakeVerifierMonitoring()

	_, err := NewGatedVerifier(lggr, "v", nil, &stubChecker{}, mon, time.Second)
	require.ErrorContains(t, err, "inner verifier")

	_, err = NewGatedVerifier(lggr, "v", &stubVerifier{}, nil, mon, time.Second)
	require.ErrorContains(t, err, "policy checker")

	_, err = NewGatedVerifier(nil, "v", &stubVerifier{}, &stubChecker{}, mon, time.Second)
	require.ErrorContains(t, err, "logger")

	_, err = NewGatedVerifier(lggr, "v", &stubVerifier{}, &stubChecker{}, nil, time.Second)
	require.ErrorContains(t, err, "monitoring")
}

func TestNewGatedVerifier_DefaultsRetryDelay(t *testing.T) {
	gate, err := NewGatedVerifier(
		logger.Test(t), "v", &stubVerifier{}, &stubChecker{},
		monitoring.NewFakeVerifierMonitoring(), 0,
	)
	require.NoError(t, err)
	assert.Equal(t, DefaultRetryDelay, gate.retryDelay)
}

// The contract promises a FAIL reason past 256 characters is truncated. HTTPChecker bounds what
// it returns, but Checker is an exported interface, so the gate bounds it again at the point the
// promise is spent: the log line and the archived job's error, which is retained for 30 days.
func TestGatedVerifier_TruncatesOversizedRejectionReason(t *testing.T) {
	oversized := strings.Repeat("x", maxReasonLength+500)
	checker := &stubChecker{verdicts: map[string]Verdict{
		msgID(1): {Decision: DecisionFail, Reason: oversized},
	}}
	inner := &stubVerifier{}

	results := newGate(t, checker, inner).VerifyMessages(
		t.Context(), []vtypes.VerificationTask{newTask(msgID(1))})
	require.Len(t, results, 1)
	require.NotNil(t, results[0].Error)

	got := results[0].Error.Error.Error()
	assert.Less(t, len(got), len(oversized), "the archived error must not carry the whole reason")
	assert.Contains(t, got, "...(truncated)")
	assert.Empty(t, inner.forwarded(), "a FAIL must still not reach the wrapped verifier")
}

func TestWrapVerifier(t *testing.T) {
	inner := &stubVerifier{}
	lggr := logger.Test(t)
	mon := monitoring.NewFakeVerifierMonitoring()

	t.Run("no config leaves the verifier untouched", func(t *testing.T) {
		got, err := WrapVerifier(lggr, "v", inner, nil, mon, nil)
		require.NoError(t, err)
		assert.Same(t, inner, got, "a verifier without a hook must not gain a layer")
	})

	t.Run("config wraps the verifier", func(t *testing.T) {
		got, err := WrapVerifier(lggr, "v", inner, &Config{
			BaseURL:    "https://policy.example.com",
			RetryDelay: "3s",
		}, mon, nil)
		require.NoError(t, err)

		gate, ok := got.(*GatedVerifier)
		require.True(t, ok)
		assert.Equal(t, 3*time.Second, gate.retryDelay)
	})

	t.Run("invalid config fails construction", func(t *testing.T) {
		_, err := WrapVerifier(lggr, "v", inner, &Config{BaseURL: "not a url at all"}, mon, nil)
		require.Error(t, err)
	})

	t.Run("require_auth without a credential fails construction", func(t *testing.T) {
		// The failure has to happen here rather than at the first message: a credential that
		// never reached the container would otherwise show up as every message on the lane
		// retrying against a 401.
		_, err := WrapVerifier(lggr, "v", inner, &Config{
			BaseURL:     "https://policy.example.com",
			RequireAuth: true,
		}, mon, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "secrets file", "the error must name where the credential is meant to come from")
		assert.Contains(t, err.Error(), "api_key")
	})

	t.Run("require_auth with a credential wraps the verifier", func(t *testing.T) {
		got, err := WrapVerifier(lggr, "v", inner, &Config{
			BaseURL:     "https://policy.example.com",
			RequireAuth: true,
		}, mon, testCredential())
		require.NoError(t, err)
		assert.NotSame(t, inner, got)
	})
}

func TestGatedVerifier_InvalidTaskSkipsTheEndpoint(t *testing.T) {
	rejected := errors.New("unsupported message version: 99")
	checker := &stubChecker{}
	inner := &validatingVerifier{invalid: map[string]error{msgID(1): rejected}}
	gate := newGate(t, checker, inner)

	results := gate.VerifyMessages(t.Context(), []vtypes.VerificationTask{newTask(msgID(1))})

	assert.Zero(t, checker.callCount(),
		"the hook gates messages this verifier would sign, so a task it already rejects costs the operator nothing")

	// The gate does not invent a result for the skipped task. It forwards it and the verifier
	// fails it with its own error, which is what an ungated verifier would have recorded.
	require.Len(t, results, 1)
	require.NotNil(t, results[0].Error)
	assert.False(t, results[0].Error.Retryable)
	assert.Equal(t, rejected.Error(), results[0].Error.Error.Error())
	assert.Equal(t, []string{msgID(1)}, inner.forwarded())
}

func TestGatedVerifier_OnlyValidTasksReachTheEndpoint(t *testing.T) {
	checker := &stubChecker{
		verdicts: map[string]Verdict{msgID(3): {Decision: DecisionFail, Reason: "sanctioned sender"}},
	}
	inner := &validatingVerifier{invalid: map[string]error{
		msgID(1): errors.New("receiver cannot be empty"),
		msgID(4): errors.New("message source chain selector 99 is not configured"),
	}}
	gate := newGate(t, checker, inner)

	tasks := []vtypes.VerificationTask{
		newTask(msgID(1)), newTask(msgID(2)), newTask(msgID(3)), newTask(msgID(4)),
	}
	results := gate.VerifyMessages(t.Context(), tasks)

	assert.ElementsMatch(t, []string{msgID(2), msgID(3)}, checker.callsMade(),
		"only the tasks the verifier would sign are worth an endpoint call")

	// Every task still produces exactly one result, or its queue job hangs until the lock goes stale.
	require.Len(t, results, len(tasks))
	byID := resultsByMessageID(t, results)
	require.Len(t, byID, len(tasks))

	require.NotNil(t, byID[msgID(2)].Result, "the one valid task that passed policy is signed")

	require.NotNil(t, byID[msgID(3)].Error)
	assert.Contains(t, byID[msgID(3)].Error.Error.Error(), "policy hook rejected")

	for _, id := range []string{msgID(1), msgID(4)} {
		require.NotNil(t, byID[id].Error)
		assert.NotContains(t, byID[id].Error.Error.Error(), "policy",
			"a task the verifier rejects keeps the verifier's own error, so it is not counted as a policy drop")
	}
}

func TestGatedVerifier_EndpointCalledForEveryTaskWithoutAValidator(t *testing.T) {
	// stubVerifier does not implement vtypes.TaskValidator. The gate has to keep working with a
	// verifier that cannot tell it anything in advance, which is the contract that lets the gate
	// wrap implementations other than the commit verifier.
	checker := &stubChecker{}
	inner := &stubVerifier{}
	gate := newGate(t, checker, inner)
	require.Nil(t, gate.precheck)

	tasks := []vtypes.VerificationTask{newTask(msgID(1)), newTask(msgID(2))}
	results := gate.VerifyMessages(t.Context(), tasks)

	require.Len(t, results, len(tasks))
	assert.Equal(t, len(tasks), checker.callCount())
}

func TestGatedVerifier_PrecheckIsDiscoveredFromTheWrappedVerifier(t *testing.T) {
	gate := newGate(t, &stubChecker{}, &validatingVerifier{})
	assert.NotNil(t, gate.precheck,
		"a verifier that implements vtypes.TaskValidator must be used as the precheck, or the hook runs before the verifier's own checks again")
}

// TestGatedVerifier_PassCannotOverrideVerification is the security property the hook is defined
// by: it can only subtract a signature, never add one. A PASS is not an instruction to sign. It
// only forwards the task to the wrapped verifier, which then runs every one of its own checks and
// signs or refuses on its own terms.
//
// Structurally the gate cannot do otherwise: the only results it authors are the two error cases
// in VerifyMessages, so every non-error result in what it returns came out of
// inner.VerifyMessages. This test pins that against a refactor, with a verifier that clears the
// precheck (so the endpoint really is consulted and really does answer PASS) and then fails
// verification anyway.
func TestGatedVerifier_PassCannotOverrideVerification(t *testing.T) {
	signingFailure := errors.New("failed to resolve signable payload: unknown ccv address")
	checker := &stubChecker{} // PASS for everything.
	inner := &lateFailingVerifier{failVerification: map[string]error{msgID(1): signingFailure}}
	gate := newGate(t, checker, inner)

	tasks := []vtypes.VerificationTask{newTask(msgID(1)), newTask(msgID(2))}
	results := gate.VerifyMessages(t.Context(), tasks)

	// Order is not asserted: the gate evaluates a batch concurrently.
	require.ElementsMatch(t, []string{msgID(1), msgID(2)}, checker.callsMade(),
		"both tasks must reach the endpoint, or this proves nothing about what a PASS can do")

	byID := resultsByMessageID(t, results)
	require.Len(t, byID, len(tasks))

	// The task the verifier refuses stays refused, and keeps the verifier's own error rather
	// than anything the endpoint had to say about it.
	require.Nil(t, byID[msgID(1)].Result, "a PASS must not produce a signature the verifier withheld")
	require.NotNil(t, byID[msgID(1)].Error)
	assert.Equal(t, signingFailure.Error(), byID[msgID(1)].Error.Error.Error())
	assert.NotContains(t, byID[msgID(1)].Error.Error.Error(), "policy")

	// And the gate is not simply failing everything: the task the verifier accepts is signed.
	require.NotNil(t, byID[msgID(2)].Result)
}

// The gate authors results in exactly one place, and both of its cases are errors. Anything with
// a Result came from the wrapped verifier. A change that let the gate build a Result would make
// a PASS able to manufacture a signature, so it is worth failing a test over.
func TestGatedVerifier_NeverAuthorsASuccessfulResult(t *testing.T) {
	checker := &stubChecker{
		verdicts: map[string]Verdict{msgID(2): {Decision: DecisionFail}},
		errs:     map[string]error{msgID(3): errors.New("endpoint down")},
	}
	// Forwarded tasks all fail, so every result in the batch has to be an error: the two the
	// gate authors plus the one the verifier authors.
	inner := &lateFailingVerifier{failVerification: map[string]error{
		msgID(1): errors.New("receiver cannot be empty"),
	}}
	gate := newGate(t, checker, inner)

	results := gate.VerifyMessages(t.Context(), []vtypes.VerificationTask{
		newTask(msgID(1)), newTask(msgID(2)), newTask(msgID(3)),
	})

	require.Len(t, results, 3)
	for _, r := range results {
		assert.Nil(t, r.Result, "no successful result can originate in the gate")
		require.NotNil(t, r.Error)
	}
}
