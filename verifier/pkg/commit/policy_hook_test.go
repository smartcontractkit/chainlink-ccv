package commit

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/policy"
	verifier "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vtypes"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// fixedChecker answers every message with the same verdict.
type fixedChecker struct {
	verdict policy.Verdict
}

func (c fixedChecker) Evaluate(context.Context, policy.EvaluateRequest) (policy.Verdict, error) {
	return c.verdict, nil
}

// TestPolicyHook_SignedPayloadUnchanged covers the ticket's acceptance criterion that the signed
// payload and signature are identical with and without the hook. The gate calls the endpoint
// before the commit verifier runs and discards the response once the verdict is read, so nothing
// the endpoint returns can reach the signature — this pins that down.
func TestPolicyHook_SignedPayloadUnchanged(t *testing.T) {
	signer, addr := newTestSigner(t)
	executorAddr := protocol.UnknownAddress([]byte{0xEE})
	const (
		sourceChain protocol.ChainSelector = 1
		destChain   protocol.ChainSelector = 2
	)
	config := newSingleChainConfig(sourceChain, addr, executorAddr)
	blob := []byte{0xAA, 0xBB, 0xCC, 0xDD}

	newVerifier := func(t *testing.T) verifier.Verifier {
		t.Helper()
		cv, err := NewCommitVerifier(config, addr, signer, logger.Test(t), monitoring.NewFakeVerifierMonitoring())
		require.NoError(t, err)
		return cv
	}

	runOnce := func(t *testing.T, v verifier.Verifier) *protocol.VerifierNodeResult {
		t.Helper()
		task := newVerifiableTask(t, sourceChain, destChain, addr, blob, executorAddr)
		results := v.VerifyMessages(t.Context(), []verifier.VerificationTask{task})
		require.Len(t, results, 1)
		require.Nil(t, results[0].Error)
		require.NotNil(t, results[0].Result)
		return results[0].Result
	}

	// Establish that signing is deterministic first, so the comparison below means what it
	// claims. If this ever fails, the signer changed, not the hook.
	baseline := runOnce(t, newVerifier(t))
	repeat := runOnce(t, newVerifier(t))
	require.Equal(t, baseline, repeat, "commit verification must be deterministic for this comparison to hold")

	gated, err := policy.NewGatedVerifier(
		logger.Test(t), "committee-verifier-1", newVerifier(t),
		// A reason on a PASS is still ignored: only the verdict is read.
		fixedChecker{verdict: policy.Verdict{Decision: policy.DecisionPass, Reason: "reviewed by ACME AML"}},
		monitoring.NewFakeVerifierMonitoring(), 0,
	)
	require.NoError(t, err)

	withHook := runOnce(t, gated)

	assert.Equal(t, baseline.Signature, withHook.Signature, "signature must not depend on the hook")
	assert.Equal(t, baseline, withHook, "the whole signed result must be byte-identical to an ungated run")
}

// TestPolicyHook_FailNeverSigns is the other half of the criterion: a rejected message produces no
// signed result at all, so nothing reaches the aggregator for it.
func TestPolicyHook_FailNeverSigns(t *testing.T) {
	signer, addr := newTestSigner(t)
	executorAddr := protocol.UnknownAddress([]byte{0xEE})
	const (
		sourceChain protocol.ChainSelector = 1
		destChain   protocol.ChainSelector = 2
	)
	config := newSingleChainConfig(sourceChain, addr, executorAddr)
	cv, err := NewCommitVerifier(config, addr, signer, logger.Test(t), monitoring.NewFakeVerifierMonitoring())
	require.NoError(t, err)

	gated, err := policy.NewGatedVerifier(
		logger.Test(t), "committee-verifier-1", cv,
		fixedChecker{verdict: policy.Verdict{Decision: policy.DecisionFail, Reason: "sanctioned sender"}},
		monitoring.NewFakeVerifierMonitoring(), 0,
	)
	require.NoError(t, err)

	task := newVerifiableTask(t, sourceChain, destChain, addr, []byte{0xAA, 0xBB, 0xCC, 0xDD}, executorAddr)
	results := gated.VerifyMessages(t.Context(), []verifier.VerificationTask{task})

	require.Len(t, results, 1)
	assert.Nil(t, results[0].Result, "a rejected message must produce no signed result")
	require.NotNil(t, results[0].Error)
	assert.False(t, results[0].Error.Retryable)
}

// failingSigner clears every check that does not need the signer and then refuses to sign. It is
// how this file reaches the signing-time failure path: ValidateTask is by construction the part of
// verification that runs without the signer, so no task shape can make the precheck report a
// signer error.
type failingSigner struct {
	err error
}

func (s failingSigner) Sign([]byte) ([]byte, error) { return nil, s.err }

// recordingChecker answers every message with the same verdict and counts the calls, so a test
// can tell "the endpoint passed it and the verifier still refused" apart from "the endpoint was
// never asked".
type recordingChecker struct {
	verdict policy.Verdict
	calls   int
}

func (c *recordingChecker) Evaluate(context.Context, policy.EvaluateRequest) (policy.Verdict, error) {
	c.calls++
	return c.verdict, nil
}

// TestPolicyHook_PassCannotBypassVerification is the answer to "are the policy checks purely
// additive": they are. A PASS is not an instruction to sign. It only lets the task reach the
// commit verifier, which then applies every check it would have applied with no hook configured.
//
// Both subtests run the real commit verifier rather than a stub, and both assert the same two
// things: no signature, and an error identical to the one an ungated verifier produces. What
// separates them is whether the endpoint was consulted at all, which is asserted rather than
// assumed, because the two paths reach the same outcome for different reasons and a test that
// silently took the wrong one would prove much less than it appears to.
func TestPolicyHook_PassCannotBypassVerification(t *testing.T) {
	executorAddr := protocol.UnknownAddress([]byte{0xEE})
	const (
		configuredSourceChain protocol.ChainSelector = 1
		destChain             protocol.ChainSelector = 2
		// Not in the verifier's config, so the verifier refuses the task before signing,
		// whatever the endpoint would have said about it.
		unconfiguredSourceChain protocol.ChainSelector = 99
	)
	verifierBlob := []byte{0xAA, 0xBB, 0xCC, 0xDD}

	// The case the property is actually about. The task is well formed, so it clears the
	// precheck and the endpoint is asked and answers PASS; the verifier then fails at signing
	// time. A PASS in hand, and still no signature.
	t.Run("endpoint passed and the verifier failed at signing", func(t *testing.T) {
		_, addr := newTestSigner(t)
		signingFailure := errors.New("hsm unavailable")
		config := newSingleChainConfig(configuredSourceChain, addr, executorAddr)
		cv, err := NewCommitVerifier(config, addr, failingSigner{err: signingFailure},
			logger.Test(t), monitoring.NewFakeVerifierMonitoring())
		require.NoError(t, err)

		checker := &recordingChecker{verdict: policy.Verdict{Decision: policy.DecisionPass}}
		gated, err := policy.NewGatedVerifier(
			logger.Test(t), "committee-verifier-1", cv, checker,
			monitoring.NewFakeVerifierMonitoring(), 0,
		)
		require.NoError(t, err)

		task := newVerifiableTask(t, configuredSourceChain, destChain, addr, verifierBlob, executorAddr)
		results := gated.VerifyMessages(t.Context(), []verifier.VerificationTask{task})

		require.Equal(t, 1, checker.calls,
			"the endpoint must have been asked and answered PASS, or this proves nothing about what a PASS can do")

		require.Len(t, results, 1)
		assert.Nil(t, results[0].Result, "a PASS must not produce a signature the verifier withheld")
		require.NotNil(t, results[0].Error)
		assert.Contains(t, results[0].Error.Error.Error(), signingFailure.Error(),
			"the result must carry the verifier's own signing failure")
		assert.NotContains(t, results[0].Error.Error.Error(), "policy hook",
			"the gate did not author this result")

		assertUngatedFailsIdentically(t, cv, task, results[0])
	})

	// The complementary path: the verifier rejects the task before signing, so the gate skips
	// the endpoint entirely. Asserted here so the skip stays deliberate, and so the subtest
	// above cannot quietly become this one if the precheck ever widens.
	t.Run("verifier rejected before signing, so the endpoint was never asked", func(t *testing.T) {
		signer, addr := newTestSigner(t)
		config := newSingleChainConfig(configuredSourceChain, addr, executorAddr)
		cv, err := NewCommitVerifier(config, addr, signer, logger.Test(t), monitoring.NewFakeVerifierMonitoring())
		require.NoError(t, err)

		checker := &recordingChecker{verdict: policy.Verdict{Decision: policy.DecisionPass}}
		gated, err := policy.NewGatedVerifier(
			logger.Test(t), "committee-verifier-1", cv, checker,
			monitoring.NewFakeVerifierMonitoring(), 0,
		)
		require.NoError(t, err)

		task := newVerifiableTask(t, unconfiguredSourceChain, destChain, addr, verifierBlob, executorAddr)
		results := gated.VerifyMessages(t.Context(), []verifier.VerificationTask{task})

		assert.Zero(t, checker.calls,
			"the hook gates messages this verifier would sign, so a task it already rejects costs the operator nothing")

		require.Len(t, results, 1)
		assert.Nil(t, results[0].Result, "a task the verifier rejects is never signed")
		require.NotNil(t, results[0].Error)
		assert.NotContains(t, results[0].Error.Error.Error(), "policy hook",
			"a task the verifier rejects keeps the verifier's own error, so it is not counted as a policy drop")

		assertUngatedFailsIdentically(t, cv, task, results[0])
	})
}

// assertUngatedFailsIdentically is the statement of "additive": the same task through the
// unwrapped verifier fails with the same error, so enabling the hook cannot change this outcome
// in either direction.
func assertUngatedFailsIdentically(
	t *testing.T,
	cv verifier.Verifier,
	task verifier.VerificationTask,
	gatedResult verifier.VerificationResult,
) {
	t.Helper()

	ungated := cv.VerifyMessages(t.Context(), []verifier.VerificationTask{task})
	require.Len(t, ungated, 1)
	assert.Nil(t, ungated[0].Result)
	require.NotNil(t, ungated[0].Error)
	assert.Equal(t, ungated[0].Error.Error.Error(), gatedResult.Error.Error.Error())
	assert.Equal(t, ungated[0].Error.Retryable, gatedResult.Error.Retryable)
}
