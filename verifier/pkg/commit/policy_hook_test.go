package commit

import (
	"context"
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
