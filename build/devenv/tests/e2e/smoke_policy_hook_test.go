package e2e

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	chain_selectors "github.com/smartcontractkit/chain-selectors"
	ccv "github.com/smartcontractkit/chainlink-ccv/build/devenv"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	devenvcommon "github.com/smartcontractkit/chainlink-ccv/build/devenv/common"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/logasserter"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/verifiercli"
	verifier "github.com/smartcontractkit/chainlink-ccv/verifier/pkg"
	"github.com/smartcontractkit/chainlink-testing-framework/framework"
)

// TestE2ESmoke_PolicyHook exercises the operator policy hook end to end against a real committee,
// covering the three behaviors the feature is defined by:
//
//  1. PASS is transparent — a message the endpoint approves is attested exactly as it would be
//     with no hook, and the endpoint really was consulted.
//  2. An endpoint outage retries — while the endpoint returns 5xx the message is held, not
//     dropped, and it lands on its own once the endpoint recovers, with no operator action.
//  3. FAIL drops — the message is never attested, deleting the rejection afterwards does not
//     bring it back, and a checkpoint rewind replays it.
//
// It needs the standard.policy-hook.profile: both NOPs of the default committee point at the
// fake policy endpoint, and the source chain must support manual block progress so the test
// controls when a message reaches finality.
func TestE2ESmoke_PolicyHook(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode; requires a running devenv environment")
	}
	smokeTestConfig := GetSmokeTestConfig()
	in, err := ccv.LoadOutput[ccv.Cfg](smokeTestConfig)
	require.NoError(t, err)

	ctx := ccv.Plog.WithContext(t.Context())
	lib, err := ccv.NewLibFromCCVEnv(zerolog.Ctx(ctx), smokeTestConfig, chain_selectors.FamilyEVM)
	require.NoError(t, err)
	chains, err := lib.Chains(ctx)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(chains), 2, "expected at least 2 chains")

	src, progressable, ok := chainSupportingManualBlockProgress(ctx, chains)
	require.True(t, ok,
		"expected a chain implementing ProgressableChain with SupportManualBlockProgress; run with standard.policy-hook.profile")
	srcSelector := src.Details.ChainSelector

	var dest ccv.ChainImpl
	for _, ch := range chains {
		if ch.Details.ChainSelector != srcSelector {
			dest = ch
			break
		}
	}
	require.NotZero(t, dest.Details.ChainSelector, "expected a destination chain distinct from the source")
	destSelector := dest.Details.ChainSelector
	receiver := mustGetEOAReceiverAddress(t, dest)

	aggregatorClient, err := in.NewAggregatorClientForCommittee(
		zerolog.Ctx(ctx).With().Str("component", "aggregator-client").Logger(),
		devenvcommon.DefaultCommitteeVerifierQualifier)
	require.NoError(t, err)
	t.Cleanup(func() { _ = aggregatorClient.Close() })

	policy := newPolicyFake(t, in)
	policy.reset(t, ctx)
	t.Cleanup(func() {
		// Leave the endpoint passing everything so a reused environment is not poisoned for
		// the next test.
		policy.reset(t, context.Background())
		_, _ = framework.SaveContainerLogs(fmt.Sprintf("%s-%s", framework.DefaultCTFLogsDir, t.Name()))
	})

	committee := newVerifierCommitteeClientForSmoke(t, in)
	committee.ResumeAllBestEffort(ctx)
	t.Cleanup(func() { committee.ResumeAllBestEffort(ctx) })

	logAssert := logasserter.New(DefaultLokiURL, zerolog.Ctx(ctx).With().Str("component", "log-asserter").Logger())
	require.NoError(t, logAssert.StartStreaming(ctx, []logasserter.LogStage{
		logasserter.MessageReachedVerifier(),
		logasserter.MessageDroppedByPolicyHook(),
		logasserter.PolicyHookVerdictUnavailable(),
	}))
	t.Cleanup(logAssert.StopStreaming)

	messageOpts := committeeV3MessageOptions(t, in, srcSelector)
	advanceBlocks := func(numBlocks int) {
		require.NoError(t, progressable.AdvanceBlocks(ctx, numBlocks), "advance %d blocks", numBlocks)
		time.Sleep(3 * time.Second)
	}
	send := func() cciptestinterfaces.MessageSentEvent {
		return sendMessageAndConfirm(t, ctx, src, destSelector,
			cciptestinterfaces.MessageFields{Receiver: receiver}, messageOpts, 3)
	}

	// Phase 1: the endpoint passes, so the message is attested as usual.
	passed := send()
	advanceBlocks(verifier.ConfirmationDepth + 5)
	requireAggregatorResult(t, ctx, aggregatorClient, passed.MessageID,
		"a message the policy endpoint passed must reach the aggregator")
	require.Positive(t, policy.callsFor(t, ctx, passed.MessageID),
		"the endpoint must actually have been consulted, otherwise this test proves nothing about the hook")

	// Phase 2: the endpoint is down. The message must be held and retried, never dropped, and it
	// must land on its own once the endpoint recovers - no checkpoint rewind, no operator action.
	policy.forceStatus(t, ctx, http.StatusServiceUnavailable)
	held := send()
	advanceBlocks(verifier.ConfirmationDepth + 5)

	retryCtx, cancelRetry := context.WithTimeout(ctx, 90*time.Second)
	defer cancelRetry()
	_, err = logAssert.WaitForStage(retryCtx, held.MessageID, logasserter.PolicyHookVerdictUnavailable())
	require.NoError(t, err, "an endpoint outage must be logged as a retry, not a drop")

	requireNoAggregatorResult(t, ctx, aggregatorClient, held.MessageID,
		"a message must not be attested while the policy verdict is unknown")
	require.Greater(t, policy.callsFor(t, ctx, held.MessageID), 2,
		"with two gated committee nodes, more than two calls means the message was retried rather than abandoned")

	policy.endOutage(t, ctx)
	requireAggregatorResult(t, ctx, aggregatorClient, held.MessageID,
		"a held message must be attested once the endpoint recovers, with no checkpoint rewind")

	// Phase 3: the endpoint rejects one message. Register the rejection before the message
	// reaches finality, since that is when the verifier consults the endpoint.
	rejected := send()
	policy.rejectMessage(t, ctx, rejected.MessageID, "sanctioned sender (devenv test)")
	advanceBlocks(verifier.ConfirmationDepth + 5)

	reachedCtx, cancelReached := context.WithTimeout(ctx, 60*time.Second)
	defer cancelReached()
	_, err = logAssert.WaitForStage(reachedCtx, rejected.MessageID, logasserter.MessageReachedVerifier())
	require.NoError(t, err, "message should reach the verifier before it is dropped")

	dropCtx, cancelDrop := context.WithTimeout(ctx, 60*time.Second)
	defer cancelDrop()
	_, err = logAssert.WaitForStage(dropCtx, rejected.MessageID, logasserter.MessageDroppedByPolicyHook())
	require.NoError(t, err, "a FAIL verdict must drop the message in the verifier")

	requireNoAggregatorResult(t, ctx, aggregatorClient, rejected.MessageID,
		"a rejected message must not be attested")

	// Move the checkpoint well past the dropped message, then stop rejecting it. A drop is
	// terminal: clearing the rejection alone must not bring the message back.
	advanceBlocks(verifier.ConfirmationDepth*3 + 30)
	policy.reset(t, ctx)
	advanceBlocks(verifier.ConfirmationDepth + 5)
	requireNoAggregatorResult(t, ctx, aggregatorClient, rejected.MessageID,
		"a dropped message must not reappear just because the endpoint stopped rejecting it")

	// Only replay recovers it: rewind the committee checkpoint and let the message be read again.
	require.NoError(t, committee.RewindFinalizedHeight(ctx,
		verifiercli.FormatChainSelector(srcSelector), verifiercli.FormatBlockHeight(0)),
		"rewind committee finalized height")

	advanceBlocks(verifier.ConfirmationDepth*2 + 10)

	// The rescan starts at block 0 and re-verifies every message this test sent, so the replay
	// gets the same budget the curse-recovery test allows rather than the 45s a fresh message gets.
	replayCtx, cancelReplay := context.WithTimeout(ctx, 120*time.Second)
	defer cancelReplay()
	_, err = aggregatorClient.WaitForVerifierResultForMessage(replayCtx, rejected.MessageID, time.Second)
	require.NoError(t, err, "a dropped message must be recoverable by replaying from a rewound checkpoint")
}
