package e2e

import (
	"context"
	"fmt"
	"net/http"
	"strings"
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
// covering the four behaviors the feature is defined by:
//
//  1. PASS is transparent — a message the endpoint approves is attested exactly as it would be
//     with no hook, and the endpoint really was consulted.
//  2. An endpoint outage retries — while the endpoint returns 5xx the message is held, not
//     dropped, and it lands on its own once the endpoint recovers, with no operator action.
//  3. FAIL drops — the message is never attested, deleting the rejection afterwards does not
//     bring it back, and a checkpoint rewind replays it.
//  4. A FAIL drop is also recoverable by reschedule — after the endpoint clears, moving the
//     archived job back to the active queue on every committee member, with the node still
//     running, gets the message attested, and the endpoint is consulted again.
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

	// The phases share one environment and run in order, but each leaves the endpoint able to
	// pass everything, so any single one can be run on its own with -run
	// 'TestE2ESmoke_PolicyHook/<name>' against an environment that is already up.
	t.Run("pass is transparent", func(t *testing.T) {
		passed := send()
		advanceBlocks(verifier.ConfirmationDepth + 5)
		requireAggregatorResult(t, ctx, aggregatorClient, passed.MessageID,
			"a message the policy endpoint passed must reach the aggregator")
		require.Positive(t, policy.callsFor(t, ctx, passed.MessageID),
			"the endpoint must actually have been consulted, otherwise this test proves nothing about the hook")
	})

	// The endpoint is down. The message must be held and retried, never dropped, and it must
	// land on its own once the endpoint recovers - no checkpoint rewind, no operator action.
	t.Run("endpoint outage retries", func(t *testing.T) {
		// Whatever this phase asserts, the endpoint has to be passing again by the time it
		// returns, or every later phase inherits the outage.
		t.Cleanup(func() { policy.endOutage(t, context.WithoutCancel(ctx)) })

		policy.forceStatus(t, ctx, http.StatusServiceUnavailable)
		held := send()
		advanceBlocks(verifier.ConfirmationDepth + 5)

		retryCtx, cancelRetry := context.WithTimeout(ctx, 90*time.Second)
		defer cancelRetry()
		_, err := logAssert.WaitForStage(retryCtx, held.MessageID, logasserter.PolicyHookVerdictUnavailable())
		require.NoError(t, err, "an endpoint outage must be logged as a retry, not a drop")

		requireNoAggregatorResult(t, ctx, aggregatorClient, held.MessageID,
			"a message must not be attested while the policy verdict is unknown")
		require.Greater(t, policy.callsFor(t, ctx, held.MessageID), 2,
			"with two gated committee nodes, more than two calls means the message was retried rather than abandoned")

		policy.endOutage(t, ctx)
		requireAggregatorResult(t, ctx, aggregatorClient, held.MessageID,
			"a held message must be attested once the endpoint recovers, with no checkpoint rewind")
	})

	// The endpoint rejects one message. Register the rejection before the message reaches
	// finality, since that is when the verifier consults the endpoint.
	t.Run("fail drops and only replay recovers", func(t *testing.T) {
		rejected := send()
		policy.rejectMessage(t, ctx, rejected.MessageID, "sanctioned sender (devenv test)")
		advanceBlocks(verifier.ConfirmationDepth + 5)

		reachedCtx, cancelReached := context.WithTimeout(ctx, 60*time.Second)
		defer cancelReached()
		_, err := logAssert.WaitForStage(reachedCtx, rejected.MessageID, logasserter.MessageReachedVerifier())
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

		// Only replay recovers it: rewind the committee checkpoint and let the message be read
		// again.
		require.NoError(t, committee.RewindFinalizedHeight(ctx,
			verifiercli.FormatChainSelector(srcSelector), verifiercli.FormatBlockHeight(0)),
			"rewind committee finalized height")

		advanceBlocks(verifier.ConfirmationDepth*2 + 10)

		// The rescan starts at block 0 and re-verifies every message this test sent, so the
		// replay gets the same budget the curse-recovery test allows rather than the 45s a
		// fresh message gets.
		replayCtx, cancelReplay := context.WithTimeout(ctx, 120*time.Second)
		defer cancelReplay()
		_, err = aggregatorClient.WaitForVerifierResultForMessage(replayCtx, rejected.MessageID, time.Second)
		require.NoError(t, err, "a dropped message must be recoverable by replaying from a rewound checkpoint")
	})

	// The per-message lever the runbook recommends: the endpoint rejects one message, the job
	// lands in each member's archive, and an operator recovers it with `job-queue reschedule`
	// against the running node - no pause, no restart, no checkpoint rewind. This is the
	// composition TestE2ESmoke_JobQueueCLI does not cover: there the rescheduled row is
	// synthetic and the verifier never consumes it.
	t.Run("fail drops and reschedule recovers", func(t *testing.T) {
		// Leave the endpoint passing for a reused environment even if the test fails while the
		// rejection is still registered.
		t.Cleanup(func() { policy.reset(t, context.WithoutCancel(ctx)) })

		rejected := send()
		policy.rejectMessage(t, ctx, rejected.MessageID, "sanctioned sender (devenv test)")
		advanceBlocks(verifier.ConfirmationDepth + 5)

		reachedCtx, cancelReached := context.WithTimeout(ctx, 60*time.Second)
		defer cancelReached()
		_, err := logAssert.WaitForStage(reachedCtx, rejected.MessageID, logasserter.MessageReachedVerifier())
		require.NoError(t, err, "message should reach the verifier before it is dropped")

		dropCtx, cancelDrop := context.WithTimeout(ctx, 60*time.Second)
		defer cancelDrop()
		_, err = logAssert.WaitForStage(dropCtx, rejected.MessageID, logasserter.MessageDroppedByPolicyHook())
		require.NoError(t, err, "a FAIL verdict must drop the message in the verifier")

		requireNoAggregatorResult(t, ctx, aggregatorClient, rejected.MessageID,
			"a rejected message must not be attested")

		// The drop archives one job per committee member, in that member's own database. Wait
		// until every member's archive shows the message before rescheduling - the same
		// `job-queue list` check the runbook gives an operator. The default list limit is
		// plenty in devenv.
		messageID := rejected.MessageID.String()
		for _, m := range committee.Members() {
			require.Eventually(t, func() bool {
				out, err := m.JobQueue().List(ctx, verifiercli.QueueTaskVerifier, committee.VerifierID())
				return err == nil && strings.Contains(strings.ToLower(out), strings.ToLower(messageID))
			}, 60*time.Second, 2*time.Second,
				"member %s must show the dropped message in its task-verifier archive", m.Container())
		}

		// Clear the rejection first: reschedule re-asks the endpoint, so a still-FAILing
		// endpoint would just drop the message again. Reset also empties the fake's call log,
		// which the assertion below uses to prove the replay re-consulted the hook.
		policy.reset(t, ctx)

		// Reschedule on every member against the running node. The aggregator only returns a
		// result once every member has signed, so skipping a member leaves the message stuck.
		for _, m := range committee.Members() {
			out, err := m.JobQueue().RescheduleByMessageID(ctx,
				verifiercli.QueueTaskVerifier, committee.VerifierID(), messageID, verifiercli.RetryDuration("1h"))
			require.NoError(t, err, "reschedule on %s must succeed against the running node; output: %s",
				m.Container(), out)
		}

		replayCtx, cancelReplay := context.WithTimeout(ctx, 90*time.Second)
		defer cancelReplay()
		_, err = aggregatorClient.WaitForVerifierResultForMessage(replayCtx, rejected.MessageID, time.Second)
		require.NoError(t, err,
			"a dropped message must be recoverable by rescheduling the archived job on every committee member")

		require.GreaterOrEqual(t, policy.callsFor(t, ctx, rejected.MessageID), len(committee.Members()),
			"every member must consult the endpoint again after reschedule; reschedule must not bypass the hook")

		for _, m := range committee.Members() {
			out, err := m.JobQueue().List(ctx, verifiercli.QueueTaskVerifier, committee.VerifierID())
			require.NoError(t, err, "list on %s after recovery; output: %s", m.Container(), out)
			require.NotContains(t, strings.ToLower(out), strings.ToLower(messageID),
				"a verified message must not remain in %s's archive; output: %s", m.Container(), out)
		}
	})
}
