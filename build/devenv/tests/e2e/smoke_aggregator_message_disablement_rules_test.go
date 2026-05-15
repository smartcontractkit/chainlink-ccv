package e2e

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	chain_selectors "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/operations/proxy"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/sequences"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/versioned_verifier_resolver"
	ccv "github.com/smartcontractkit/chainlink-ccv/build/devenv"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	devenvcommon "github.com/smartcontractkit/chainlink-ccv/build/devenv/common"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/aggregatorcli"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/logasserter"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/verifiercli"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	verifier "github.com/smartcontractkit/chainlink-ccv/verifier/pkg"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-testing-framework/framework"
)

// aggregatorRefreshBuffer is the time to wait after a CLI mutation for the
// aggregator registry and verifier message-rules poller to pick up the DB
// change. The devenv template and verifier default poll every 2s, so 10s gives
// a comfortable margin across both loops.
const aggregatorRefreshBuffer = 10 * time.Second

func TestE2ESmoke_AggregatorMessageDisablementRulesCLI(t *testing.T) {
	smokeTestConfig := GetSmokeTestConfig()
	in, err := ccv.LoadOutput[ccv.Cfg](smokeTestConfig)
	require.NoError(t, err)

	require.GreaterOrEqual(t, len(in.Aggregator), 1, "expected at least one aggregator in the environment")
	require.NotNil(t, in.Aggregator[0].Out, "first aggregator must have output")
	require.NotEmpty(t, in.Aggregator[0].Out.AggregatorContainerName, "aggregator container name must be set")

	ac := aggregatorcli.NewClient(in.Aggregator[0].Out.AggregatorContainerName)
	rulesClient := ac.MessageDisablementRules()
	ctx := ccv.Plog.WithContext(t.Context())

	t.Cleanup(func() {
		_, _ = framework.SaveContainerLogs(fmt.Sprintf("%s-%s", framework.DefaultCTFLogsDir, t.Name()))
	})

	selectorA := uint64(9_000_000_000_000_000_000) + uint64(time.Now().UnixNano()%1_000_000)
	selectorB := selectorA + 1

	createOutput, err := rulesClient.CreateChain(ctx, aggregatorcli.FormatChainSelector(selectorA))
	require.NoError(t, err, "create chain rule should succeed: %s", createOutput)
	ruleID, err := aggregatorcli.ParseRuleID(createOutput)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = rulesClient.Delete(context.Background(), ruleID) })

	getOutput, err := rulesClient.Get(ctx, ruleID)
	require.NoError(t, err, "get should succeed: %s", getOutput)
	require.Contains(t, getOutput, "Chain")

	createLaneOutput, err := rulesClient.CreateLane(ctx, aggregatorcli.FormatChainSelector(selectorA), aggregatorcli.FormatChainSelector(selectorB))
	require.NoError(t, err, "create lane rule should succeed: %s", createLaneOutput)
	laneRuleID, err := aggregatorcli.ParseRuleID(createLaneOutput)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = rulesClient.Delete(context.Background(), laneRuleID) })

	listOutput, err := rulesClient.List(ctx, "--type", "Lane")
	require.NoError(t, err, "list should succeed: %s", listOutput)
	require.Contains(t, listOutput, string(laneRuleID))

	deleteOutput, err := rulesClient.Delete(ctx, laneRuleID)
	require.NoError(t, err, "delete lane rule should succeed: %s", deleteOutput)

	deleteOutput, err = rulesClient.Delete(ctx, ruleID)
	require.NoError(t, err, "delete should succeed: %s", deleteOutput)
}

// TestE2ESmoke_AggregatorLaneDisablementRule validates the full user-visible
// behavior of aggregator message disablement rules:
//
//  1. Unrelated lane - while the lane between chains[0] and chains[1] is
//     disabled, chains[0] -> chains[2] continues to be processed normally.
//  2. Disabled lane - messages on chains[0] -> chains[1] are dropped by the
//     verifier and never reach the result store.
//  3. Replay - deleting the rule alone does not replay a dropped message once
//     the verifier checkpoint has advanced; rewinding the committee checkpoint
//     makes the original message process normally.
func TestE2ESmoke_AggregatorLaneDisablementRule(t *testing.T) {
	smokeTestConfig := GetSmokeTestConfig()
	in, err := ccv.LoadOutput[ccv.Cfg](smokeTestConfig)
	require.NoError(t, err)

	ctx := ccv.Plog.WithContext(t.Context())
	lib, err := ccv.NewLibFromCCVEnv(zerolog.Ctx(ctx), smokeTestConfig, chain_selectors.FamilyEVM)
	require.NoError(t, err)
	chains, err := lib.Chains(ctx)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(chains), 3, "expected at least 3 chains")

	require.GreaterOrEqual(t, len(in.Aggregator), 1)
	require.NotNil(t, in.Aggregator[0].Out)
	require.NotEmpty(t, in.Aggregator[0].Out.AggregatorContainerName, "aggregator container name must be set")

	aggregatorClient, err := in.NewAggregatorClientForCommittee(
		zerolog.Ctx(ctx).With().Str("component", "aggregator-client").Logger(),
		devenvcommon.DefaultCommitteeVerifierQualifier)
	require.NoError(t, err)
	t.Cleanup(func() { _ = aggregatorClient.Close() })

	blockedSrc := chains[0]
	blockedDest := chains[1]
	allowedDest := chains[2]
	blockedSrcSelector := blockedSrc.Details.ChainSelector
	blockedDestSelector := blockedDest.Details.ChainSelector
	allowedDestSelector := allowedDest.Details.ChainSelector
	progressable, ok := blockedSrc.CCIP17.(cciptestinterfaces.ProgressableChain)
	if !ok {
		t.Skip("source chain does not implement ProgressableChain; skipping message-disablement replay smoke test")
	}
	require.True(t, progressable.SupportManualBlockProgress(ctx),
		"source chain must support manual block progression with automining enabled; run with env-src-auto-mine.toml")
	advanceBlocks := func(numBlocks int) {
		require.NoError(t, progressable.AdvanceBlocks(ctx, numBlocks), "advance %d blocks", numBlocks)
		time.Sleep(3 * time.Second)
	}

	receiverOnBlockedDest := mustGetEOAReceiverAddress(t, blockedDest)
	receiverOnAllowedDest := mustGetEOAReceiverAddress(t, allowedDest)

	ac := aggregatorcli.NewClient(in.Aggregator[0].Out.AggregatorContainerName)
	rulesClient := ac.MessageDisablementRules()
	cliCtx := context.Background()

	createOutput, err := rulesClient.CreateLane(cliCtx, aggregatorcli.FormatChainSelector(blockedSrcSelector), aggregatorcli.FormatChainSelector(blockedDestSelector))
	require.NoError(t, err, "CLI create lane rule should succeed: %s", createOutput)
	ruleID, err := aggregatorcli.ParseRuleID(createOutput)
	require.NoError(t, err)

	t.Cleanup(func() {
		_, _ = rulesClient.Delete(cliCtx, ruleID)
		_, _ = framework.SaveContainerLogs(fmt.Sprintf("%s-%s", framework.DefaultCTFLogsDir, t.Name()))
	})

	time.Sleep(aggregatorRefreshBuffer)

	committee := newVerifierCommitteeClientForSmoke(t, in)
	committee.ResumeAllBestEffort(ctx)
	t.Cleanup(func() { committee.ResumeAllBestEffort(ctx) })

	logAssert := logasserter.New(DefaultLokiURL, zerolog.Ctx(ctx).With().Str("component", "log-asserter").Logger())
	require.NoError(t, logAssert.StartStreaming(ctx, []logasserter.LogStage{
		logasserter.MessageReachedVerifier(),
		logasserter.MessageDroppedInVerifier(),
	}))
	t.Cleanup(logAssert.StopStreaming)

	messageOpts := committeeV3MessageOptions(t, in, blockedSrcSelector)

	// Phase A: chains[0] -> chains[2] is unrelated to the disabled lane.
	sentEvtAllowed := sendMessageAndConfirm(t, ctx, blockedSrc, allowedDestSelector,
		cciptestinterfaces.MessageFields{Receiver: receiverOnAllowedDest},
		messageOpts, 3)
	advanceBlocks(verifier.ConfirmationDepth + 5)
	requireAggregatorResult(t, ctx, aggregatorClient, sentEvtAllowed.MessageID, "message on unrelated lane should still reach the aggregator")

	// Phase B: chains[0] -> chains[1] is dropped by the verifier.
	sentEvtBlocked := sendMessageAndConfirm(t, ctx, blockedSrc, blockedDestSelector,
		cciptestinterfaces.MessageFields{Receiver: receiverOnBlockedDest},
		messageOpts, 3)
	advanceBlocks(verifier.ConfirmationDepth / 5)
	reachedCtx, cancelReached := context.WithTimeout(ctx, 60*time.Second)
	defer cancelReached()
	_, err = logAssert.WaitForStage(reachedCtx, sentEvtBlocked.MessageID, logasserter.MessageReachedVerifier())
	require.NoError(t, err, "message should reach verifier pending queue before it is dropped")
	dropCtx, cancelDrop := context.WithTimeout(ctx, 60*time.Second)
	defer cancelDrop()
	_, err = logAssert.WaitForStage(dropCtx, sentEvtBlocked.MessageID, logasserter.MessageDroppedInVerifier())
	require.NoError(t, err, "message should be dropped in verifier due to message disablement rule")
	requireNoAggregatorResult(t, ctx, aggregatorClient, sentEvtBlocked.MessageID, "message should not be in aggregator while lane rule exists")

	// Move the checkpoint past the dropped message while the rule is active. Removing the
	// rule alone should not replay it; replay requires an operator checkpoint rewind.
	advanceBlocks(verifier.ConfirmationDepth*3 + 30)
	requireNoAggregatorResult(t, ctx, aggregatorClient, sentEvtBlocked.MessageID, "dropped message should not reach aggregator while rule exists")

	_, err = rulesClient.Delete(cliCtx, ruleID)
	require.NoError(t, err, "CLI delete lane rule should succeed")
	time.Sleep(aggregatorRefreshBuffer)
	advanceBlocks(verifier.ConfirmationDepth + 5)
	requireNoAggregatorResult(t, ctx, aggregatorClient, sentEvtBlocked.MessageID, "dropped message should not reappear after rule deletion alone")

	require.NoError(t, committee.RewindFinalizedHeight(ctx,
		verifiercli.FormatChainSelector(blockedSrcSelector), verifiercli.FormatBlockHeight(0)),
		"rewind committee finalized height")

	advanceBlocks(verifier.ConfirmationDepth*2 + 10)
	requireAggregatorResult(t, ctx, aggregatorClient, sentEvtBlocked.MessageID, "dropped message should be reprocessed after checkpoint rewind")
}

// TestE2ESmoke_AggregatorChainDisablementRule validates that a Chain rule
// drops any message touching the configured selector while unrelated chains
// keep flowing, and that dropped messages require a checkpoint rewind to replay.
func TestE2ESmoke_AggregatorChainDisablementRule(t *testing.T) {
	smokeTestConfig := GetSmokeTestConfig()
	in, err := ccv.LoadOutput[ccv.Cfg](smokeTestConfig)
	require.NoError(t, err)

	ctx := ccv.Plog.WithContext(t.Context())
	lib, err := ccv.NewLibFromCCVEnv(zerolog.Ctx(ctx), smokeTestConfig, chain_selectors.FamilyEVM)
	require.NoError(t, err)
	chains, err := lib.Chains(ctx)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(chains), 3, "expected at least 3 chains")

	require.GreaterOrEqual(t, len(in.Aggregator), 1)
	require.NotNil(t, in.Aggregator[0].Out)
	require.NotEmpty(t, in.Aggregator[0].Out.AggregatorContainerName, "aggregator container name must be set")

	aggregatorClient, err := in.NewAggregatorClientForCommittee(
		zerolog.Ctx(ctx).With().Str("component", "aggregator-client").Logger(),
		devenvcommon.DefaultCommitteeVerifierQualifier)
	require.NoError(t, err)
	t.Cleanup(func() { _ = aggregatorClient.Close() })

	src := chains[0]
	blockedDest := chains[1]
	allowedDest := chains[2]
	blockedDestSelector := blockedDest.Details.ChainSelector
	allowedDestSelector := allowedDest.Details.ChainSelector
	srcSelector := src.Details.ChainSelector
	progressable, ok := src.CCIP17.(cciptestinterfaces.ProgressableChain)
	if !ok {
		t.Skip("source chain does not implement ProgressableChain; skipping message-disablement replay smoke test")
	}
	require.True(t, progressable.SupportManualBlockProgress(ctx),
		"source chain must support manual block progression with automining enabled; run with env-src-auto-mine.toml")
	advanceBlocks := func(numBlocks int) {
		require.NoError(t, progressable.AdvanceBlocks(ctx, numBlocks), "advance %d blocks", numBlocks)
		time.Sleep(3 * time.Second)
	}

	ac := aggregatorcli.NewClient(in.Aggregator[0].Out.AggregatorContainerName)
	rulesClient := ac.MessageDisablementRules()
	cliCtx := context.Background()

	createOutput, err := rulesClient.CreateChain(cliCtx, aggregatorcli.FormatChainSelector(blockedDestSelector))
	require.NoError(t, err, "CLI create chain rule should succeed: %s", createOutput)
	ruleID, err := aggregatorcli.ParseRuleID(createOutput)
	require.NoError(t, err)

	t.Cleanup(func() {
		_, _ = rulesClient.Delete(cliCtx, ruleID)
		_, _ = framework.SaveContainerLogs(fmt.Sprintf("%s-%s", framework.DefaultCTFLogsDir, t.Name()))
	})

	time.Sleep(aggregatorRefreshBuffer)

	committee := newVerifierCommitteeClientForSmoke(t, in)
	committee.ResumeAllBestEffort(ctx)
	t.Cleanup(func() { committee.ResumeAllBestEffort(ctx) })

	logAssert := logasserter.New(DefaultLokiURL, zerolog.Ctx(ctx).With().Str("component", "log-asserter").Logger())
	require.NoError(t, logAssert.StartStreaming(ctx, []logasserter.LogStage{
		logasserter.MessageReachedVerifier(),
		logasserter.MessageDroppedInVerifier(),
	}))
	t.Cleanup(logAssert.StopStreaming)

	messageOpts := committeeV3MessageOptions(t, in, srcSelector)

	allowedSent := sendMessageAndConfirm(t, ctx, src, allowedDestSelector,
		cciptestinterfaces.MessageFields{Receiver: mustGetEOAReceiverAddress(t, allowedDest)},
		messageOpts, 3)
	advanceBlocks(verifier.ConfirmationDepth + 5)
	requireAggregatorResult(t, ctx, aggregatorClient, allowedSent.MessageID, "message on unrelated chain should still reach the aggregator")

	blockedSent := sendMessageAndConfirm(t, ctx, src, blockedDestSelector,
		cciptestinterfaces.MessageFields{Receiver: mustGetEOAReceiverAddress(t, blockedDest)},
		messageOpts, 3)
	advanceBlocks(verifier.ConfirmationDepth / 5)
	reachedCtx, cancelReached := context.WithTimeout(ctx, 60*time.Second)
	defer cancelReached()
	_, err = logAssert.WaitForStage(reachedCtx, blockedSent.MessageID, logasserter.MessageReachedVerifier())
	require.NoError(t, err, "message should reach verifier pending queue before it is dropped")
	dropCtx, cancelDrop := context.WithTimeout(ctx, 60*time.Second)
	defer cancelDrop()
	_, err = logAssert.WaitForStage(dropCtx, blockedSent.MessageID, logasserter.MessageDroppedInVerifier())
	require.NoError(t, err, "message should be dropped in verifier due to message disablement rule")
	requireNoAggregatorResult(t, ctx, aggregatorClient, blockedSent.MessageID, "message touching disabled chain should not be in aggregator")

	advanceBlocks(verifier.ConfirmationDepth*3 + 30)
	requireNoAggregatorResult(t, ctx, aggregatorClient, blockedSent.MessageID, "dropped message should not reach aggregator while rule exists")

	_, err = rulesClient.Delete(cliCtx, ruleID)
	require.NoError(t, err, "CLI delete chain rule should succeed")
	time.Sleep(aggregatorRefreshBuffer)
	advanceBlocks(verifier.ConfirmationDepth + 5)
	requireNoAggregatorResult(t, ctx, aggregatorClient, blockedSent.MessageID, "dropped message should not reappear after rule deletion alone")

	require.NoError(t, committee.RewindFinalizedHeight(ctx,
		verifiercli.FormatChainSelector(srcSelector), verifiercli.FormatBlockHeight(0)),
		"rewind committee finalized height")

	advanceBlocks(verifier.ConfirmationDepth*2 + 10)
	requireAggregatorResult(t, ctx, aggregatorClient, blockedSent.MessageID, "dropped message should be reprocessed after checkpoint rewind")
}

func committeeV3MessageOptions(t *testing.T, in *ccv.Cfg, srcSelector uint64) cciptestinterfaces.MessageOptions {
	t.Helper()

	executorAddr := getContractAddress(t, in, srcSelector,
		datastore.ContractType(sequences.ExecutorProxyType),
		proxy.Deploy.Version(),
		devenvcommon.DefaultExecutorQualifier,
		"executor")
	ccvAddr := getContractAddress(t, in, srcSelector,
		datastore.ContractType(versioned_verifier_resolver.CommitteeVerifierResolverType),
		versioned_verifier_resolver.Version.String(),
		devenvcommon.DefaultCommitteeVerifierQualifier,
		"committee verifier proxy")

	return cciptestinterfaces.MessageOptions{
		Executor: executorAddr,
		CCVs: []protocol.CCV{
			{CCVAddress: ccvAddr, Args: []byte{}, ArgsLen: 0},
		},
	}
}

func sendMessageAndConfirm(
	t *testing.T,
	ctx context.Context,
	src cciptestinterfaces.CCIP17,
	destSelector uint64,
	fields cciptestinterfaces.MessageFields,
	extraArgs cciptestinterfaces.ExtraArgsDataProvider,
	messageVersion uint8,
) cciptestinterfaces.MessageSentEvent {
	t.Helper()

	seqNo, err := src.GetExpectedNextSequenceNumber(ctx, destSelector)
	require.NoError(t, err)
	_, err = src.SendMessage(ctx, destSelector, fields, extraArgs, messageVersion)
	require.NoError(t, err)
	sentEvt, err := src.ConfirmSendOnSource(ctx, destSelector, cciptestinterfaces.MessageEventKey{SeqNum: seqNo}, defaultSentTimeout)
	require.NoError(t, err)
	return sentEvt
}

func requireAggregatorResult(t *testing.T, ctx context.Context, aggregatorClient *ccv.AggregatorClient, messageID [32]byte, msg string) {
	t.Helper()

	waitCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	_, err := aggregatorClient.WaitForVerifierResultForMessage(waitCtx, messageID, 500*time.Millisecond)
	require.NoError(t, err, msg)
}

func requireNoAggregatorResult(t *testing.T, ctx context.Context, aggregatorClient *ccv.AggregatorClient, messageID [32]byte, msg string) {
	t.Helper()

	time.Sleep(20 * time.Second)
	notProcessedCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err := aggregatorClient.GetVerifierResultForMessage(notProcessedCtx, messageID)
	require.Error(t, err, msg)
}

func newVerifierCommitteeClientForSmoke(t *testing.T, in *ccv.Cfg) *verifiercli.CommitteeClient {
	t.Helper()

	require.GreaterOrEqual(t, len(in.Verifier), 1)
	require.NotNil(t, in.Verifier[0].Out)
	verifierID := in.Verifier[0].Out.VerifierID
	require.NotEmpty(t, verifierID)

	members := make([]*verifiercli.Client, 0)
	for _, v := range in.Verifier {
		if v.Out == nil || v.Out.VerifierID != verifierID {
			continue
		}
		require.NotEmpty(t, v.Out.ContainerName, "verifier container name must be set")
		members = append(members, verifiercli.NewClient(v.Out.ContainerName))
	}

	committee, err := verifiercli.NewCommitteeClient(verifierID, members...)
	require.NoError(t, err)
	return committee
}
