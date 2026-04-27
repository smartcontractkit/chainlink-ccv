package e2e

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	chain_selectors "github.com/smartcontractkit/chain-selectors"
	ccv "github.com/smartcontractkit/chainlink-ccv/build/devenv"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	devenvcommon "github.com/smartcontractkit/chainlink-ccv/build/devenv/common"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/aggregatorcli"
	"github.com/smartcontractkit/chainlink-testing-framework/framework"
)

// aggregatorRefreshBuffer is the time to wait after a CLI mutation for the
// aggregator registry to pick up the DB change. The devenv template sets
// messageDisablementRules.refreshInterval = "2s", so 5s gives a comfortable margin.
const aggregatorRefreshBuffer = 5 * time.Second

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
// behavior of aggregator message disablement rules across three phases:
//
//  1. Unrelated lane — while the lane between chains[0] and chains[1] is
//     disabled, chains[0] -> chains[2] continues to be processed normally.
//  2. Disabled lane — messages on chains[0] -> chains[1] are rejected by the
//     aggregator with FailedPrecondition and never reach the result store.
//  3. Recovery — deleting the lane rule restores normal processing.
func TestE2ESmoke_AggregatorLaneDisablementRule(t *testing.T) {
	smokeTestConfig := GetSmokeTestConfig()
	in, err := ccv.LoadOutput[ccv.Cfg](smokeTestConfig)
	require.NoError(t, err)

	ctx := ccv.Plog.WithContext(t.Context())
	lib, err := ccv.NewLib(zerolog.Ctx(ctx), smokeTestConfig, chain_selectors.FamilyEVM)
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

	// Phase A: chains[0] -> chains[2] is unrelated to the disabled lane.
	seqNoAllowed, err := blockedSrc.GetExpectedNextSequenceNumber(ctx, allowedDestSelector)
	require.NoError(t, err)
	_, err = blockedSrc.SendMessage(ctx, allowedDestSelector,
		cciptestinterfaces.MessageFields{Receiver: receiverOnAllowedDest},
		cciptestinterfaces.MessageOptions{Version: 3})
	require.NoError(t, err)
	sentEvtAllowed, err := blockedSrc.ConfirmSendOnSource(ctx, allowedDestSelector, cciptestinterfaces.MessageEventKey{SeqNum: seqNoAllowed}, defaultSentTimeout)
	require.NoError(t, err)

	allowedCtx, cancelAllowed := context.WithTimeout(ctx, 45*time.Second)
	defer cancelAllowed()
	_, err = aggregatorClient.WaitForVerifierResultForMessage(allowedCtx, sentEvtAllowed.MessageID, 500*time.Millisecond)
	require.NoError(t, err, "message on unrelated lane should still reach the aggregator")

	// Phase B: chains[0] -> chains[1] is rejected by the lane rule.
	seqNoBlocked, err := blockedSrc.GetExpectedNextSequenceNumber(ctx, blockedDestSelector)
	require.NoError(t, err)
	_, err = blockedSrc.SendMessage(ctx, blockedDestSelector,
		cciptestinterfaces.MessageFields{Receiver: receiverOnBlockedDest},
		cciptestinterfaces.MessageOptions{Version: 3})
	require.NoError(t, err)
	sentEvtBlocked, err := blockedSrc.ConfirmSendOnSource(ctx, blockedDestSelector, cciptestinterfaces.MessageEventKey{SeqNum: seqNoBlocked}, defaultSentTimeout)
	require.NoError(t, err)

	time.Sleep(20 * time.Second)
	notProcessedCtx, cancelNotProcessed := context.WithTimeout(ctx, 5*time.Second)
	defer cancelNotProcessed()
	_, err = aggregatorClient.GetVerifierResultForMessage(notProcessedCtx, sentEvtBlocked.MessageID)
	require.Error(t, err, "message should not be in aggregator while lane rule exists")

	// Phase C: deleting the rule restores the lane.
	_, err = rulesClient.Delete(cliCtx, ruleID)
	require.NoError(t, err, "CLI delete lane rule should succeed")
	time.Sleep(aggregatorRefreshBuffer)

	seqNoRecovery, err := blockedSrc.GetExpectedNextSequenceNumber(ctx, blockedDestSelector)
	require.NoError(t, err)
	_, err = blockedSrc.SendMessage(ctx, blockedDestSelector,
		cciptestinterfaces.MessageFields{Receiver: receiverOnBlockedDest},
		cciptestinterfaces.MessageOptions{Version: 3})
	require.NoError(t, err)
	sentEvtRecovery, err := blockedSrc.ConfirmSendOnSource(ctx, blockedDestSelector, cciptestinterfaces.MessageEventKey{SeqNum: seqNoRecovery}, defaultSentTimeout)
	require.NoError(t, err)

	recoveryCtx, cancelRecovery := context.WithTimeout(ctx, 45*time.Second)
	defer cancelRecovery()
	_, err = aggregatorClient.WaitForVerifierResultForMessage(recoveryCtx, sentEvtRecovery.MessageID, 500*time.Millisecond)
	require.NoError(t, err, "message should reach the aggregator after lane rule is deleted")
}

// TestE2ESmoke_AggregatorChainDisablementRule validates that a Chain rule
// blocks any message touching the configured selector while unrelated chains
// keep flowing.
func TestE2ESmoke_AggregatorChainDisablementRule(t *testing.T) {
	smokeTestConfig := GetSmokeTestConfig()
	in, err := ccv.LoadOutput[ccv.Cfg](smokeTestConfig)
	require.NoError(t, err)

	ctx := ccv.Plog.WithContext(t.Context())
	lib, err := ccv.NewLib(zerolog.Ctx(ctx), smokeTestConfig, chain_selectors.FamilyEVM)
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

	allowedSent := sendMessageAndConfirm(t, ctx, src, allowedDestSelector,
		cciptestinterfaces.MessageFields{Receiver: mustGetEOAReceiverAddress(t, allowedDest)},
		cciptestinterfaces.MessageOptions{Version: 3})
	requireAggregatorResult(t, ctx, aggregatorClient, allowedSent.MessageID, "message on unrelated chain should still reach the aggregator")

	blockedSent := sendMessageAndConfirm(t, ctx, src, blockedDestSelector,
		cciptestinterfaces.MessageFields{Receiver: mustGetEOAReceiverAddress(t, blockedDest)},
		cciptestinterfaces.MessageOptions{Version: 3})
	requireNoAggregatorResult(t, ctx, aggregatorClient, blockedSent.MessageID, "message touching disabled chain should not be in aggregator")

	_, err = rulesClient.Delete(cliCtx, ruleID)
	require.NoError(t, err, "CLI delete chain rule should succeed")
	time.Sleep(aggregatorRefreshBuffer)

	recoverySent := sendMessageAndConfirm(t, ctx, src, blockedDestSelector,
		cciptestinterfaces.MessageFields{Receiver: mustGetEOAReceiverAddress(t, blockedDest)},
		cciptestinterfaces.MessageOptions{Version: 3})
	requireAggregatorResult(t, ctx, aggregatorClient, recoverySent.MessageID, "message should reach the aggregator after chain rule is deleted")
}

func sendMessageAndConfirm(
	t *testing.T,
	ctx context.Context,
	src cciptestinterfaces.CCIP17,
	destSelector uint64,
	fields cciptestinterfaces.MessageFields,
	opts cciptestinterfaces.MessageOptions,
) cciptestinterfaces.MessageSentEvent {
	t.Helper()

	seqNo, err := src.GetExpectedNextSequenceNumber(ctx, destSelector)
	require.NoError(t, err)
	_, err = src.SendMessage(ctx, destSelector, fields, opts)
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
