package e2e

import (
	"context"
	"fmt"
	"strconv"
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

// aggregatorRefreshBuffer is the time to wait after a CLI disable/enable for
// the aggregator registry to pick up the DB change. The devenv template sets
// chainDisable.refreshInterval = "2s", so 5s gives a comfortable margin.
const aggregatorRefreshBuffer = 5 * time.Second

// TestE2ESmoke_AggregatorChainsCLI exercises the aggregator chains CLI surface
// (list, disable, enable) without going through the full message flow.
func TestE2ESmoke_AggregatorChainsCLI(t *testing.T) {
	smokeTestConfig := GetSmokeTestConfig()
	in, err := ccv.LoadOutput[ccv.Cfg](smokeTestConfig)
	require.NoError(t, err)

	require.GreaterOrEqual(t, len(in.Aggregator), 1, "expected at least one aggregator in the environment")
	require.NotNil(t, in.Aggregator[0].Out, "first aggregator must have output")
	require.NotEmpty(t, in.Aggregator[0].Out.AggregatorContainerName, "aggregator container name must be set")

	ac := aggregatorcli.NewClient(in.Aggregator[0].Out.AggregatorContainerName)
	ctx := ccv.Plog.WithContext(t.Context())

	t.Cleanup(func() {
		_, _ = framework.SaveContainerLogs(fmt.Sprintf("%s-%s", framework.DefaultCTFLogsDir, t.Name()))
	})

	listOutput, err := ac.Chains().List(ctx)
	require.NoError(t, err, "list should succeed: %s", listOutput)
	require.Contains(t, listOutput, "Chain", "output must contain Chain header; got: %s", listOutput)

	// Pick an arbitrary selector to exercise disable/enable.
	lib, err := ccv.NewLib(zerolog.Ctx(ctx), smokeTestConfig, chain_selectors.FamilyEVM)
	require.NoError(t, err)
	chains, err := lib.Chains(ctx)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(chains), 1)
	srcSelector := strconv.FormatUint(chains[0].Details.ChainSelector, 10)

	_, err = ac.Chains().Disable(ctx, "--source", srcSelector)
	require.NoError(t, err, "disable should succeed")

	_, err = ac.Chains().Enable(ctx, "--source", srcSelector)
	require.NoError(t, err, "enable should succeed")
}

// TestE2ESmoke_AggregatorChainDisableEnable validates the full user-visible
// behaviour of the aggregator chain kill switch across three phases:
//
//  1. Non-disabled lane — while chains[0] is disabled as a SOURCE, messages on
//     the reverse lane (chains[1] → chains[0]) are unaffected because chains[0]
//     is only blocked as a source, not as a destination.
//  2. Disabled — messages from chains[0] (the disabled source) are rejected by
//     the aggregator with FailedPrecondition and never reach the result store.
//  3. Recovery — re-enabling chains[0] restores normal processing for that lane.
func TestE2ESmoke_AggregatorChainDisableEnable(t *testing.T) {
	smokeTestConfig := GetSmokeTestConfig()
	in, err := ccv.LoadOutput[ccv.Cfg](smokeTestConfig)
	require.NoError(t, err)

	ctx := ccv.Plog.WithContext(t.Context())
	lib, err := ccv.NewLib(zerolog.Ctx(ctx), smokeTestConfig, chain_selectors.FamilyEVM)
	require.NoError(t, err)
	chains, err := lib.Chains(ctx)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(chains), 2, "expected at least 2 chains")

	require.GreaterOrEqual(t, len(in.Aggregator), 1)
	require.NotNil(t, in.Aggregator[0].Out)
	require.NotEmpty(t, in.Aggregator[0].Out.AggregatorContainerName, "aggregator container name must be set")

	aggregatorClient, err := in.NewAggregatorClientForCommittee(
		zerolog.Ctx(ctx).With().Str("component", "aggregator-client").Logger(),
		devenvcommon.DefaultCommitteeVerifierQualifier)
	require.NoError(t, err)
	t.Cleanup(func() { _ = aggregatorClient.Close() })

	// chains[0] will be disabled as a source; chains[1] will remain fully enabled.
	disabledSrc := chains[0]
	otherSrc := chains[1]
	disabledSrcSelector := disabledSrc.Details.ChainSelector
	otherSrcSelector := otherSrc.Details.ChainSelector

	receiverOnOtherSrc := mustGetEOAReceiverAddress(t, otherSrc)
	receiverOnDisabledSrc := mustGetEOAReceiverAddress(t, disabledSrc)

	ac := aggregatorcli.NewClient(in.Aggregator[0].Out.AggregatorContainerName)
	cliCtx := context.Background()

	t.Cleanup(func() {
		// Best-effort re-enable so the environment is clean for subsequent tests.
		_, _ = ac.Chains().Enable(cliCtx, "--source", strconv.FormatUint(disabledSrcSelector, 10))
		_, _ = framework.SaveContainerLogs(fmt.Sprintf("%s-%s", framework.DefaultCTFLogsDir, t.Name()))
	})

	_, err = ac.Chains().Disable(cliCtx, "--source", strconv.FormatUint(disabledSrcSelector, 10))
	require.NoError(t, err, "CLI disable should succeed")

	// Wait for the registry to refresh so the gate is active.
	time.Sleep(aggregatorRefreshBuffer)

	// -------------------------------------------------------------------------
	// Phase A — Non-disabled lane: chains[1] → chains[0].
	// chains[0] is only disabled as a SOURCE; it is still a valid DESTINATION,
	// so this lane must continue to be processed normally.
	// -------------------------------------------------------------------------
	seqNoAlt, err := otherSrc.GetExpectedNextSequenceNumber(ctx, disabledSrcSelector)
	require.NoError(t, err)
	_, err = otherSrc.SendMessage(ctx, disabledSrcSelector,
		cciptestinterfaces.MessageFields{Receiver: receiverOnDisabledSrc},
		cciptestinterfaces.MessageOptions{})
	require.NoError(t, err)
	sentEvtAlt, err := otherSrc.WaitOneSentEventBySeqNo(ctx, disabledSrcSelector, seqNoAlt, defaultSentTimeout)
	require.NoError(t, err)

	nonDisabledCtx, cancelNonDisabled := context.WithTimeout(ctx, 45*time.Second)
	defer cancelNonDisabled()
	_, err = aggregatorClient.WaitForVerifierResultForMessage(nonDisabledCtx, sentEvtAlt.MessageID, 500*time.Millisecond)
	require.NoError(t, err, "message on non-disabled lane should still reach the aggregator")

	// -------------------------------------------------------------------------
	// Phase B — Disabled: chains[0] → chains[1] is rejected.
	// -------------------------------------------------------------------------
	seqNo, err := disabledSrc.GetExpectedNextSequenceNumber(ctx, otherSrcSelector)
	require.NoError(t, err)
	_, err = disabledSrc.SendMessage(ctx, otherSrcSelector,
		cciptestinterfaces.MessageFields{Receiver: receiverOnOtherSrc},
		cciptestinterfaces.MessageOptions{})
	require.NoError(t, err)
	sentEvt, err := disabledSrc.WaitOneSentEventBySeqNo(ctx, otherSrcSelector, seqNo, defaultSentTimeout)
	require.NoError(t, err)

	// Give verifiers enough time to attempt — and fail — writing their results.
	time.Sleep(20 * time.Second)
	notProcessedCtx, cancelNotProcessed := context.WithTimeout(ctx, 5*time.Second)
	defer cancelNotProcessed()
	_, err = aggregatorClient.GetVerifierResultForMessage(notProcessedCtx, sentEvt.MessageID)
	require.Error(t, err, "message should not be in aggregator while source chain is disabled")

	// -------------------------------------------------------------------------
	// Phase C — Recovery: re-enabling chains[0] restores the lane.
	// -------------------------------------------------------------------------
	_, err = ac.Chains().Enable(cliCtx, "--source", strconv.FormatUint(disabledSrcSelector, 10))
	require.NoError(t, err, "CLI enable should succeed")

	// Wait for the registry to refresh so the gate is lifted.
	time.Sleep(aggregatorRefreshBuffer)

	seqNoRecovery, err := disabledSrc.GetExpectedNextSequenceNumber(ctx, otherSrcSelector)
	require.NoError(t, err)
	_, err = disabledSrc.SendMessage(ctx, otherSrcSelector,
		cciptestinterfaces.MessageFields{Receiver: receiverOnOtherSrc},
		cciptestinterfaces.MessageOptions{})
	require.NoError(t, err)
	sentEvtRecovery, err := disabledSrc.WaitOneSentEventBySeqNo(ctx, otherSrcSelector, seqNoRecovery, defaultSentTimeout)
	require.NoError(t, err)

	recoveryCtx, cancelRecovery := context.WithTimeout(ctx, 45*time.Second)
	defer cancelRecovery()
	_, err = aggregatorClient.WaitForVerifierResultForMessage(recoveryCtx, sentEvtRecovery.MessageID, 500*time.Millisecond)
	require.NoError(t, err, "message should reach the aggregator after source chain is re-enabled")
}
