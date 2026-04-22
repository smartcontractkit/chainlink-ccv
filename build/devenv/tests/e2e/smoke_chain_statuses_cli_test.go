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
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/verifiercli"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-testing-framework/framework"
)

func TestE2ESmoke_ChainStatusesCLI(t *testing.T) {
	smokeTestConfig := GetSmokeTestConfig()
	in, err := ccv.LoadOutput[ccv.Cfg](smokeTestConfig)
	require.NoError(t, err)

	require.GreaterOrEqual(t, len(in.Verifier), 1, "expected at least one verifier in the environment")
	require.NotNil(t, in.Verifier[0].Out, "first verifier must have output (container name)")
	require.NotEmpty(t, in.Verifier[0].Out.ContainerName, "verifier container name must be set")
	verifierID := in.Verifier[0].Out.VerifierID
	require.NotEmpty(t, verifierID, "verifier ID must be set")

	vc := verifiercli.NewClient(in.Verifier[0].Out.ContainerName)
	ctx := context.Background()

	t.Cleanup(func() {
		vc.ResumeBestEffort(ctx)
		_, _ = framework.SaveContainerLogs(fmt.Sprintf("%s-%s", framework.DefaultCTFLogsDir, t.Name()))
	})

	listOutput, err := vc.ChainStatuses().List(ctx)
	require.NoError(t, err, "list should succeed: %s", listOutput)
	require.Contains(t, listOutput, "Chain", "output must contain Chain header; got: %s", listOutput)
	require.Contains(t, listOutput, "Chain Selector", "output must contain Chain Selector header; got: %s", listOutput)

	chainSelector, hasRow := verifiercli.ParseFirstListRow(listOutput)
	require.True(t, hasRow, "list output must contain at least one chain status row to exercise disable/enable/set-finalized-height; got: %s", listOutput)

	require.NoError(t, vc.Pause(ctx), "must be able to stop verifier process before running CLI mutations")

	_, err = vc.ChainStatuses().Disable(ctx, chainSelector, verifierID)
	require.NoError(t, err, "disable should succeed")

	_, err = vc.ChainStatuses().SetFinalizedHeight(ctx, chainSelector, verifierID, verifiercli.FormatBlockHeight(1))
	require.NoError(t, err, "set-finalized-height should succeed")

	_, err = vc.ChainStatuses().Enable(ctx, chainSelector, verifierID)
	require.NoError(t, err, "enable should succeed")

	finalList, err := vc.ChainStatuses().List(ctx)
	require.NoError(t, err, "final list should succeed: %s", finalList)
	require.Contains(t, finalList, string(chainSelector), "final list should contain chain selector %s; got: %s", chainSelector, finalList)
}

func TestE2ESmoke_ChainStatusDisableEnable(t *testing.T) {
	smokeTestConfig := GetSmokeTestConfig()
	in, err := ccv.LoadOutput[ccv.Cfg](smokeTestConfig)
	require.NoError(t, err)

	ctx := ccv.Plog.WithContext(t.Context())
	lib, err := ccv.NewLib(zerolog.Ctx(ctx), smokeTestConfig, chain_selectors.FamilyEVM)
	require.NoError(t, err)
	chains, err := lib.Chains(ctx)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(chains), 2, "expected at least 2 chains")

	require.GreaterOrEqual(t, len(in.Verifier), 1)
	require.NotNil(t, in.Verifier[0].Out)
	verifierID := in.Verifier[0].Out.VerifierID
	require.NotEmpty(t, verifierID)

	aggregatorClient, err := in.NewAggregatorClientForCommittee(
		zerolog.Ctx(ctx).With().Str("component", "aggregator-client").Logger(),
		devenvcommon.DefaultCommitteeVerifierQualifier)
	require.NoError(t, err)
	t.Cleanup(func() { _ = aggregatorClient.Close() })

	srcImpl := chains[0]
	destImpl := chains[1]
	srcSelector := srcImpl.Details.ChainSelector
	destSelector := destImpl.Details.ChainSelector

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
	receiver := mustGetEOAReceiverAddress(t, destImpl)

	messageOpts := cciptestinterfaces.MessageOptions{
		Version:  3,
		Executor: executorAddr,
		CCVs: []protocol.CCV{
			{CCVAddress: ccvAddr, Args: []byte{}, ArgsLen: 0},
		},
	}
	messageFields := cciptestinterfaces.MessageFields{Receiver: receiver, Data: []byte("disable-enable-test")}

	vc := verifiercli.NewClient(in.Verifier[0].Out.ContainerName)
	cliCtx := context.Background()

	t.Cleanup(func() {
		vc.ResumeBestEffort(cliCtx)
		_, _ = framework.SaveContainerLogs(fmt.Sprintf("%s-%s", framework.DefaultCTFLogsDir, t.Name()))
	})

	require.NoError(t, vc.Pause(cliCtx))
	_, err = vc.ChainStatuses().Disable(cliCtx, verifiercli.FormatChainSelector(srcSelector), verifierID)
	require.NoError(t, err)
	require.NoError(t, vc.RestartAndWaitReady(cliCtx))

	sentEvent, err := srcImpl.SendMessage(ctx, destSelector, messageFields, messageOpts)
	require.NoError(t, err)
	sentEvt, err := srcImpl.ConfirmSendOnSource(ctx, destSelector, cciptestinterfaces.MessageEventKey{MessageID: sentEvent.MessageID}, defaultSentTimeout)
	require.NoError(t, err)
	msgID1 := sentEvt.MessageID

	waitNotProcessed, cancelNotProcessed := context.WithTimeout(ctx, 25*time.Second)
	defer cancelNotProcessed()
	time.Sleep(20 * time.Second)
	_, err = aggregatorClient.GetVerifierResultForMessage(waitNotProcessed, msgID1)
	require.Error(t, err, "message should not be in aggregator while source chain is disabled")

	require.NoError(t, vc.Pause(cliCtx))
	_, err = vc.ChainStatuses().Enable(cliCtx, verifiercli.FormatChainSelector(srcSelector), verifierID)
	require.NoError(t, err)
	require.NoError(t, vc.RestartAndWaitReady(cliCtx))

	sentEvent2, err := srcImpl.SendMessage(ctx, destSelector, cciptestinterfaces.MessageFields{Receiver: receiver, Data: []byte("disable-enable-test-2")}, messageOpts)
	require.NoError(t, err)
	sentEvt2, err := srcImpl.ConfirmSendOnSource(ctx, destSelector, cciptestinterfaces.MessageEventKey{MessageID: sentEvent2.MessageID}, defaultSentTimeout)
	require.NoError(t, err)
	msgID2 := sentEvt2.MessageID

	waitProcessed, cancelProcessed := context.WithTimeout(ctx, 45*time.Second)
	defer cancelProcessed()
	_, err = aggregatorClient.WaitForVerifierResultForMessage(waitProcessed, msgID2, 500*time.Millisecond)
	require.NoError(t, err, "message should be in aggregator after source chain is re-enabled")
}

func TestE2ESmoke_ChainStatusFinalizedHeight(t *testing.T) {
	smokeTestConfig := GetSmokeTestConfig()
	in, err := ccv.LoadOutput[ccv.Cfg](smokeTestConfig)
	require.NoError(t, err)

	ctx := ccv.Plog.WithContext(t.Context())
	lib, err := ccv.NewLib(zerolog.Ctx(ctx), smokeTestConfig, chain_selectors.FamilyEVM)
	require.NoError(t, err)
	chains, err := lib.Chains(ctx)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(chains), 2)

	require.GreaterOrEqual(t, len(in.Verifier), 1)
	require.NotNil(t, in.Verifier[0].Out)
	verifierID := in.Verifier[0].Out.VerifierID
	require.NotEmpty(t, verifierID)

	aggregatorClient, err := in.NewAggregatorClientForCommittee(
		zerolog.Ctx(ctx).With().Str("component", "aggregator-client").Logger(),
		devenvcommon.DefaultCommitteeVerifierQualifier)
	require.NoError(t, err)
	t.Cleanup(func() { _ = aggregatorClient.Close() })

	srcImpl := chains[0]
	destImpl := chains[1]
	srcSelector := srcImpl.Details.ChainSelector
	destSelector := destImpl.Details.ChainSelector

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
	receiver := mustGetEOAReceiverAddress(t, destImpl)

	messageOpts := cciptestinterfaces.MessageOptions{
		Version:  3,
		Executor: executorAddr,
		CCVs:     []protocol.CCV{{CCVAddress: ccvAddr, Args: []byte{}, ArgsLen: 0}},
	}
	messageFields := cciptestinterfaces.MessageFields{Receiver: receiver, Data: []byte("finalized-height-test")}

	vc := verifiercli.NewClient(in.Verifier[0].Out.ContainerName)
	cliCtx := context.Background()

	t.Cleanup(func() {
		vc.ResumeBestEffort(cliCtx)
		_, _ = framework.SaveContainerLogs(fmt.Sprintf("%s-%s", framework.DefaultCTFLogsDir, t.Name()))
	})

	require.NoError(t, vc.Pause(cliCtx))
	_, err = vc.ChainStatuses().SetFinalizedHeight(cliCtx, verifiercli.FormatChainSelector(srcSelector), verifierID, verifiercli.FormatBlockHeight(999999))
	require.NoError(t, err)
	require.NoError(t, vc.RestartAndWaitReady(cliCtx))

	seqNo, err := srcImpl.GetExpectedNextSequenceNumber(ctx, destSelector)
	require.NoError(t, err)
	_, err = srcImpl.SendMessage(ctx, destSelector, messageFields, messageOpts)
	require.NoError(t, err)
	sentEvt, err := srcImpl.ConfirmSendOnSource(ctx, destSelector, cciptestinterfaces.MessageEventKey{SeqNum: seqNo}, defaultSentTimeout)
	require.NoError(t, err)
	msgID := sentEvt.MessageID

	require.NoError(t, vc.Pause(cliCtx))
	_, err = vc.ChainStatuses().SetFinalizedHeight(cliCtx, verifiercli.FormatChainSelector(srcSelector), verifierID, verifiercli.FormatBlockHeight(1))
	require.NoError(t, err)
	require.NoError(t, vc.RestartAndWaitReady(cliCtx))

	waitProcessed, cancelProcessed := context.WithTimeout(ctx, 45*time.Second)
	defer cancelProcessed()
	_, err = aggregatorClient.WaitForVerifierResultForMessage(waitProcessed, msgID, 500*time.Millisecond)
	require.NoError(t, err, "message should be in aggregator after finalized height is set to 1")
}
