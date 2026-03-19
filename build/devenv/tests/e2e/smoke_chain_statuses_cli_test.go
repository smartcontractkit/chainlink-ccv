package e2e

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	chain_selectors "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/sequences"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/versioned_verifier_resolver"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v2_0_0/operations/proxy"
	ccv "github.com/smartcontractkit/chainlink-ccv/build/devenv"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	devenvcommon "github.com/smartcontractkit/chainlink-ccv/build/devenv/common"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-testing-framework/framework"
)

const (
	verifierBinary        = "/app/verifier/cmd/committee/tmp/committee"
	committeeProcessMatch = "tmp/committee"
)

func execInContainer(containerName string, args ...string) (string, error) {
	cmd := exec.Command("docker", append([]string{"exec", containerName}, args...)...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func restartVerifierAndWaitReady(t *testing.T, containerName string, cliArgs func(string, ...string) []string) {
	t.Helper()
	cmd := exec.Command("docker", "restart", containerName)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "docker restart verifier: %s", string(out))
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(2 * time.Second)
		_, err := execInContainer(containerName, cliArgs("list")...)
		if err == nil {
			return
		}
	}
	t.Fatalf("verifier did not become ready within 60 seconds after restart")
}

func parseFirstListRow(listOutput string) (chainSelector string, ok bool) {
	if strings.Contains(listOutput, "No chain status rows found.") {
		return "", false
	}
	lines := strings.SplitSeq(listOutput, "\n")
	for line := range lines {
		if !strings.Contains(line, "|") {
			continue
		}
		parts := strings.Split(line, "|")
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
		}
		if len(parts) < 2 {
			continue
		}
		if strings.Contains(parts[0], "Chain") && strings.Contains(line, "verifier_id") {
			continue
		}
		if strings.TrimLeft(line, "-+| \t") == "" {
			continue
		}
		sel := parts[1]
		if _, err := strconv.ParseUint(sel, 10, 64); err != nil {
			continue
		}
		return sel, true
	}
	return "", false
}

func TestE2ESmoke_ChainStatusesCLI(t *testing.T) {
	smokeTestConfig := GetSmokeTestConfig()
	in, err := ccv.LoadOutput[ccv.Cfg](smokeTestConfig)
	require.NoError(t, err)

	require.GreaterOrEqual(t, len(in.Verifier), 1, "expected at least one verifier in the environment")
	require.NotNil(t, in.Verifier[0].Out, "first verifier must have output (container name)")
	containerName := strings.TrimPrefix(in.Verifier[0].Out.ContainerName, "/")
	require.NotEmpty(t, containerName, "verifier container name must be set")
	verifierID := in.Verifier[0].Out.VerifierID
	require.NotEmpty(t, verifierID, "verifier ID must be set")

	cliArgs := func(subcommand string, extra ...string) []string {
		return append([]string{verifierBinary, "ccv", "chain-statuses", subcommand}, extra...)
	}

	t.Cleanup(func() {
		_, _ = execInContainer(containerName, "pkill", "-CONT", "-f", committeeProcessMatch)
		_, _ = framework.SaveContainerLogs(fmt.Sprintf("%s-%s", framework.DefaultCTFLogsDir, t.Name()))
	})

	listOutput, err := execInContainer(containerName, cliArgs("list")...)
	require.NoError(t, err, "list should succeed: %s", listOutput)
	require.Contains(t, listOutput, "Chain", "output must contain Chain header; got: %s", listOutput)
	require.Contains(t, listOutput, "Chain Selector", "output must contain Chain Selector header; got: %s", listOutput)

	chainSelector, hasRow := parseFirstListRow(listOutput)
	require.True(t, hasRow, "list output must contain at least one chain status row to exercise disable/enable/set-finalized-height; got: %s", listOutput)

	_, err = execInContainer(containerName, "pkill", "-STOP", "-f", committeeProcessMatch)
	require.NoError(t, err, "must be able to stop verifier process (pkill -STOP) before running CLI mutations")

	_, err = execInContainer(containerName, cliArgs("disable", "--chain-selector", chainSelector, "--verifier-id", verifierID)...)
	require.NoError(t, err, "disable should succeed")

	_, err = execInContainer(containerName, cliArgs("set-finalized-height", "--chain-selector", chainSelector, "--verifier-id", verifierID, "--block-height", "1")...)
	require.NoError(t, err, "set-finalized-height should succeed")

	_, err = execInContainer(containerName, cliArgs("enable", "--chain-selector", chainSelector, "--verifier-id", verifierID)...)
	require.NoError(t, err, "enable should succeed")

	finalList, err := execInContainer(containerName, cliArgs("list")...)
	require.NoError(t, err, "final list should succeed: %s", finalList)
	require.Contains(t, finalList, chainSelector, "final list should contain chain selector %s; got: %s", chainSelector, finalList)
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
	containerName := strings.TrimPrefix(in.Verifier[0].Out.ContainerName, "/")
	require.NotEmpty(t, containerName)
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

	cliArgs := func(subcommand string, extra ...string) []string {
		return append([]string{verifierBinary, "ccv", "chain-statuses", subcommand}, extra...)
	}
	sourceSelectorStr := strconv.FormatUint(srcSelector, 10)

	t.Cleanup(func() {
		_, _ = framework.SaveContainerLogs(fmt.Sprintf("%s-%s", framework.DefaultCTFLogsDir, t.Name()))
	})

	_, err = execInContainer(containerName, "pkill", "-STOP", "-f", committeeProcessMatch)
	require.NoError(t, err)
	_, err = execInContainer(containerName, cliArgs("disable", "--chain-selector", sourceSelectorStr, "--verifier-id", verifierID)...)
	require.NoError(t, err)
	restartVerifierAndWaitReady(t, containerName, cliArgs)

	seqNo, err := srcImpl.GetExpectedNextSequenceNumber(ctx, destSelector)
	require.NoError(t, err)
	_, err = srcImpl.SendMessage(ctx, destSelector, messageFields, messageOpts)
	require.NoError(t, err)
	sentEvt, err := srcImpl.WaitOneSentEventBySeqNo(ctx, destSelector, seqNo, defaultSentTimeout)
	require.NoError(t, err)
	msgID1 := sentEvt.MessageID

	waitNotProcessed, cancelNotProcessed := context.WithTimeout(ctx, 25*time.Second)
	defer cancelNotProcessed()
	time.Sleep(20 * time.Second)
	_, err = aggregatorClient.GetVerifierResultForMessage(waitNotProcessed, msgID1)
	require.Error(t, err, "message should not be in aggregator while source chain is disabled")

	_, err = execInContainer(containerName, "pkill", "-STOP", "-f", committeeProcessMatch)
	require.NoError(t, err)
	_, err = execInContainer(containerName, cliArgs("enable", "--chain-selector", sourceSelectorStr, "--verifier-id", verifierID)...)
	require.NoError(t, err)
	restartVerifierAndWaitReady(t, containerName, cliArgs)

	seqNo2, err := srcImpl.GetExpectedNextSequenceNumber(ctx, destSelector)
	require.NoError(t, err)
	_, err = srcImpl.SendMessage(ctx, destSelector, cciptestinterfaces.MessageFields{Receiver: receiver, Data: []byte("disable-enable-test-2")}, messageOpts)
	require.NoError(t, err)
	sentEvt2, err := srcImpl.WaitOneSentEventBySeqNo(ctx, destSelector, seqNo2, defaultSentTimeout)
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
	containerName := strings.TrimPrefix(in.Verifier[0].Out.ContainerName, "/")
	require.NotEmpty(t, containerName)
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

	cliArgs := func(subcommand string, extra ...string) []string {
		return append([]string{verifierBinary, "ccv", "chain-statuses", subcommand}, extra...)
	}
	sourceSelectorStr := strconv.FormatUint(srcSelector, 10)

	t.Cleanup(func() {
		_, _ = framework.SaveContainerLogs(fmt.Sprintf("%s-%s", framework.DefaultCTFLogsDir, t.Name()))
	})

	_, err = execInContainer(containerName, "pkill", "-STOP", "-f", committeeProcessMatch)
	require.NoError(t, err)
	_, err = execInContainer(containerName, cliArgs("set-finalized-height", "--chain-selector", sourceSelectorStr, "--verifier-id", verifierID, "--block-height", "999999")...)
	require.NoError(t, err)
	restartVerifierAndWaitReady(t, containerName, cliArgs)

	seqNo, err := srcImpl.GetExpectedNextSequenceNumber(ctx, destSelector)
	require.NoError(t, err)
	_, err = srcImpl.SendMessage(ctx, destSelector, messageFields, messageOpts)
	require.NoError(t, err)
	sentEvt, err := srcImpl.WaitOneSentEventBySeqNo(ctx, destSelector, seqNo, defaultSentTimeout)
	require.NoError(t, err)
	msgID := sentEvt.MessageID

	_, err = execInContainer(containerName, "pkill", "-STOP", "-f", committeeProcessMatch)
	require.NoError(t, err)
	_, err = execInContainer(containerName, cliArgs("set-finalized-height", "--chain-selector", sourceSelectorStr, "--verifier-id", verifierID, "--block-height", "1")...)
	require.NoError(t, err)
	restartVerifierAndWaitReady(t, containerName, cliArgs)

	waitProcessed, cancelProcessed := context.WithTimeout(ctx, 45*time.Second)
	defer cancelProcessed()
	_, err = aggregatorClient.WaitForVerifierResultForMessage(waitProcessed, msgID, 500*time.Millisecond)
	require.NoError(t, err, "message should be in aggregator after finalized height is set to 1")
}
