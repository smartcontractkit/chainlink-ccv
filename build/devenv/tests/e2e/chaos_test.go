package e2e

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	chain_selectors "github.com/smartcontractkit/chain-selectors"
	ccv "github.com/smartcontractkit/chainlink-ccv/build/devenv"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	devenvcommon "github.com/smartcontractkit/chainlink-ccv/build/devenv/common"
	devenvevm "github.com/smartcontractkit/chainlink-ccv/build/devenv/evm"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services/committeeverifier"
	devenvutil "github.com/smartcontractkit/chainlink-ccv/build/devenv/util"
	"github.com/smartcontractkit/chainlink-common/pkg/utils/tests"
	"github.com/smartcontractkit/chainlink-testing-framework/framework"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/chaos"
)

const (
	// ExecPumba waits for this much before returning, since we don't want to wait
	// we keep this at zero.
	ctfPumbaTimeout = 0 * time.Second

	outageDuration = 20 * time.Second

	rpcFailoverTimeout     = 3 * time.Minute
	rpcProxyCleanupTimeout = 15 * time.Second
)

func TestChaos_EVMRPCFailover(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode; requires a running devenv environment")
	}
	setup := setupChaos(t, GetSmokeTestConfig())
	failoverOutput := requireEVMRPCFailoverOutput(t, setup.in)
	for _, proxyOutput := range failoverOutput.Chains {
		t.Cleanup(func() {
			setRPCProxyRunningBestEffort(setup.l, proxyOutput.PrimaryContainerName, true)
			setRPCProxyRunningBestEffort(setup.l, proxyOutput.SecondaryContainerName, false)
		})
	}

	fromSelector, toSelector := setup.chains[0].Details.ChainSelector, setup.chains[1].Details.ChainSelector
	cases := []struct {
		name        string
		failedChain uint64
		description string
	}{
		{
			name:        "source head tracker switches RPC",
			failedChain: fromSelector,
			description: "source-chain primary RPC",
		},
		{
			name:        "destination transaction manager switches RPC",
			failedChain: toSelector,
			description: "destination-chain primary RPC",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			chainID, err := chain_selectors.GetChainIDFromSelector(tc.failedChain)
			require.NoError(t, err)
			proxyOutput := failoverOutput.Chains[chainID]
			require.NotNilf(t, proxyOutput, "no RPC failover proxies for chain %s", chainID)
			requireDirectTestRPC(t, setup.in, chainID, proxyOutput)

			// The secondary was deliberately stopped while standalone services
			// initialized, making the primary their only possible initial node.
			setRPCProxyRunning(t, setup.l, proxyOutput.SecondaryContainerName, true)
			setRPCProxyRunning(t, setup.l, proxyOutput.PrimaryContainerName, false)

			setup.l.Info().
				Str("failedRPC", tc.description).
				Str("primary", proxyOutput.PrimaryContainerName).
				Str("secondary", proxyOutput.SecondaryContainerName).
				Msg("Sending message while the initially active RPC is unavailable")

			messageCase := v2TestCase{
				name:                     tc.name,
				fromSelector:             fromSelector,
				toSelector:               toSelector,
				receiver:                 mustGetEOAReceiverAddress(t, setup.chainMap[toSelector]),
				assertExecuted:           true,
				numExpectedVerifications: 1,
				executionTimeout:         rpcFailoverTimeout,
			}
			ctx := ccv.Plog.WithContext(t.Context())
			runV2TestCase(t, ctx, zerolog.Ctx(ctx), messageCase, setup.chainMap, setup.defaultAggregatorClient, setup.indexerMonitor, AssertMessageOptions{
				TickInterval:            5 * time.Second,
				Timeout:                 rpcFailoverTimeout,
				ExpectedVerifierResults: messageCase.numExpectedVerifications,
				AssertVerifierLogs:      false,
				AssertExecutorLogs:      false,
			})

			// Keep the healthy secondary available between phases. This avoids a
			// gap while the node pool rediscovers the restored primary.
			setRPCProxyRunning(t, setup.l, proxyOutput.PrimaryContainerName, true)
		})
	}
}

func requireEVMRPCFailoverOutput(t *testing.T, in *ccv.Cfg) *devenvevm.RPCFailoverOutput {
	t.Helper()
	localNetwork := in.LocalNetworks[chain_selectors.FamilyEVM]
	require.NotNil(t, localNetwork, "test requires the EVM local-network failover profile")
	require.NotEmpty(t, localNetwork.Output, "EVM local-network output is missing")

	output, err := devenvutil.OpaqueToConcreteStrict[devenvevm.LocalNetworkOutput](localNetwork.Output)
	require.NoError(t, err)
	require.NotNil(t, output.RPCFailover, "EVM RPC failover output is missing")
	require.NotEmpty(t, output.RPCFailover.Chains, "RPC failover proxy outputs are missing")
	return output.RPCFailover
}

func requireDirectTestRPC(t *testing.T, in *ccv.Cfg, chainID string, proxyOutput *devenvevm.RPCFailoverChainOutput) {
	t.Helper()
	for _, chain := range in.Blockchains {
		if chain == nil || chain.Out == nil || chain.Out.ChainID != chainID {
			continue
		}
		require.GreaterOrEqual(t, len(chain.Out.Nodes), 3, "stored chain output must contain direct and proxy RPC nodes")
		require.NotNil(t, chain.Out.Nodes[0])
		require.NotNil(t, proxyOutput.PrimaryNode)
		require.NotNil(t, proxyOutput.SecondaryNode)
		require.NotEqual(t, proxyOutput.PrimaryNode.InternalHTTPUrl, chain.Out.Nodes[0].InternalHTTPUrl)
		require.NotEqual(t, proxyOutput.SecondaryNode.InternalHTTPUrl, chain.Out.Nodes[0].InternalHTTPUrl)
		return
	}
	t.Fatalf("chain %s not found in stored environment output", chainID)
}

func setRPCProxyRunning(t *testing.T, l *zerolog.Logger, containerName string, running bool) {
	t.Helper()
	action := "stop"
	if running {
		action = "start"
	}
	l.Info().Str("container", containerName).Str("action", action).Msg("Changing RPC proxy state")
	out, err := exec.CommandContext(t.Context(), "docker", action, containerName).CombinedOutput()
	require.NoErrorf(t, err, "docker %s %s failed: %s", action, containerName, strings.TrimSpace(string(out)))
	if running {
		require.Eventually(t, func() bool {
			return exec.CommandContext(t.Context(), "docker", "exec", containerName, "nginx", "-t").Run() == nil
		}, 15*time.Second, 250*time.Millisecond, "RPC proxy %s did not become ready", containerName)
	}
}

func setRPCProxyRunningBestEffort(l *zerolog.Logger, containerName string, running bool) {
	ctx, cancel := context.WithTimeout(context.Background(), rpcProxyCleanupTimeout)
	defer cancel()

	action := "stop"
	if running {
		action = "start"
	}
	if out, err := exec.CommandContext(ctx, "docker", action, containerName).CombinedOutput(); err != nil {
		l.Error().Err(err).
			Str("container", containerName).
			Str("action", action).
			Str("output", strings.TrimSpace(string(out))).
			Msg("Failed to restore RPC proxy state")
	}
}

func TestChaos_AggregatorOutageRecovery(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode; requires a running devenv environment")
	}
	setup := setupChaos(t, GetSmokeTestConfig())

	var defaultAggregatorContainerName string
	for _, agg := range setup.in.Aggregator {
		if agg.CommitteeName == devenvcommon.DefaultCommitteeVerifierQualifier {
			defaultAggregatorContainerName = agg.Out.NginxContainerName
			break
		}
	}
	require.NotEmpty(t, defaultAggregatorContainerName, "default aggregator container name not found")

	fromSelector, toSelector := setup.chains[0].Details.ChainSelector, setup.chains[1].Details.ChainSelector

	// Stop the aggregator prior to sending the message to simulate an outage.
	pumbaCmd := fmt.Sprintf("stop --duration=%s --restart re2:%s", outageDuration.String(), defaultAggregatorContainerName)
	setup.l.Info().Str("pumbaCmd", pumbaCmd).Msg("Stopping the aggregator prior to sending the message to simulate an outage")
	pumbaClose, err := chaos.ExecPumba(
		pumbaCmd,
		ctfPumbaTimeout,
	)
	require.NoError(t, err)
	t.Cleanup(pumbaClose)

	tc := v2TestCase{
		name:                     "src->dst msg execution eoa receiver",
		fromSelector:             fromSelector,
		toSelector:               toSelector,
		receiver:                 mustGetEOAReceiverAddress(t, setup.chainMap[toSelector]),
		expectFail:               false,
		numExpectedVerifications: 1,
	}

	ctx := ccv.Plog.WithContext(t.Context())
	l := zerolog.Ctx(ctx)

	runV2TestCase(t, ctx, l, tc, setup.chainMap, setup.defaultAggregatorClient, setup.indexerMonitor, AssertMessageOptions{
		TickInterval:            5 * time.Second,
		Timeout:                 tests.WaitTimeout(t),
		ExpectedVerifierResults: tc.numExpectedVerifications,
		AssertVerifierLogs:      false,
		AssertExecutorLogs:      false,
	})
}

func TestChaos_VerifierFaultToleranceThresholdViolated(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode; requires a running devenv environment")
	}
	setup := setupChaos(t, GetSmokeTestConfig())

	var defaultVerifierInputs []*committeeverifier.Input
	for _, verifier := range setup.in.Verifier {
		if verifier.CommitteeName == devenvcommon.DefaultCommitteeVerifierQualifier {
			defaultVerifierInputs = append(defaultVerifierInputs, verifier)
		}
	}
	require.NotEmpty(t, defaultVerifierInputs, "default verifier inputs not found")

	var defaultAggregator *services.AggregatorInput
	for _, aggregator := range setup.in.Aggregator {
		if aggregator.CommitteeName == devenvcommon.DefaultCommitteeVerifierQualifier {
			defaultAggregator = aggregator
			break
		}
	}
	require.NotNil(t, defaultAggregator, "default aggregator not found")
	require.NotNil(t, defaultAggregator.Out, "Out nil for default aggregator")
	require.NotNil(t, defaultAggregator.Out.GeneratedCommittee, "GeneratedCommittee nil for default aggregator, need it for this test")

	fromSelector, toSelector := setup.chains[0].Details.ChainSelector, setup.chains[1].Details.ChainSelector
	fromSelectorStr := fmt.Sprintf("%d", fromSelector)

	quorumConfig, ok := defaultAggregator.Out.GeneratedCommittee.QuorumConfigs[fromSelectorStr]
	require.True(t, ok, "quorum config not found for source chain %d", fromSelector)
	threshold := quorumConfig.Threshold
	require.GreaterOrEqual(t, len(defaultVerifierInputs), int(threshold), "number of default verifiers must be greater than or equal to the threshold for this test")
	numVerifiersToStop := len(defaultVerifierInputs) - int(threshold) + 1
	require.Greater(t, numVerifiersToStop, 0, "number of verifiers to stop must be greater than 0 for this test")

	toStop := defaultVerifierInputs[:numVerifiersToStop]
	// pumba accepts a regex pattern for container names.
	containerRe2 := fmt.Sprintf("(%s)", strings.Join(func() []string {
		names := make([]string, 0, len(toStop))
		for _, verifier := range toStop {
			names = append(names, fmt.Sprintf("^%s$", verifier.Out.ContainerName))
		}
		return names
	}(), "|"))
	// shut down enough verifiers so that the fault tolerance threshold is violated.
	// when the verifier is back up its expected to sign the message.
	pumbaCmd := fmt.Sprintf("stop --duration=%s --restart re2:%s", outageDuration.String(), containerRe2)
	setup.l.Info().Str("pumbaCmd", pumbaCmd).Msg("Stopping the verifier prior to sending the message to simulate an outage")
	pumbaClose, err := chaos.ExecPumba(
		pumbaCmd,
		ctfPumbaTimeout,
	)
	require.NoError(t, err)
	t.Cleanup(pumbaClose)

	tc := v2TestCase{
		name:                     "src->dst msg execution eoa receiver",
		fromSelector:             fromSelector,
		toSelector:               toSelector,
		receiver:                 mustGetEOAReceiverAddress(t, setup.chainMap[toSelector]),
		assertExecuted:           true,
		numExpectedVerifications: 1,
	}

	setup.l.Info().
		Str("verifiersToStop", containerRe2).
		Msg("sending message with some verifiers down")

	ctx := ccv.Plog.WithContext(t.Context())
	l := zerolog.Ctx(ctx)

	runV2TestCase(
		t,
		ctx,
		l,
		tc,
		setup.chainMap,
		setup.defaultAggregatorClient,
		setup.indexerMonitor,
		AssertMessageOptions{
			TickInterval:            5 * time.Second,
			Timeout:                 tests.WaitTimeout(t),
			ExpectedVerifierResults: tc.numExpectedVerifications,
			AssertVerifierLogs:      false,
			AssertExecutorLogs:      false,
		})
}

func TestChaos_AllExecutorsDown(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode; requires a running devenv environment")
	}
	setup := setupChaos(t, GetSmokeTestConfig())

	var defaultExecutorContainerNames []string
	for _, executor := range setup.in.Executor {
		if executor.ExecutorQualifier == devenvcommon.DefaultExecutorQualifier {
			defaultExecutorContainerNames = append(defaultExecutorContainerNames, fmt.Sprintf("^%s$", executor.Out.ContainerName))
		}
	}
	require.NotEmpty(t, defaultExecutorContainerNames, "default executor container names not found")

	containerRe2 := fmt.Sprintf("(%s)", strings.Join(defaultExecutorContainerNames, "|"))
	pumbaCmd := fmt.Sprintf("stop --duration=%s --restart re2:%s", 30*time.Second, containerRe2)
	setup.l.Info().Str("pumbaCmd", pumbaCmd).Msg("Stopping the executors prior to sending the message to simulate an outage")
	pumbaClose, err := chaos.ExecPumba(
		pumbaCmd,
		ctfPumbaTimeout,
	)
	require.NoError(t, err)
	t.Cleanup(pumbaClose)

	fromSelector, toSelector := setup.chains[0].Details.ChainSelector, setup.chains[1].Details.ChainSelector
	require.Contains(t, setup.chainMap, fromSelector, "source chain selector not found in chain map")
	require.Contains(t, setup.chainMap, toSelector, "destination chain selector not found in chain map")

	tc := v2TestCase{
		name:                     "src->dst msg execution eoa receiver",
		fromSelector:             fromSelector,
		toSelector:               toSelector,
		receiver:                 mustGetEOAReceiverAddress(t, setup.chainMap[toSelector]),
		assertExecuted:           true,
		numExpectedVerifications: 1,
	}

	ctx := ccv.Plog.WithContext(t.Context())
	l := zerolog.Ctx(ctx)

	runV2TestCase(t, ctx, l, tc, setup.chainMap, setup.defaultAggregatorClient, setup.indexerMonitor, AssertMessageOptions{
		TickInterval:            5 * time.Second,
		Timeout:                 5 * time.Minute,
		ExpectedVerifierResults: tc.numExpectedVerifications,
		AssertVerifierLogs:      false,
		AssertExecutorLogs:      false,
	})
}

func TestChaos_IndexerDown(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode; requires a running devenv environment")
	}
	setup := setupChaos(t, GetSmokeTestConfig())

	require.NotEmpty(t, setup.in.Indexer, "no indexer in config")
	indexerContainerName := setup.in.Indexer[0].Out.ContainerName
	require.NotEmpty(t, indexerContainerName, "indexer container name not found")

	pumbaCmd := fmt.Sprintf("stop --duration=%s --restart re2:%s", 30*time.Second, fmt.Sprintf("^%s$", indexerContainerName))
	setup.l.Info().Str("pumbaCmd", pumbaCmd).Msg("Stopping the indexer prior to sending the message to simulate an outage")
	pumbaClose, err := chaos.ExecPumba(
		pumbaCmd,
		ctfPumbaTimeout,
	)
	require.NoError(t, err)
	t.Cleanup(pumbaClose)

	fromSelector, toSelector := setup.chains[0].Details.ChainSelector, setup.chains[1].Details.ChainSelector
	require.Contains(t, setup.chainMap, fromSelector, "source chain selector not found in chain map")
	require.Contains(t, setup.chainMap, toSelector, "destination chain selector not found in chain map")

	tc := v2TestCase{
		name:                     "src->dst msg execution eoa receiver",
		fromSelector:             fromSelector,
		toSelector:               toSelector,
		receiver:                 mustGetEOAReceiverAddress(t, setup.chainMap[toSelector]),
		assertExecuted:           true,
		numExpectedVerifications: 1,
	}

	ctx := ccv.Plog.WithContext(t.Context())
	l := zerolog.Ctx(ctx)

	runV2TestCase(t, ctx, l, tc, setup.chainMap, setup.defaultAggregatorClient, setup.indexerMonitor, AssertMessageOptions{
		TickInterval:            5 * time.Second,
		Timeout:                 tests.WaitTimeout(t),
		ExpectedVerifierResults: tc.numExpectedVerifications,
		AssertVerifierLogs:      false,
		AssertExecutorLogs:      false,
	})
}

type chaosSetup struct {
	in                      *ccv.Cfg
	chains                  []ccv.ChainImpl
	chainMap                map[uint64]cciptestinterfaces.CCIP17
	defaultAggregatorClient *ccv.AggregatorClient
	indexerMonitor          *ccv.IndexerMonitor
	l                       *zerolog.Logger
}

func setupChaos(t *testing.T, envOutPath string) *chaosSetup {
	t.Cleanup(func() {
		_, err := framework.SaveContainerLogs(fmt.Sprintf("%s-%s", framework.DefaultCTFLogsDir, t.Name()))
		require.NoError(t, err)
	})

	in, err := ccv.LoadOutput[ccv.Cfg](envOutPath)
	require.NoError(t, err)
	ctx := ccv.Plog.WithContext(t.Context())
	l := zerolog.Ctx(ctx)

	// Only load EVM chains for now, as more chains become supported we can add them.
	lib, err := ccv.NewLibFromCCVEnv(l, envOutPath, chain_selectors.FamilyEVM)
	require.NoError(t, err)
	chains, err := lib.Chains(ctx)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(chains), 2, "expected at least 2 chains for this test in the environment")
	chainMap, err := lib.ChainsMap(ctx)
	require.NoError(t, err)

	var defaultAggregatorClient *ccv.AggregatorClient
	if _, ok := in.AggregatorEndpoints[devenvcommon.DefaultCommitteeVerifierQualifier]; ok {
		defaultAggregatorClient, err = in.NewAggregatorClientForCommittee(
			zerolog.Ctx(ctx).With().Str("component", "aggregator-client").Logger(),
			devenvcommon.DefaultCommitteeVerifierQualifier)
		require.NoError(t, err)
		require.NotNil(t, defaultAggregatorClient)
		t.Cleanup(func() {
			defaultAggregatorClient.Close()
		})
	}

	var indexerMonitor *ccv.IndexerMonitor
	indexerClient, err := lib.Indexer()
	if err == nil {
		indexerMonitor, err = ccv.NewIndexerMonitor(
			zerolog.Ctx(ctx).With().Str("component", "indexer-client").Logger(),
			indexerClient)
		require.NoError(t, err)
		require.NotNil(t, indexerMonitor)
	}

	return &chaosSetup{
		in:                      in,
		chains:                  chains,
		chainMap:                chainMap,
		defaultAggregatorClient: defaultAggregatorClient,
		indexerMonitor:          indexerMonitor,
		l:                       l,
	}
}
