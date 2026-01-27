package e2e

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	ccv "github.com/smartcontractkit/chainlink-ccv/devenv"
	"github.com/smartcontractkit/chainlink-ccv/devenv/cciptestinterfaces"
	devenvcommon "github.com/smartcontractkit/chainlink-ccv/devenv/common"
	"github.com/smartcontractkit/chainlink-ccv/devenv/services"
	"github.com/smartcontractkit/chainlink-common/pkg/utils/tests"
	"github.com/smartcontractkit/chainlink-testing-framework/framework"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/chaos"
)

const (
	// ExecPumba waits for this much before returning, since we don't want to wait
	// we keep this at zero.
	ctfPumbaTimeout = 0 * time.Second

	outageDuration = 20 * time.Second
)

func TestChaos_AggregatorOutageRecovery(t *testing.T) {
	setup := setupChaos(t, "../../env-out.toml")

	var defaultAggregatorContainerName string
	for _, agg := range setup.in.Aggregator {
		if agg.CommitteeName == devenvcommon.DefaultCommitteeVerifierQualifier {
			defaultAggregatorContainerName = agg.Out.ContainerName
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

	runV2TestCase(t, tc, setup.chainMap, setup.defaultAggregatorClient, setup.indexerMonitor, AssertMessageOptions{
		TickInterval:            5 * time.Second,
		Timeout:                 tests.WaitTimeout(t),
		ExpectedVerifierResults: tc.numExpectedVerifications,
		AssertVerifierLogs:      false,
		AssertExecutorLogs:      false,
	})
}

func TestChaos_VerifierFaultToleranceThresholdViolated(t *testing.T) {
	setup := setupChaos(t, "../../env-out.toml")

	var defaultVerifierInputs []*services.VerifierInput
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
			names = append(names, verifier.Out.ContainerName)
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

	runV2TestCase(
		t,
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
	setup := setupChaos(t, "../../env-out.toml")

	var defaultExecutorContainerNames []string
	for _, executor := range setup.in.Executor {
		if executor.ExecutorQualifier == devenvcommon.DefaultCommitteeVerifierQualifier {
			defaultExecutorContainerNames = append(defaultExecutorContainerNames, executor.Out.ContainerName)
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

	runV2TestCase(t, tc, setup.chainMap, setup.defaultAggregatorClient, setup.indexerMonitor, AssertMessageOptions{
		TickInterval:            5 * time.Second,
		Timeout:                 tests.WaitTimeout(t),
		ExpectedVerifierResults: tc.numExpectedVerifications,
		AssertVerifierLogs:      false,
		AssertExecutorLogs:      false,
	})
}

func TestChaos_IndexerDown(t *testing.T) {
	setup := setupChaos(t, "../../env-out.toml")

	indexerContainerName := setup.in.Indexer.Out.ContainerName
	require.NotEmpty(t, indexerContainerName, "indexer container name not found")

	pumbaCmd := fmt.Sprintf("stop --duration=%s --restart re2:%s", 30*time.Second, indexerContainerName)
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

	runV2TestCase(t, tc, setup.chainMap, setup.defaultAggregatorClient, setup.indexerMonitor, AssertMessageOptions{
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

	lib, err := ccv.NewLib(l, envOutPath)
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
