package e2e

import (
	"fmt"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	ccv "github.com/smartcontractkit/chainlink-ccv/devenv"
	"github.com/smartcontractkit/chainlink-ccv/devenv/evm"
	"github.com/smartcontractkit/chainlink-testing-framework/framework"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/chaos"
)

const (
	// ExecPumba waits for this much before returning, since we don't want to wait
	// we keep this at zero.
	ctfPumbaTimeout = 0 * time.Second
)

func TestChaos_AggregatorOutageRecovery(t *testing.T) {
	const outageDuration = 20 * time.Second

	in, err := ccv.LoadOutput[ccv.Cfg]("../../env-out.toml")
	require.NoError(t, err)
	ctx := ccv.Plog.WithContext(t.Context())
	l := zerolog.Ctx(ctx)

	var defaultAggregatorContainerName string
	for _, agg := range in.Aggregator {
		if agg.CommitteeName == evm.DefaultCommitteeVerifierQualifier {
			defaultAggregatorContainerName = agg.Out.ContainerName
			break
		}
	}
	require.NotEmpty(t, defaultAggregatorContainerName, "default aggregator container name not found")

	lib, err := ccv.NewLib(l, "../../env-out.toml")
	require.NoError(t, err)
	chains, err := lib.Chains(ctx)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(chains), 2, "expected at least 2 chains for this test in the environment")
	chainMap, err := lib.ChainsMap(ctx)
	require.NoError(t, err)

	t.Cleanup(func() {
		_, err := framework.SaveContainerLogs(fmt.Sprintf("%s-%s", framework.DefaultCTFLogsDir, t.Name()))
		require.NoError(t, err)
	})

	fromSelector, toSelector := chains[0].Details.ChainSelector, chains[1].Details.ChainSelector

	var defaultAggregatorClient *ccv.AggregatorClient
	if _, ok := in.AggregatorEndpoints[evm.DefaultCommitteeVerifierQualifier]; ok {
		defaultAggregatorClient, err = in.NewAggregatorClientForCommittee(
			zerolog.Ctx(ctx).With().Str("component", "aggregator-client").Logger(),
			evm.DefaultCommitteeVerifierQualifier)
		require.NoError(t, err)
		require.NotNil(t, defaultAggregatorClient)
		t.Cleanup(func() {
			defaultAggregatorClient.Close()
		})
	}

	var indexerClient *ccv.IndexerClient
	if in.IndexerEndpoint != "" {
		indexerClient = ccv.NewIndexerClient(
			zerolog.Ctx(ctx).With().Str("component", "indexer-client").Logger(),
			in.IndexerEndpoint)
		require.NotNil(t, indexerClient)
	}

	// Stop the aggregator prior to sending the message to simulate an outage.
	pumbaCmd := fmt.Sprintf("stop --duration=%s --restart re2:%s", outageDuration.String(), defaultAggregatorContainerName)
	l.Info().Str("pumbaCmd", pumbaCmd).Msg("Stopping the aggregator prior to sending the message to simulate an outage")
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
		receiver:                 mustGetEOAReceiverAddress(t, chainMap[toSelector]),
		expectFail:               false,
		numExpectedVerifications: 1,
	}

	startTime := time.Now()
	runV2TestCase(t, tc, chainMap, defaultAggregatorClient, indexerClient, AssertMessageOptions{
		TickInterval:            5 * time.Second,
		Timeout:                 waitTimeout(t),
		ExpectedVerifierResults: tc.numExpectedVerifications,
		AssertVerifierLogs:      false,
		AssertExecutorLogs:      false,
	})
	duration := time.Since(startTime)
	l.Info().Dur("duration", duration).Msg("Time taken to run the test")
}

func waitTimeout(t *testing.T) time.Duration {
	deadline, ok := t.Deadline()
	if !ok {
		deadline = time.Now().Add(10 * time.Second)
	}
	return time.Until(deadline)
}
