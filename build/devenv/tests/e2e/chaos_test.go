package e2e

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	ccv "github.com/smartcontractkit/chainlink-ccv/devenv"
	"github.com/smartcontractkit/chainlink-ccv/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/devenv/evm"
	"github.com/smartcontractkit/chainlink-ccv/devenv/services"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
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
		if agg.CommitteeName == evm.DefaultCommitteeVerifierQualifier {
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

	startTime := time.Now()
	runV2TestCase(t, tc, setup.chainMap, setup.defaultAggregatorClient, setup.indexerClient, AssertMessageOptions{
		TickInterval:            5 * time.Second,
		Timeout:                 waitTimeout(t),
		ExpectedVerifierResults: tc.numExpectedVerifications,
		AssertVerifierLogs:      false,
		AssertExecutorLogs:      false,
	})
	duration := time.Since(startTime)
	setup.l.Info().Dur("duration", duration).Msg("Time taken to run the test")
}

func TestChaos_VerifierFaultToleranceThresholdViolated(t *testing.T) {
	setup := setupChaos(t, "../../env-out.toml")

	var defaultVerifierInputs []*services.VerifierInput
	for _, verifier := range setup.in.Verifier {
		if verifier.CommitteeName == evm.DefaultCommitteeVerifierQualifier {
			defaultVerifierInputs = append(defaultVerifierInputs, verifier)
		}
	}
	require.NotEmpty(t, defaultVerifierInputs, "default verifier inputs not found")

	var thresholdPerSource map[uint64]uint8
	for _, aggregator := range setup.in.Aggregator {
		if aggregator.CommitteeName == evm.DefaultCommitteeVerifierQualifier {
			thresholdPerSource = aggregator.Out.ThresholdPerSource
			break
		}
	}
	require.NotNil(t, thresholdPerSource, "threshold per source nil for default aggregator, need it for this test")

	fromSelector, toSelector := setup.chains[0].Details.ChainSelector, setup.chains[1].Details.ChainSelector

	require.Contains(t, thresholdPerSource, fromSelector, "threshold per source not found for source chain %d", fromSelector)
	threshold := thresholdPerSource[fromSelector]
	require.Greater(t, len(defaultVerifierInputs), int(threshold), "number of default verifiers must be greater than the threshold for this test")
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
		assertExecuted:           false, // we don't assert executed since we are shutting down the verifiers.
		numExpectedVerifications: 0,     // we don't expect any verifications since we are shutting down the verifiers.
	}

	// the verifiers that should sign are the remaining ones, that weren't stopped.
	toSign := defaultVerifierInputs[numVerifiersToStop:]
	signerAddresses := make([]protocol.UnknownAddress, 0, len(toSign))
	for _, verifier := range toSign {
		signerAddresses = append(signerAddresses, protocol.UnknownAddress(common.HexToAddress(verifier.SigningKeyPublic).Bytes()))
	}

	setup.l.Info().
		Any("expectedSignerAddresses", signerAddresses).
		Msg("sending message with verifiers down")

	startTime := time.Now()
	runV2TestCase(
		t,
		tc,
		setup.chainMap,
		setup.defaultAggregatorClient,
		nil, // set indexerClient to nil because we are shutting down the verifiers and won't get a verifier result.
		AssertMessageOptions{
			TickInterval:            5 * time.Second,
			Timeout:                 waitTimeout(t),
			ExpectedVerifierResults: tc.numExpectedVerifications,
			AssertVerifierLogs:      false,
			AssertExecutorLogs:      false,
			ExpectedSignerAddresses: signerAddresses,
		})
	duration := time.Since(startTime)
	setup.l.Info().Dur("duration", duration).Msg("Time taken to run the test")
}

func waitTimeout(t *testing.T) time.Duration {
	deadline, ok := t.Deadline()
	if !ok {
		deadline = time.Now().Add(10 * time.Second)
	}
	return time.Until(deadline)
}

type chaosSetup struct {
	in                      *ccv.Cfg
	chains                  []ccv.ChainImpl
	chainMap                map[uint64]cciptestinterfaces.CCIP17ProductConfiguration
	defaultAggregatorClient *ccv.AggregatorClient
	indexerClient           *ccv.IndexerClient
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

	return &chaosSetup{
		in:                      in,
		chains:                  chains,
		chainMap:                chainMap,
		defaultAggregatorClient: defaultAggregatorClient,
		indexerClient:           indexerClient,
		l:                       l,
	}
}
