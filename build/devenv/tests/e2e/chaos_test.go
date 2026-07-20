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
	devenvcommon "github.com/smartcontractkit/chainlink-ccv/build/devenv/common"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services/committeeverifier"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/chaos"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/tcapi"
	"github.com/smartcontractkit/chainlink-common/pkg/utils/tests"
	"github.com/smartcontractkit/chainlink-testing-framework/framework"
)

func TestChaos_AggregatorOutageRecovery(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode; requires a running devenv environment")
	}
	ctx, lib, setup := setupChaosEVM(t, GetSmokeTestConfig())
	src, dst := chaosChainPair(t, ctx, lib)

	aggregatorContainer, err := chaos.DefaultAggregatorNginx(setup.in, devenvcommon.DefaultCommitteeVerifierQualifier)
	require.NoError(t, err)

	msg, err := chaos.HydrateEVMEOADefaultVerifier(ctx, lib, src, dst)
	require.NoError(t, err)

	require.NoError(t, chaos.RunScenario(t, ctx, chaos.ScenarioSpec{
		Lib:      lib,
		Src:      src,
		Dst:      dst,
		Fields:   msg.Fields,
		MsgOpts:  msg.MsgOpts,
		SendArgs: tcapi.SendArgs{},
		Outage: chaos.OutageSpec{
			Duration:      chaos.DefaultOutageDuration,
			Targets:       []string{aggregatorContainer},
			LiteralSingle: true,
		},
		Assert: tcapi.AssertMessageOptions{
			TickInterval:            5 * time.Second,
			Timeout:                 tests.WaitTimeout(t),
			ExpectedVerifierResults: 1,
			AssertVerifierLogs:      false,
			AssertExecutorLogs:      false,
		},
	}))
}

func TestChaos_VerifierFaultToleranceThresholdViolated(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode; requires a running devenv environment")
	}
	ctx, lib, setup := setupChaosEVM(t, GetSmokeTestConfig())
	src, dst := chaosChainPair(t, ctx, lib)

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

	fromSelectorStr := fmt.Sprintf("%d", src)
	quorumConfig, ok := defaultAggregator.Out.GeneratedCommittee.QuorumConfigs[fromSelectorStr]
	require.True(t, ok, "quorum config not found for source chain %d", src)
	threshold := quorumConfig.Threshold
	require.GreaterOrEqual(t, len(defaultVerifierInputs), int(threshold), "number of default verifiers must be greater than or equal to the threshold for this test")
	numVerifiersToStop := len(defaultVerifierInputs) - int(threshold) + 1
	require.Greater(t, numVerifiersToStop, 0, "number of verifiers to stop must be greater than 0 for this test")

	toStop := defaultVerifierInputs[:numVerifiersToStop]
	stopNames := make(map[string]struct{}, len(toStop))
	for _, verifier := range toStop {
		stopNames[verifier.Out.ContainerName] = struct{}{}
	}
	verifierTargets, err := chaos.VerifierContainers(setup.in, devenvcommon.DefaultCommitteeVerifierQualifier, func(v *committeeverifier.Input) bool {
		_, ok := stopNames[v.Out.ContainerName]
		return ok
	})
	require.NoError(t, err)

	msg, err := chaos.HydrateEVMEOADefaultVerifier(ctx, lib, src, dst)
	require.NoError(t, err)

	setup.l.Info().
		Strs("verifiersToStop", verifierTargets).
		Msg("sending message with some verifiers down")

	require.NoError(t, chaos.RunScenario(t, ctx, chaos.ScenarioSpec{
		Lib:      lib,
		Src:      src,
		Dst:      dst,
		Fields:   msg.Fields,
		MsgOpts:  msg.MsgOpts,
		SendArgs: tcapi.SendArgs{},
		Outage: chaos.OutageSpec{
			Duration: chaos.DefaultOutageDuration,
			Targets:  verifierTargets,
		},
		Assert: tcapi.AssertMessageOptions{
			TickInterval:            5 * time.Second,
			Timeout:                 tests.WaitTimeout(t),
			ExpectedVerifierResults: 1,
			AssertVerifierLogs:      false,
			AssertExecutorLogs:      false,
		},
		ConfirmExecOnDest: true,
	}))
}

func TestChaos_AllExecutorsDown(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode; requires a running devenv environment")
	}
	ctx, lib, setup := setupChaosEVM(t, GetSmokeTestConfig())
	src, dst := chaosChainPair(t, ctx, lib)

	executorTargets, err := chaos.ExecutorContainers(setup.in, devenvcommon.DefaultExecutorQualifier)
	require.NoError(t, err)

	msg, err := chaos.HydrateEVMEOADefaultVerifier(ctx, lib, src, dst)
	require.NoError(t, err)

	require.NoError(t, chaos.RunScenario(t, ctx, chaos.ScenarioSpec{
		Lib:      lib,
		Src:      src,
		Dst:      dst,
		Fields:   msg.Fields,
		MsgOpts:  msg.MsgOpts,
		SendArgs: tcapi.SendArgs{},
		Outage: chaos.OutageSpec{
			Duration: chaos.ExecutorOutageDuration,
			Targets:  executorTargets,
		},
		Assert: tcapi.AssertMessageOptions{
			TickInterval:            5 * time.Second,
			Timeout:                 5 * time.Minute,
			ExpectedVerifierResults: 1,
			AssertVerifierLogs:      false,
			AssertExecutorLogs:      false,
		},
		Run: tcapi.RunConfig{
			ConfirmExecTimeout: 5 * time.Minute,
		},
		ConfirmExecOnDest: true,
	}))
}

func TestChaos_IndexerDown(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode; requires a running devenv environment")
	}
	ctx, lib, setup := setupChaosEVM(t, GetSmokeTestConfig())
	src, dst := chaosChainPair(t, ctx, lib)

	indexerTarget, err := chaos.IndexerContainer(setup.in, 0)
	require.NoError(t, err)

	msg, err := chaos.HydrateEVMEOADefaultVerifier(ctx, lib, src, dst)
	require.NoError(t, err)

	require.NoError(t, chaos.RunScenario(t, ctx, chaos.ScenarioSpec{
		Lib:      lib,
		Src:      src,
		Dst:      dst,
		Fields:   msg.Fields,
		MsgOpts:  msg.MsgOpts,
		SendArgs: tcapi.SendArgs{},
		Outage: chaos.OutageSpec{
			Duration: chaos.ExecutorOutageDuration,
			Targets:  []string{indexerTarget},
		},
		Assert: tcapi.AssertMessageOptions{
			TickInterval:            5 * time.Second,
			Timeout:                 tests.WaitTimeout(t),
			ExpectedVerifierResults: 1,
			AssertVerifierLogs:      false,
			AssertExecutorLogs:      false,
		},
		ConfirmExecOnDest: true,
	}))
}

type chaosSetup struct {
	in *ccv.Cfg
	l  *zerolog.Logger
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

	return &chaosSetup{
		in: in,
		l:  l,
	}
}

func setupChaosEVM(t *testing.T, envOutPath string) (context.Context, ccv.Lib, *chaosSetup) {
	setup := setupChaos(t, envOutPath)
	lib, err := ccv.NewLibFromCCVEnv(setup.l, envOutPath, chain_selectors.FamilyEVM)
	require.NoError(t, err)
	return ccv.Plog.WithContext(t.Context()), lib, setup
}

func chaosChainPair(t *testing.T, ctx context.Context, lib ccv.Lib) (src, dst uint64) {
	t.Helper()
	chains, err := lib.Chains(ctx)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(chains), 2, "expected at least 2 chains for this test in the environment")
	return chains[0].Details.ChainSelector, chains[1].Details.ChainSelector
}
