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
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services/committeeverifier"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/tcapi"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/tcapi/basic"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/tcapi/chaos"
	"github.com/smartcontractkit/chainlink-common/pkg/utils/tests"
	"github.com/smartcontractkit/chainlink-testing-framework/framework"
)

func TestChaos_AggregatorOutageRecovery(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode; requires a running devenv environment")
	}
	ctx, lib, setup, src, dst := setupChaosEVMSession(t)

	aggregatorContainer, err := chaos.DefaultAggregatorNginx(setup.in, devenvcommon.DefaultCommitteeVerifierQualifier)
	require.NoError(t, err)

	runEVMChaosScenario(t, ctx, lib, src, dst, evmChaosConfig{}, &chaos.OutageSpec{
		Duration: chaos.DefaultOutageDuration,
		Targets:  []string{aggregatorContainer},
	}, nil)
}

func TestChaos_VerifierFaultToleranceThresholdViolated(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode; requires a running devenv environment")
	}
	ctx, lib, setup, src, dst := setupChaosEVMSession(t)

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

	setup.l.Info().
		Strs("verifiersToStop", verifierTargets).
		Msg("sending message with some verifiers down")

	runEVMChaosScenario(t, ctx, lib, src, dst, evmChaosConfig{ConfirmExec: true}, &chaos.OutageSpec{
		Duration: chaos.DefaultOutageDuration,
		Targets:  verifierTargets,
	}, nil)
}

func TestChaos_AllExecutorsDown(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode; requires a running devenv environment")
	}
	ctx, lib, setup, src, dst := setupChaosEVMSession(t)

	executorTargets, err := chaos.ExecutorContainers(setup.in, devenvcommon.DefaultExecutorQualifier)
	require.NoError(t, err)

	runEVMChaosScenario(t, ctx, lib, src, dst, evmChaosConfig{
		ConfirmExec: true,
		Timeout:     5 * time.Minute,
		ExecTimeout: 5 * time.Minute,
	}, &chaos.OutageSpec{
		Duration: chaos.DefaultOutageDuration,
		Targets:  executorTargets,
	}, nil)
}

func TestChaos_IndexerDown(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode; requires a running devenv environment")
	}
	ctx, lib, setup, src, dst := setupChaosEVMSession(t)

	indexerTarget, err := chaos.IndexerContainer(setup.in, 0)
	require.NoError(t, err)

	runEVMChaosScenario(t, ctx, lib, src, dst, evmChaosConfig{ConfirmExec: true}, &chaos.OutageSpec{
		Duration: chaos.DefaultOutageDuration,
		Targets:  []string{indexerTarget},
	}, nil)
}

// TestChaos_RPCLatency injects 20,000 ms of network latency on both source and
// destination blockchain RPC containers for 1 minute, then sends a V3 message
// and confirms offchain finalization and on-chain execution succeed despite
// the added latency.
func TestChaos_RPCLatency(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode; requires a running devenv environment")
	}
	ctx, lib, setup, src, dst := setupChaosEVMSession(t)

	srcRPCTarget, err := chaos.BlockchainContainerForSelector(setup.in, src)
	require.NoError(t, err)
	dstRPCTarget, err := chaos.BlockchainContainerForSelector(setup.in, dst)
	require.NoError(t, err)

	setup.l.Info().
		Strs("rpcTargets", []string{srcRPCTarget, dstRPCTarget}).
		Msg("sending message with 20000ms/20sec RPC latency injected")

	runEVMChaosScenario(t, ctx, lib, src, dst, evmChaosConfig{
		ConfirmExec: true,
		Timeout:     5 * time.Minute,
		ExecTimeout: 5 * time.Minute,
	}, &chaos.OutageSpec{},
		&chaos.LatencySpec{
			Duration: 1 * time.Minute,
			Delay:    20000, // 20 seconds of latency to account for 2 RPC calls per chain (send + confirm)
			Targets:  []string{srcRPCTarget, dstRPCTarget},
		})
}

// evmChaosConfig configures the V3 message lifecycle options for an EVM chaos scenario.
// Zero values use sensible defaults: tests.WaitTimeout(t) for Timeout, no exec-timeout
// override, and ConfirmExec=false. When Latency is non-nil, the scenario injects network
// latency instead of a container stop outage.
type evmChaosConfig struct {
	ConfirmExec bool
	Timeout     time.Duration // 0 = tests.WaitTimeout(t)
	ExecTimeout time.Duration // 0 = no override
}

// setupChaosEVMSession is the shared preamble for EVM chaos tests: loads the devenv
// environment and picks the first two chains.
func setupChaosEVMSession(t *testing.T) (context.Context, ccv.Lib, *chaosSetup, uint64, uint64) {
	ctx, lib, setup := setupChaosEVM(t, GetSmokeTestConfig())
	src, dst := chaosChainPair(t, ctx, lib)
	return ctx, lib, setup, src, dst
}

// runEVMChaosScenario hydrates a default EOA-receiver V3 message and runs the chaos
// scenario. cfg overrides the default assert timeout, exec timeout, and ConfirmExec flag.
func runEVMChaosScenario(t *testing.T, ctx context.Context, lib ccv.Lib, src, dst uint64, cfg evmChaosConfig, outage *chaos.OutageSpec, latency *chaos.LatencySpec) {
	t.Helper()
	receiver, ccvs, executor, err := basic.ResolveEOAReceiverDefaultVerifier(ctx, lib, src, dst)
	require.NoError(t, err)

	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = tests.WaitTimeout(t)
	}

	spec := chaos.ScenarioSpec{
		Lib: lib,
		Src: src,
		Dst: dst,
		Fields: cciptestinterfaces.MessageFields{
			Receiver: receiver,
		},
		Opts: cciptestinterfaces.MessageOptions{
			FinalityConfig: 1,
			Executor:       executor,
			CCVs:           ccvs,
		},
		SendArgs: tcapi.SendArgs{},
		Assert: tcapi.AssertMessageOptions{
			TickInterval:            5 * time.Second,
			Timeout:                 timeout,
			ExpectedVerifierResults: 1,
			AssertVerifierLogs:      false,
			AssertExecutorLogs:      false,
		},
		ConfirmExecOnDest: cfg.ConfirmExec,
		Latency:           latency,
		Outage:            outage,
	}
	if cfg.ExecTimeout != 0 {
		spec.Run.ConfirmExecTimeout = cfg.ExecTimeout
	}

	require.NoError(t, chaos.RunScenario(t, ctx, spec))
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
