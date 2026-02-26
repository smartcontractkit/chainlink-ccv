package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	chain_selectors "github.com/smartcontractkit/chain-selectors"
	ccv "github.com/smartcontractkit/chainlink-ccv/devenv"
	"github.com/smartcontractkit/chainlink-ccv/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/devenv/services"
	"github.com/smartcontractkit/chainlink-common/pkg/utils/tests"
	"github.com/smartcontractkit/chainlink-testing-framework/framework"
)

// DefaultHATestConfig is the path to the HA environment output config.
// When launched via `ccv up env.toml,env-HA.toml`, the output is named
// after the base config (env.toml) → env-out.toml.
// Override via HA_TEST_CONFIG env var.
const DefaultHATestConfig = "../../env-out.toml"

func getHATestConfig() string {
	if cfg := os.Getenv("HA_TEST_CONFIG"); cfg != "" {
		return cfg
	}
	return DefaultHATestConfig
}

// haTestSetup holds everything needed to run an HA regression test.
type haTestSetup struct {
	in           *ccv.Cfg
	chains       []ccv.ChainImpl
	chainMap     map[uint64]cciptestinterfaces.CCIP17
	aggClients   map[string]*ccv.AggregatorClient // container name → per-instance client
	indexerMons  map[string]*ccv.IndexerMonitor
	l            *zerolog.Logger
	fromSelector uint64
	toSelector   uint64
}

// aggsByCommittee returns aggregator inputs for a given committee.
func (s *haTestSetup) aggsByCommittee(committee string) []*services.AggregatorInput {
	var result []*services.AggregatorInput
	for _, agg := range s.in.Aggregator {
		if agg.CommitteeName == committee {
			result = append(result, agg)
		}
	}
	return result
}

// findHACommittee returns the name of a committee that has more than one
// aggregator (i.e., HA expansion happened). Fails the test if none exists.
func (s *haTestSetup) findHACommittee(t *testing.T) string {
	t.Helper()
	for name, committee := range s.in.EnvironmentTopology.NOPTopology.Committees {
		if len(committee.Aggregators) > 1 {
			return name
		}
	}
	t.Fatal("no committee with multiple aggregators found — HA expansion did not happen")
	return ""
}

// survivingAggClient returns an aggregator client for the given committee
// that is NOT in the killed set. Returns nil if all instances are killed.
func (s *haTestSetup) survivingAggClient(committee string, killedContainers ...string) *ccv.AggregatorClient {
	killed := make(map[string]bool, len(killedContainers))
	for _, name := range killedContainers {
		killed[name] = true
	}
	for _, agg := range s.in.Aggregator {
		if agg.CommitteeName != committee || agg.Out == nil {
			continue
		}
		if killed[agg.Out.ContainerName] {
			continue
		}
		if client, ok := s.aggClients[agg.Out.ContainerName]; ok {
			return client
		}
	}
	return nil
}

// survivingIndexerMon returns an indexer monitor that is NOT in the killed set.
func (s *haTestSetup) survivingIndexerMon(killedContainers ...string) *ccv.IndexerMonitor {
	killed := make(map[string]bool, len(killedContainers))
	for _, name := range killedContainers {
		killed[name] = true
	}
	for name, mon := range s.indexerMons {
		if !killed[name] {
			return mon
		}
	}
	return nil
}

// sendAndAssertExecution sends a CCIP message and asserts end-to-end delivery.
// aggClient and indexerMon may be nil to skip intermediate checks; on-chain
// execution on the destination chain is always verified as the ground truth.
func (s *haTestSetup) sendAndAssertExecution(
	t *testing.T,
	aggClient *ccv.AggregatorClient,
	indexerMon *ccv.IndexerMonitor,
) {
	t.Helper()
	ctx := ccv.Plog.WithContext(t.Context())
	l := zerolog.Ctx(ctx)

	seqNo, err := s.chainMap[s.fromSelector].GetExpectedNextSequenceNumber(ctx, s.toSelector)
	require.NoError(t, err)
	l.Info().Uint64("SeqNo", seqNo).Msg("Sending CCIP message")

	_, err = s.chainMap[s.fromSelector].SendMessage(ctx, s.toSelector, cciptestinterfaces.MessageFields{
		Receiver: mustGetEOAReceiverAddress(t, s.chainMap[s.toSelector]),
		Data:     []byte{},
	}, cciptestinterfaces.MessageOptions{
		Version:             2,
		ExecutionGasLimit:   200_000,
		OutOfOrderExecution: true,
	})
	require.NoError(t, err)

	sentEvent, err := s.chainMap[s.fromSelector].WaitOneSentEventBySeqNo(
		ctx, s.toSelector, seqNo, defaultSentTimeout)
	require.NoError(t, err)
	messageID := sentEvent.MessageID

	testCtx := NewTestingContext(t, ctx, s.chainMap, aggClient, indexerMon)
	result, err := testCtx.AssertMessage(messageID, AssertMessageOptions{
		TickInterval:            5 * time.Second,
		Timeout:                 tests.WaitTimeout(t),
		ExpectedVerifierResults: 1,
		AssertVerifierLogs:      false,
		AssertExecutorLogs:      false,
	})
	require.NoError(t, err)
	if aggClient != nil {
		require.NotNil(t, result.AggregatedResult,
			"expected aggregated result from surviving aggregator")
	}
	if indexerMon != nil {
		require.Len(t, result.IndexedVerifications.Results, 1,
			"expected exactly 1 indexed verification")
	}

	e, err := s.chainMap[s.toSelector].WaitOneExecEventBySeqNo(
		ctx, s.fromSelector, seqNo, defaultExecTimeout)
	require.NoError(t, err)
	require.NotNil(t, e)
	require.Equal(t, cciptestinterfaces.ExecutionStateSuccess, e.State,
		"unexpected execution state, return data: %x", e.ReturnData)
}

// ---------------------------------------------------------------------------
// Container lifecycle helpers
// ---------------------------------------------------------------------------

// stopContainer stops a single Docker container by exact name.
// A t.Cleanup handler restarts the container at teardown so the environment
// is left clean even if the test fails early.
func stopContainer(t *testing.T, l *zerolog.Logger, containerName string) {
	t.Helper()
	l.Info().Str("container", containerName).Msg("Stopping container")
	if err := exec.Command("docker", "stop", containerName).Run(); err != nil {
		t.Fatalf("failed to stop container %q: %v", containerName, err)
	}
	t.Cleanup(func() { restartContainer(t, l, containerName) })
}

// restartContainer starts a stopped Docker container by exact name.
func restartContainer(t *testing.T, l *zerolog.Logger, containerName string) {
	t.Helper()
	l.Info().Str("container", containerName).Msg("Restarting container")
	if err := exec.Command("docker", "start", containerName).Run(); err != nil {
		l.Error().Err(err).Str("container", containerName).
			Msg("Failed to restart container")
	}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestHA_Baseline verifies that the HA environment is healthy: expansion
// produced the expected topology and a message flows end-to-end with all
// services running.
func TestHA_Baseline(t *testing.T) {
	setup := setupHATest(t)

	// Verify HA is enabled.
	require.True(t, setup.in.HighAvailability, "HA must be enabled")

	// Verify expansion produced the expected topology.
	// env.toml defines: default (redundant=1), secondary (redundant=1), tertiary (redundant=0)
	// → 3 original + 2 HA clones = 5 aggregators total.
	require.Len(t, setup.in.Aggregator, 5,
		"expected 5 aggregators (3 original + 2 HA clones)")

	// Verify indexer expansion: 1 original + 1 HA clone = 2.
	require.Len(t, setup.in.Indexer, 2,
		"expected 2 indexers (1 original + 1 HA clone)")

	// Verify committee-level aggregator counts.
	haCommittee := setup.findHACommittee(t)
	committeeAggs := setup.aggsByCommittee(haCommittee)
	require.Len(t, committeeAggs, 2,
		"HA committee %q should have 2 aggregators", haCommittee)

	// All aggregators in the HA committee must serve the same committee.
	for _, agg := range committeeAggs {
		require.Equal(t, haCommittee, agg.CommitteeName)
	}

	// Verify the HA clone was named correctly by expansion.
	require.Equal(t, fmt.Sprintf("%s-ha-1", haCommittee), committeeAggs[1].Name,
		"HA clone should follow the naming convention")

	// Verify the topology was updated with both aggregator entries.
	committee := setup.in.EnvironmentTopology.NOPTopology.Committees[haCommittee]
	require.Len(t, committee.Aggregators, 2,
		"topology should have 2 aggregator entries for the HA committee")

	// Verify indexer addresses were expanded.
	require.GreaterOrEqual(t, len(setup.in.EnvironmentTopology.IndexerAddress), 2,
		"topology should have at least 2 indexer addresses after expansion")

	// End-to-end: send a message and verify delivery with all services up.
	aggClient := setup.survivingAggClient(haCommittee)
	indexerMon := setup.survivingIndexerMon()
	require.NotNil(t, aggClient, "need at least one aggregator client for baseline")
	setup.sendAndAssertExecution(t, aggClient, indexerMon)
}

// TestHA_SingleAggregatorDown kills one of the redundant aggregators in an
// HA-enabled committee, verifies that a message still flows through the
// surviving aggregator, then restarts and confirms recovery.
func TestHA_SingleAggregatorDown(t *testing.T) {
	setup := setupHATest(t)

	haCommittee := setup.findHACommittee(t)
	committeeAggs := setup.aggsByCommittee(haCommittee)
	require.Len(t, committeeAggs, 2, "need 2 aggregators in %q for this test", haCommittee)

	killedAgg := committeeAggs[0].Out.ContainerName
	require.NotEmpty(t, killedAgg)

	// Phase 1: Kill one aggregator, send a message, assert it flows via the survivor.
	stopContainer(t, setup.l, killedAgg)
	survivingClient := setup.survivingAggClient(haCommittee, killedAgg)
	require.NotNil(t, survivingClient, "must have a surviving aggregator client in committee %q", haCommittee)
	survivingIdx := setup.survivingIndexerMon()
	setup.sendAndAssertExecution(t, survivingClient, survivingIdx)

	// Phase 2: Restart the killed aggregator, send another message to verify recovery.
	restartContainer(t, setup.l, killedAgg)
	time.Sleep(5 * time.Second)
	setup.sendAndAssertExecution(t, survivingClient, survivingIdx)
}

// TestHA_SingleIndexerDown kills one of two redundant indexers, verifies that a
// message still flows, then restarts and verifies recovery.
func TestHA_SingleIndexerDown(t *testing.T) {
	setup := setupHATest(t)
	require.Len(t, setup.in.Indexer, 2, "need 2 indexers for this test")

	killedIdx := setup.in.Indexer[0].Out.ContainerName
	require.NotEmpty(t, killedIdx)

	haCommittee := setup.findHACommittee(t)

	// Phase 1: Kill the first indexer, send a message, assert it flows via the second.
	stopContainer(t, setup.l, killedIdx)
	aggClient := setup.survivingAggClient(haCommittee)
	survivingIdx := setup.survivingIndexerMon(killedIdx)
	setup.sendAndAssertExecution(t, aggClient, survivingIdx)

	// Phase 2: Restart, verify recovery.
	restartContainer(t, setup.l, killedIdx)
	time.Sleep(5 * time.Second)
	setup.sendAndAssertExecution(t, aggClient, survivingIdx)
}

// TestHA_CrossComponentDown kills one aggregator and one indexer simultaneously,
// verifying that the system tolerates a multi-component partial failure.
func TestHA_CrossComponentDown(t *testing.T) {
	setup := setupHATest(t)
	require.Len(t, setup.in.Indexer, 2, "need 2 indexers for this test")

	haCommittee := setup.findHACommittee(t)
	committeeAggs := setup.aggsByCommittee(haCommittee)
	require.Len(t, committeeAggs, 2, "need 2 aggregators in %q for this test", haCommittee)

	killedAgg := committeeAggs[0].Out.ContainerName
	killedIdx := setup.in.Indexer[0].Out.ContainerName
	require.NotEmpty(t, killedAgg)
	require.NotEmpty(t, killedIdx)

	stopContainer(t, setup.l, killedAgg)
	stopContainer(t, setup.l, killedIdx)

	survivingClient := setup.survivingAggClient(haCommittee, killedAgg)
	require.NotNil(t, survivingClient)
	survivingIdx := setup.survivingIndexerMon(killedIdx)
	require.NotNil(t, survivingIdx)

	setup.sendAndAssertExecution(t, survivingClient, survivingIdx)
}

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

func setupHATest(t *testing.T) *haTestSetup {
	t.Helper()
	t.Cleanup(func() {
		_, err := framework.SaveContainerLogs(
			fmt.Sprintf("%s-%s", framework.DefaultCTFLogsDir, t.Name()))
		require.NoError(t, err)
	})

	envOutPath := getHATestConfig()
	in, err := ccv.LoadOutput[ccv.Cfg](envOutPath)
	require.NoError(t, err)
	ctx := ccv.Plog.WithContext(t.Context())
	l := zerolog.Ctx(ctx)

	lib, err := ccv.NewLib(l, envOutPath, chain_selectors.FamilyEVM)
	require.NoError(t, err)
	chains, err := lib.Chains(ctx)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(chains), 2,
		"HA test requires at least 2 chains")
	chainMap, err := lib.ChainsMap(ctx)
	require.NoError(t, err)

	// Build per-instance aggregator clients for ALL aggregators so we can
	// selectively use a surviving instance when another is killed.
	aggClients := make(map[string]*ccv.AggregatorClient, len(in.Aggregator))
	for _, agg := range in.Aggregator {
		require.NotNil(t, agg.Out,
			"aggregator output is nil — was the environment started?")
		client, err := ccv.NewAggregatorClient(
			l.With().Str("component",
				fmt.Sprintf("agg-client-%s", agg.Out.ContainerName)).Logger(),
			agg.Out.ExternalHTTPSUrl,
			agg.Out.TLSCACertFile,
		)
		require.NoError(t, err)
		aggClients[agg.Out.ContainerName] = client
		t.Cleanup(func() { client.Close() })
	}

	// Build indexer monitors keyed by container name.
	allIndexerClients, err := lib.AllIndexers()
	require.NoError(t, err)
	require.Equal(t, len(in.Indexer), len(allIndexerClients),
		"indexer client count must match indexer config count")
	indexerMons := make(map[string]*ccv.IndexerMonitor, len(allIndexerClients))
	for i, ic := range allIndexerClients {
		containerName := in.Indexer[i].Out.ContainerName
		require.NotEmpty(t, containerName)
		mon, err := ccv.NewIndexerMonitor(
			l.With().Str("component",
				fmt.Sprintf("indexer-client-%s", containerName)).Logger(),
			ic)
		require.NoError(t, err)
		indexerMons[containerName] = mon
	}

	return &haTestSetup{
		in:           in,
		chains:       chains,
		chainMap:     chainMap,
		aggClients:   aggClients,
		indexerMons:  indexerMons,
		l:            l,
		fromSelector: chains[0].Details.ChainSelector,
		toSelector:   chains[1].Details.ChainSelector,
	}
}
