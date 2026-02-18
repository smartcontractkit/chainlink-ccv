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
	"github.com/smartcontractkit/chainlink-common/pkg/utils/tests"
	"github.com/smartcontractkit/chainlink-testing-framework/framework"
)

// DefaultHATestConfig is the path to the HA environment output config.
// Override via HA_TEST_CONFIG env var.
const DefaultHATestConfig = "../../env-HA-out.toml"

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

// survivingClients returns a client for agg and indexer instance NOT in the killed set.
// Returns nil if all instances are killed.
func (s *haTestSetup) survivingClients(killedContainers ...string) (aggClient *ccv.AggregatorClient, indexerMon *ccv.IndexerMonitor) {
	killed := make(map[string]bool, len(killedContainers))
	for _, name := range killedContainers {
		killed[name] = true
	}
	for name, client := range s.aggClients {
		if !killed[name] {
			aggClient = client
		}
	}
	for name, mon := range s.indexerMons {
		if !killed[name] {
			indexerMon = mon
		}
	}
	return aggClient, indexerMon
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

	// Verify intermediate pipeline state when clients are available.
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

	// Ground truth: the message must execute successfully on the destination chain.
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

// stopContainer stops a single Docker container by exact name using
// `docker stop`.  Unlike pumba's re2 regex matching (which is unanchored and
// can inadvertently match sibling containers), this performs an exact-name
// stop with no ambiguity.
//
// A t.Cleanup handler is registered to restart the container at test teardown
// so the environment is left in a clean state even if the test fails early.
// If the caller restarts the container explicitly mid-test (e.g. for a
// "recovery" phase), `docker start` is idempotent and the cleanup restart is
// harmless.
func stopContainer(t *testing.T, l *zerolog.Logger, containerName string) {
	t.Helper()
	l.Info().Str("container", containerName).Msg("Stopping container")
	if err := exec.Command("docker", "stop", containerName).Run(); err != nil {
		t.Fatalf("failed to stop container %q: %v", containerName, err)
	}
	t.Cleanup(func() { restartContainer(t, l, containerName) })
}

// restartContainer starts a stopped Docker container by exact name.
// Calling this on an already-running container is a no-op (docker start is
// idempotent).
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

// TestHA_Baseline verifies that the HA environment is healthy: correct topology
// (2 aggregators, 2 indexers, 1 committee) and that a message flows end-to-end
// with all services running.
func TestHA_Baseline(t *testing.T) {
	setup := setupHATest(t)

	// Topology assertions.
	require.Len(t, setup.in.Aggregator, 2, "expected 2 redundant aggregators")
	require.Len(t, setup.in.Indexer, 2, "expected 2 redundant indexers")
	require.Len(t, setup.in.Verifier, 2, "expected 2 verifiers")
	// All aggregators serve the same committee.
	for _, agg := range setup.in.Aggregator {
		require.Equal(t, "default", agg.CommitteeName,
			"all aggregators must belong to the same committee for HA")
	}

	survivingAggClient, survivingIndexerMon := setup.survivingClients()
	setup.sendAndAssertExecution(t, survivingAggClient, survivingIndexerMon)
}

// TestHA_SingleAggregatorDown kills one of two redundant aggregators, verifies
// that a message still flows through the surviving aggregator, then restarts
// the killed aggregator and confirms the system returns to full health.
func TestHA_SingleAggregatorDown(t *testing.T) {
	setup := setupHATest(t)
	require.Len(t, setup.in.Aggregator, 2, "need 2 aggregators for this test")

	killedAgg := setup.in.Aggregator[0].Out.ContainerName
	require.NotEmpty(t, killedAgg)

	// Phase 1: Kill one aggregator, send a message, assert it flows.
	stopContainer(t, setup.l, killedAgg)
	survivingClient, survivingIndexerMon := setup.survivingClients(killedAgg)
	require.NotNil(t, survivingClient, "must have a surviving aggregator client")
	setup.sendAndAssertExecution(t, survivingClient, survivingIndexerMon)

	// Phase 2: Restart the killed aggregator, send another message to verify recovery.
	restartContainer(t, setup.l, killedAgg)
	time.Sleep(5 * time.Second) // allow aggregator to stabilize
	setup.sendAndAssertExecution(t, survivingClient, survivingIndexerMon)
}

// TestHA_SingleIndexerDown kills one of two redundant indexers, verifies that a
// message still flows, then restarts and verifies recovery.
func TestHA_SingleIndexerDown(t *testing.T) {
	setup := setupHATest(t)
	require.Len(t, setup.in.Indexer, 2, "need 2 indexers for this test")

	killedIdx := setup.in.Indexer[0].Out.ContainerName
	require.NotEmpty(t, killedIdx)

	// Phase 1: Kill the first indexer, send a message, assert it flows via the second.
	stopContainer(t, setup.l, killedIdx)
	survivingClient, survivingIndexerMon := setup.survivingClients(killedIdx)
	setup.sendAndAssertExecution(t, survivingClient, survivingIndexerMon)

	// Phase 2: Restart, verify recovery.
	restartContainer(t, setup.l, killedIdx)
	time.Sleep(5 * time.Second)
	setup.sendAndAssertExecution(t, survivingClient, survivingIndexerMon)
}

// TestHA_CrossComponentDown kills one aggregator and one indexer simultaneously,
// verifying that the system tolerates a multi-component partial failure. This
// proves that the remaining aggregator + remaining indexer can independently
// carry the full pipeline.
func TestHA_CrossComponentDown(t *testing.T) {
	setup := setupHATest(t)
	require.Len(t, setup.in.Aggregator, 2, "need 2 aggregators for this test")
	require.Len(t, setup.in.Indexer, 2, "need 2 indexers for this test")

	killedAgg := setup.in.Aggregator[0].Out.ContainerName
	killedIdx := setup.in.Indexer[0].Out.ContainerName
	require.NotEmpty(t, killedAgg)
	require.NotEmpty(t, killedIdx)

	stopContainer(t, setup.l, killedAgg)
	stopContainer(t, setup.l, killedIdx)

	survivingAggClient, survivingIndexerMon := setup.survivingClients(killedAgg, killedIdx)
	require.NotNil(t, survivingAggClient)
	require.NotNil(t, survivingIndexerMon)

	setup.sendAndAssertExecution(t, survivingAggClient, survivingIndexerMon)
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

	// Build per-instance aggregator clients so we can selectively use a
	// surviving instance's client when another is killed.
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

	// Build indexer monitors keyed by container name (not URI) so that
	// survivingClients can match killed container names correctly.
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
