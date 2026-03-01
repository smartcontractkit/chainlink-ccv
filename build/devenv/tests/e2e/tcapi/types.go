package tcapi

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"github.com/rs/zerolog"
	ccv "github.com/smartcontractkit/chainlink-ccv/build/devenv"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/logasserter"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/metrics"
	committeepb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/committee-verifier/v1"
	verifierpb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/verifier/v1"
)

// DefaultLokiURL is the default Loki WebSocket URL for log streaming in tests.
const DefaultLokiURL = "ws://localhost:3030"

// TestCase represents a test case that can be run in a variety of environments.
type TestCase interface {
	// Name returns the name of the test case.
	Name() string

	// Run runs the test case.
	// The context is typically derived from the *testing.T's Context() method.
	// The harness is created separately.
	// The cfg is the configuration of the environment that the test case is running in.
	Run(ctx context.Context, harness TestHarness, cfg *ccv.Cfg) error

	// HavePrerequisites checks if the test case has all the prerequisites to run.
	// The context is typically derived from the *testing.T's Context() method.
	// The cfg is the configuration of the environment that the test case is running in.
	// This typically checks things like e.g. whether the environment has a specific contract
	// deployed, or a specific service is running.
	HavePrerequisites(ctx context.Context, cfg *ccv.Cfg) bool
}

// TestHarness is a harness that can be used by test cases to
// assert various things.
type TestHarness struct {
	// AggregatorClients is a map of aggregator clients by qualifier.
	AggregatorClients map[string]*ccv.AggregatorClient
	// IndexerMonitor is the indexer monitor.
	IndexerMonitor *ccv.IndexerMonitor
	Lib            *ccv.Lib
}

func NewTestHarness(ctx context.Context, envOutPath string, cfg *ccv.Cfg, familiesToLoad ...string) (TestHarness, error) {
	l := zerolog.Ctx(ctx)
	lib, err := ccv.NewLib(l, envOutPath, familiesToLoad...)
	if err != nil {
		return TestHarness{}, err
	}
	aggregatorClients, err := SetupAggregatorClients(ctx, cfg)
	if err != nil {
		return TestHarness{}, err
	}
	indexerMonitor, err := SetupIndexerMonitor(ctx, lib)
	if err != nil {
		return TestHarness{}, err
	}
	return TestHarness{
		AggregatorClients: aggregatorClients,
		IndexerMonitor:    indexerMonitor,
		Lib:               lib,
	}, nil
}

// SetupAggregatorClients creates and registers aggregator clients for all endpoints
// in the configuration. Returns a map of clients by qualifier.
// Cleanup handlers are automatically registered with the test.
func SetupAggregatorClients(
	ctx context.Context,
	in *ccv.Cfg,
) (map[string]*ccv.AggregatorClient, error) {
	aggregatorClients := make(map[string]*ccv.AggregatorClient)
	for qualifier := range in.AggregatorEndpoints {
		client, err := in.NewAggregatorClientForCommittee(zerolog.Ctx(ctx).With().Str("component", fmt.Sprintf("aggregator-client-%s", qualifier)).Logger(), qualifier)
		if err != nil {
			return nil, err
		}
		if client == nil {
			return nil, fmt.Errorf("aggregator client is nil for qualifier %s", qualifier)
		}
		aggregatorClients[qualifier] = client
	}
	return aggregatorClients, nil
}

// SetupIndexerMonitor creates and returns an indexer monitor if the indexer is available.
// Returns nil if the indexer is not available (no error is raised).
func SetupIndexerMonitor(
	ctx context.Context,
	lib *ccv.Lib,
) (*ccv.IndexerMonitor, error) {
	monitors, err := SetupAllIndexerMonitors(ctx, lib)
	if err != nil {
		return nil, err
	}
	for _, monitor := range monitors {
		return monitor, nil
	}
	return nil, fmt.Errorf("no indexer monitors found")
}

func SetupAllIndexerMonitors(
	ctx context.Context,
	lib *ccv.Lib,
) (map[string]*ccv.IndexerMonitor, error) {
	indexerClients, err := lib.AllIndexers()
	if err != nil {
		return nil, err
	}
	indexers := make(map[string]*ccv.IndexerMonitor)
	for _, indexer := range indexerClients {
		indexerMonitor, err := ccv.NewIndexerMonitor(
			zerolog.Ctx(ctx).With().Str("component", fmt.Sprintf("indexer-client-%s", indexer.URI())).Logger(),
			indexer)
		if err != nil {
			return nil, err
		}
		if indexerMonitor == nil {
			return nil, fmt.Errorf("indexer monitor is nil for indexer %s", indexer.URI())
		}
		indexers[indexer.URI()] = indexerMonitor
	}
	return indexers, nil
}

type TestingContext struct {
	Ctx              context.Context
	Impl             map[uint64]cciptestinterfaces.CCIP17
	AggregatorClient *ccv.AggregatorClient
	IndexerClient    *ccv.IndexerMonitor
	LogAsserter      *logasserter.LogAsserter
	Timeout          time.Duration
	logger           zerolog.Logger
}

func NewTestingContext(ctx context.Context, impl map[uint64]cciptestinterfaces.CCIP17, aggregatorClient *ccv.AggregatorClient, indexerClient *ccv.IndexerMonitor) (TestingContext, func()) {
	lokiURL := os.Getenv("LOKI_QUERY_URL")
	if lokiURL == "" {
		lokiURL = DefaultLokiURL
	}

	logger := zerolog.Ctx(ctx).With().Str("component", "TestingContext").Logger()
	logAssert := logasserter.New(lokiURL, logger)

	cleanupFunc := func() {}
	err := logAssert.StartStreaming(ctx, []logasserter.LogStage{
		logasserter.MessageReachedVerifier(),
		logasserter.MessageSigned(),
		logasserter.ProcessingInExecutor(),
		logasserter.SentToChainInExecutor(),
	})
	if err != nil {
		logger.Warn().Err(err).Msg("Could not start log metrics collection")
	} else {
		cleanupFunc = func() {
			logAssert.StopStreaming()
		}
	}

	tc := TestingContext{
		Ctx:              ctx,
		Impl:             impl,
		AggregatorClient: aggregatorClient,
		IndexerClient:    indexerClient,
		LogAsserter:      logAssert,
		Timeout:          180 * time.Second,
		logger:           logger,
	}

	return tc, cleanupFunc
}

func (tc *TestingContext) enrichMetrics(metrics []metrics.MessageMetrics) {
	tc.LogAsserter.EnrichMetrics(metrics)
}

type AssertionResult struct {
	AggregatorFound      bool
	VerifierReached      bool
	VerifierSigned       bool
	IndexerFound         bool
	ExecutorLogFound     bool
	SentToChainFound     bool
	AggregatedResult     *verifierpb.VerifierResult
	IndexedVerifications ccv.GetVerificationsForMessageIDResponse

	// This is only surfaced if ExpectedSignerAddresses is provided in AssertMessageOptions.
	CommitteeVerifierNodeResults []*committeepb.CommitteeVerifierNodeResult
}

type AssertMessageOptions struct {
	TickInterval            time.Duration
	Timeout                 time.Duration
	ExpectedVerifierResults int

	// Optional log verification, since its slower.
	AssertVerifierLogs bool
	AssertExecutorLogs bool
}

func (tc *TestingContext) AssertMessage(messageID [32]byte, opts AssertMessageOptions) (AssertionResult, error) {
	ctx, cancel := context.WithTimeout(tc.Ctx, opts.Timeout)
	defer cancel()

	result := AssertionResult{}

	if opts.AssertVerifierLogs {
		_, err := tc.LogAsserter.WaitForStage(ctx, messageID, logasserter.MessageReachedVerifier())
		if err != nil {
			return result, fmt.Errorf("verifier reached log assertion failed: %w", err)
		}

		tc.logger.Info().
			Str("messageID", fmt.Sprintf("0x%s", hex.EncodeToString(messageID[:]))).
			Msg("found message reached verifier in logs")

		result.VerifierReached = true

		_, err = tc.LogAsserter.WaitForStage(ctx, messageID, logasserter.MessageSigned())
		if err != nil {
			return result, fmt.Errorf("verifier signed log assertion failed: %w", err)
		}

		tc.logger.Info().
			Str("messageID", fmt.Sprintf("0x%s", hex.EncodeToString(messageID[:]))).
			Msg("found verifier signature in logs")

		result.VerifierSigned = true
	}

	if tc.AggregatorClient != nil {
		aggregatedResult, err := tc.AggregatorClient.WaitForVerifierResultForMessage(
			ctx,
			messageID,
			opts.TickInterval)
		if err != nil {
			return result, fmt.Errorf("aggregator check failed: %w", err)
		}

		result.AggregatedResult = aggregatedResult
		result.AggregatorFound = true
	}

	if tc.IndexerClient != nil {
		indexedVerifications, err := tc.IndexerClient.WaitForVerificationsForMessageID(
			ctx,
			messageID,
			opts.TickInterval,
			opts.ExpectedVerifierResults)
		if err != nil {
			return result, fmt.Errorf("indexer check failed: %w", err)
		}

		result.IndexedVerifications = indexedVerifications
		result.IndexerFound = true
	}

	if opts.AssertExecutorLogs {
		_, err := tc.LogAsserter.WaitForStage(ctx, messageID, logasserter.ProcessingInExecutor())
		if err != nil {
			return result, fmt.Errorf("executor log assertion failed: %w", err)
		}

		tc.logger.Info().
			Str("messageID", fmt.Sprintf("0x%s", hex.EncodeToString(messageID[:]))).
			Msg("found verifications for messageID in executor logs")

		result.ExecutorLogFound = true

		_, err = tc.LogAsserter.WaitForStage(ctx, messageID, logasserter.SentToChainInExecutor())
		if err != nil {
			return result, fmt.Errorf("executor sent to chain log assertion failed: %w", err)
		}

		tc.logger.Info().
			Str("messageID", fmt.Sprintf("0x%s", hex.EncodeToString(messageID[:]))).
			Msg("found sent to chain log for messageID in executor logs")

		result.SentToChainFound = true
	}

	return result, nil
}
