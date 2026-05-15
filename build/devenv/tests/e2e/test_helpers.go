package e2e

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	ccv "github.com/smartcontractkit/chainlink-ccv/build/devenv"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/load"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/logasserter"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/metrics"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"

	committeepb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/committee-verifier/v1"
	verifierpb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/verifier/v1"
)

// DefaultLokiURL is the default Loki WebSocket URL for log streaming in tests.
const DefaultLokiURL = "ws://localhost:3030"

// DefaultSmokeTestConfig is the default path to the smoke test configuration file.
const DefaultSmokeTestConfig = "../../env-out.toml"

// GetSmokeTestConfig returns the smoke test configuration path from environment
// variable SMOKE_TEST_CONFIG, or the default path if not set.
func GetSmokeTestConfig() string {
	smokeTestConfig := os.Getenv("SMOKE_TEST_CONFIG")
	if smokeTestConfig == "" {
		smokeTestConfig = DefaultSmokeTestConfig
	}
	return smokeTestConfig
}

// SetupAggregatorClients creates and registers aggregator clients for all endpoints
// in the configuration. Returns a map of clients by qualifier.
// Cleanup handlers are automatically registered with the test.
func SetupAggregatorClients(
	t *testing.T,
	ctx context.Context,
	in *ccv.Cfg,
) map[string]*ccv.AggregatorClient {
	aggregatorClients := make(map[string]*ccv.AggregatorClient)
	for qualifier := range in.AggregatorEndpoints {
		client, err := in.NewAggregatorClientForCommittee(
			zerolog.Ctx(ctx).With().Str("component", fmt.Sprintf("aggregator-client-%s", qualifier)).Logger(),
			qualifier)
		require.NoError(t, err)
		require.NotNil(t, client)
		aggregatorClients[qualifier] = client
		t.Cleanup(func() {
			_ = client.Close()
		})
	}
	return aggregatorClients
}

// SetupIndexerMonitor creates and returns an indexer monitor if the indexer is available.
// Returns nil if the indexer is not available (no error is raised).
func SetupIndexerMonitor(
	t *testing.T,
	ctx context.Context,
	lib ccv.Lib,
) *ccv.IndexerMonitor {
	for _, indexer := range SetupAllIndexerMonitors(t, ctx, lib) {
		return indexer
	}
	return nil
}

func SetupAllIndexerMonitors(
	t *testing.T,
	ctx context.Context,
	lib ccv.Lib,
) map[string]*ccv.IndexerMonitor {
	indexerClients, err := lib.AllIndexers()
	if err != nil {
		return nil
	}
	indexers := make(map[string]*ccv.IndexerMonitor)
	for _, indexer := range indexerClients {
		indexerMonitor, err := ccv.NewIndexerMonitor(
			zerolog.Ctx(ctx).With().Str("component", fmt.Sprintf("indexer-client-%s", indexer.URI())).Logger(),
			indexer)
		require.NoError(t, err)
		require.NotNil(t, indexerMonitor)
		indexers[indexer.URI()] = indexerMonitor
	}
	return indexers
}

type TestingContext struct {
	T                *testing.T
	Ctx              context.Context
	Impl             map[uint64]cciptestinterfaces.CCIP17
	AggregatorClient *ccv.AggregatorClient
	IndexerClient    *ccv.IndexerMonitor
	LogAsserter      *logasserter.LogAsserter
	Timeout          time.Duration
	logger           zerolog.Logger
}

func NewTestingContext(t *testing.T, ctx context.Context, impl map[uint64]cciptestinterfaces.CCIP17, aggregatorClient *ccv.AggregatorClient, indexerClient *ccv.IndexerMonitor) TestingContext {
	lokiURL := os.Getenv("LOKI_QUERY_URL")
	if lokiURL == "" {
		lokiURL = DefaultLokiURL
	}

	logger := zerolog.Ctx(ctx).With().Str("component", "log-asserter").Logger()
	logAssert := logasserter.New(lokiURL, logger)
	err := logAssert.StartStreaming(ctx, []logasserter.LogStage{
		logasserter.MessageReachedVerifier(),
		logasserter.MessageSigned(),
		logasserter.ProcessingInExecutor(),
		logasserter.SentToChainInExecutor(),
	})

	tc := TestingContext{
		T:                t,
		Ctx:              ctx,
		Impl:             impl,
		AggregatorClient: aggregatorClient,
		IndexerClient:    indexerClient,
		LogAsserter:      logAssert,
		Timeout:          180 * time.Second,
		logger:           logger,
	}

	if err != nil {
		t.Logf("Warning: Could not start log metrics collection: %v", err)
	} else {
		t.Cleanup(func() {
			logAssert.StopStreaming()
		})
	}

	return tc
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

func verifyTestConfig(e *deployment.Environment, testConfig *load.TOMLLoadTestRoot) error {
	var err error
	chainsInTestConfig := make(map[uint64]struct{})
	for _, testProfile := range testConfig.TestProfiles {
		for _, chain := range testProfile.ChainsAsSource {
			chainSelector, _ := strconv.ParseUint(chain.Selector, 10, 64)
			chainsInTestConfig[chainSelector] = struct{}{}
		}
		for _, chain := range testProfile.ChainsAsDest {
			chainSelector, _ := strconv.ParseUint(chain.Selector, 10, 64)
			chainsInTestConfig[chainSelector] = struct{}{}
		}
	}

	messageProfileNames := make(map[string]struct{})
	for _, messageProfile := range testConfig.MessageProfiles {
		messageProfileNames[messageProfile.Name] = struct{}{}
	}
	for _, testProfile := range testConfig.TestProfiles {
		for _, message := range testProfile.Messages {
			if _, ok := messageProfileNames[message.MessageProfile]; !ok {
				err = errors.Join(err, fmt.Errorf("message profile %s not found in test config", message.MessageProfile))
			}
		}
	}
	chainsInEnv := e.BlockChains.EVMChains()

	for chain := range chainsInTestConfig {
		if _, ok := chainsInEnv[chain]; !ok {
			err = errors.Join(err, fmt.Errorf("chain %d not found in environment", chain))
		}
	}
	return err
}
