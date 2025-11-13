package e2e

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/devenv/tests/e2e/logasserter"
	"github.com/smartcontractkit/chainlink-ccv/devenv/tests/e2e/metrics"

	ccv "github.com/smartcontractkit/chainlink-ccv/devenv"
	"github.com/smartcontractkit/chainlink-ccv/devenv/evm"
	pb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/go/v1"
)

type TestingContext struct {
	T                *testing.T
	Ctx              context.Context
	Impl             *evm.CCIP17EVM
	AggregatorClient *ccv.AggregatorClient
	IndexerClient    *ccv.IndexerClient
	LogAsserter      *logasserter.LogAsserter
	Timeout          time.Duration
	logger           zerolog.Logger
}

func NewTestingContext(t *testing.T, ctx context.Context, impl *evm.CCIP17EVM, aggregatorClient *ccv.AggregatorClient, indexerClient *ccv.IndexerClient) TestingContext {
	lokiURL := os.Getenv("LOKI_QUERY_URL")
	if lokiURL == "" {
		lokiURL = "ws://localhost:3030"
	}

	logger := zerolog.Ctx(ctx).With().Str("component", "log-asserter").Logger()
	logAssert := logasserter.New(lokiURL, logger)
	err := logAssert.StartStreaming(ctx, []logasserter.LogStage{
		logasserter.MessageReachedVerifier(),
		logasserter.MessageDroppedInVerifier(),
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
		Timeout:          60 * time.Second,
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
	AggregatedResult     *pb.VerifierResult
	IndexedVerifications ccv.GetVerificationsForMessageIDResponse
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

	aggregatedResult, err := tc.AggregatorClient.WaitForVerifierResultForMessage(
		ctx,
		messageID,
		opts.TickInterval)
	if err != nil {
		return result, fmt.Errorf("aggregator check failed: %w", err)
	}

	result.AggregatedResult = aggregatedResult
	result.AggregatorFound = true

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

	if opts.AssertExecutorLogs {
		_, err = tc.LogAsserter.WaitForStage(ctx, messageID, logasserter.ProcessingInExecutor())
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

// AssertMessageReachedAndDroppedInVerifier asserts that a message reached the verifier
// but was dropped due to a curse. This is useful for testing curse behavior where messages
// should not reach the aggregator or executor.
func (tc *TestingContext) AssertMessageReachedAndDroppedInVerifier(messageID [32]byte, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(tc.Ctx, timeout)
	defer cancel()

	// Wait for message to reach verifier
	_, err := tc.LogAsserter.WaitForStage(ctx, messageID, logasserter.MessageReachedVerifier())
	if err != nil {
		return fmt.Errorf("message did not reach verifier: %w", err)
	}

	tc.logger.Info().
		Str("messageID", fmt.Sprintf("0x%s", hex.EncodeToString(messageID[:]))).
		Msg("✓ Message reached verifier")

	// Wait for message to be dropped
	_, err = tc.LogAsserter.WaitForStage(ctx, messageID, logasserter.MessageDroppedInVerifier())
	if err != nil {
		return fmt.Errorf("message was not dropped in verifier: %w", err)
	}

	tc.logger.Info().
		Str("messageID", fmt.Sprintf("0x%s", hex.EncodeToString(messageID[:]))).
		Msg("✓ Message dropped in verifier due to curse")

	return nil
}

func defaultAggregatorPort(in *ccv.Cfg) int {
	for _, aggregator := range in.Aggregator {
		if aggregator.CommitteeName == "default" {
			return aggregator.HostPort
		}
	}
	panic(fmt.Sprintf("default aggregator not found, expected to find a default aggregator in the configuration, got: %+v", in.Aggregator))
}

// NewDefaultTestingContext creates a complete testing context with all necessary components
// for E2E tests. It handles loading the configuration, setting up chains, and initializing
// aggregator and indexer clients.
func NewDefaultTestingContext(t *testing.T, configPath string, expectedChainCount int) (TestingContext, []uint64) {
	in, err := ccv.LoadOutput[ccv.Cfg](configPath)
	require.NoError(t, err)

	ctx := ccv.Plog.WithContext(t.Context())
	l := zerolog.Ctx(ctx)

	chainIDs, wsURLs := make([]string, 0), make([]string, 0)
	for _, bc := range in.Blockchains {
		chainIDs = append(chainIDs, bc.ChainID)
		wsURLs = append(wsURLs, bc.Out.Nodes[0].ExternalWSUrl)
	}

	selectors, e, err := ccv.NewCLDFOperationsEnvironment(in.Blockchains, in.CLDF.DataStore)
	require.NoError(t, err)
	require.Len(t, selectors, expectedChainCount, "expected %d chains for this test in the environment", expectedChainCount)

	c, err := evm.NewCCIP17EVM(ctx, *l, e, chainIDs, wsURLs)
	require.NoError(t, err)

	indexerURL := fmt.Sprintf("http://127.0.0.1:%d", in.Indexer.Port)
	defaultAggregatorAddr := fmt.Sprintf("127.0.0.1:%d", defaultAggregatorPort(in))

	defaultAggregatorClient, err := ccv.NewAggregatorClient(
		zerolog.Ctx(ctx).With().Str("component", "aggregator-client").Logger(),
		defaultAggregatorAddr)
	require.NoError(t, err)
	require.NotNil(t, defaultAggregatorClient)
	t.Cleanup(func() {
		defaultAggregatorClient.Close()
	})

	indexerClient := ccv.NewIndexerClient(
		zerolog.Ctx(ctx).With().Str("component", "indexer-client").Logger(),
		indexerURL)
	require.NotNil(t, indexerClient)

	testCtx := NewTestingContext(t, ctx, c, defaultAggregatorClient, indexerClient)

	return testCtx, selectors
}
