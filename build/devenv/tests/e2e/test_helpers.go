package e2e

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/smartcontractkit/chainlink-ccv/devenv/tests/e2e/logasserter"
	"github.com/smartcontractkit/chainlink-ccv/devenv/tests/e2e/metrics"

	ccvEvm "github.com/smartcontractkit/chainlink-ccv/ccv-evm"
	ccv "github.com/smartcontractkit/chainlink-ccv/devenv"
	pb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/go/v1"
)

type TestingContext struct {
	T                *testing.T
	Ctx              context.Context
	Impl             *ccvEvm.CCIP17EVM
	AggregatorClient *ccv.AggregatorClient
	IndexerClient    *ccv.IndexerClient
	LogAsserter      *logasserter.LogAsserter
	Timeout          time.Duration
	logger           zerolog.Logger
}

func NewTestingContext(t *testing.T, ctx context.Context, impl *ccvEvm.CCIP17EVM, aggregatorClient *ccv.AggregatorClient, indexerClient *ccv.IndexerClient) TestingContext {
	lokiURL := os.Getenv("LOKI_QUERY_URL")
	if lokiURL == "" {
		lokiURL = "ws://localhost:3030"
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
	TickInterval time.Duration
	Timeout      time.Duration
}

func (tc *TestingContext) AssertMessage(messageID [32]byte, opts AssertMessageOptions) (AssertionResult, error) {
	ctx, cancel := context.WithTimeout(tc.Ctx, opts.Timeout)
	defer cancel()

	result := AssertionResult{}

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
		opts.TickInterval)
	if err != nil {
		return result, fmt.Errorf("indexer check failed: %w", err)
	}

	result.IndexedVerifications = indexedVerifications
	result.IndexerFound = true

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

	return result, nil
}
