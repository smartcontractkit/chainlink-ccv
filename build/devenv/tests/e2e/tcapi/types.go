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
	committeepb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/committee-verifier/v1"
	verifierpb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/verifier/v1"
)

// DefaultLokiURL is the default Loki WebSocket URL for log streaming in tests.
const DefaultLokiURL = "ws://localhost:3030"

// TestCase represents a test case that can be run in a variety of environments.
type TestCase interface {
	Name() string
	HavePrerequisites(ctx context.Context) bool
	Run(ctx context.Context) error
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
