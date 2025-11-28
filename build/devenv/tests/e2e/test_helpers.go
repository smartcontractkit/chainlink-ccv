package e2e

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/ethclient"
	promapi "github.com/prometheus/client_golang/api"
	promv1 "github.com/prometheus/client_golang/api/prometheus/v1"
	"github.com/prometheus/common/model"
	"github.com/rs/zerolog"

	"github.com/smartcontractkit/chainlink-ccv/devenv/tests/e2e/logasserter"

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

// AnvilRPCHelper provides access to Anvil-specific RPC methods.
type AnvilRPCHelper struct {
	client *ethclient.Client
	logger zerolog.Logger
}

// NewAnvilRPCHelper creates a new helper for Anvil RPC operations.
func NewAnvilRPCHelper(client *ethclient.Client, logger zerolog.Logger) *AnvilRPCHelper {
	return &AnvilRPCHelper{
		client: client,
		logger: logger,
	}
}

// Mine mines the specified number of blocks.
func (a *AnvilRPCHelper) Mine(ctx context.Context, numBlocks int) error {
	for i := 0; i < numBlocks; i++ {
		var result any
		err := a.client.Client().CallContext(ctx, &result, "evm_mine")
		if err != nil {
			return fmt.Errorf("failed to mine %d blocks: %w", numBlocks, err)
		}
	}
	a.logger.Info().Int("numBlocks", numBlocks).Msg("Mined blocks")
	return nil
}

func (a *AnvilRPCHelper) MustMine(ctx context.Context, numBlocks int) {
	err := a.Mine(ctx, numBlocks)
	if err != nil {
		panic(fmt.Sprintf("MustMine failed: %v", err))
	}
	// This is to ensure that the blocks are read by client (e.g. source reader in verifier) as it's constantly polling.
	time.Sleep(3 * time.Second)
}

// Snapshot creates a snapshot of the current blockchain state.
func (a *AnvilRPCHelper) Snapshot(ctx context.Context) (string, error) {
	var snapshotID string
	err := a.client.Client().CallContext(ctx, &snapshotID, "evm_snapshot")
	if err != nil {
		return "", fmt.Errorf("failed to create snapshot: %w", err)
	}
	a.logger.Info().Str("snapshotID", snapshotID).Msg("Created snapshot")
	return snapshotID, nil
}

// Revert reverts the blockchain to a previous snapshot.
func (a *AnvilRPCHelper) Revert(ctx context.Context, snapshotID string) error {
	var result bool
	err := a.client.Client().CallContext(ctx, &result, "evm_revert", snapshotID)
	if err != nil {
		return fmt.Errorf("failed to revert to snapshot %s: %w", snapshotID, err)
	}
	if !result {
		return fmt.Errorf("revert to snapshot %s returned false", snapshotID)
	}
	a.logger.Info().Str("snapshotID", snapshotID).Msg("Reverted to snapshot")
	return nil
}

// GetAutomine returns whether auto-mining (instant mining) is enabled.
func (a *AnvilRPCHelper) GetAutomine(ctx context.Context) (bool, error) {
	var automine bool
	err := a.client.Client().CallContext(ctx, &automine, "anvil_getAutomine")
	if err != nil {
		return false, fmt.Errorf("failed to get automine status: %w", err)
	}
	a.logger.Info().Bool("automine", automine).Msg("Got automine status")
	return automine, nil
}

// PrometheusHelper provides utilities for querying Prometheus metrics.
type PrometheusHelper struct {
	api    promv1.API
	logger zerolog.Logger
}

// NewPrometheusHelper creates a new helper for Prometheus operations.
func NewPrometheusHelper(prometheusURL string, logger zerolog.Logger) (*PrometheusHelper, error) {
	client, err := promapi.NewClient(promapi.Config{
		Address: prometheusURL,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create Prometheus client: %w", err)
	}

	return &PrometheusHelper{
		api:    promv1.NewAPI(client),
		logger: logger,
	}, nil
}

func (p *PrometheusHelper) GetPercentile(
	ctx context.Context,
	metric string,
	percentile float64,
) (float64, error) {
	if percentile < 0 || percentile > 1 {
		return 0, fmt.Errorf("percentile must be between 0 and 1, got %f", percentile)
	}

	// We assume CI/test runs start from zeroed histogram buckets for the given selector.
	// Therefore, the bucket values at endTime represent the full histogram over the run.
	//
	// Example query:
	//   histogram_quantile(0.90, sum by (le) (http_request_duration_seconds_bucket{test_id="loadtest-123"}))
	query := fmt.Sprintf(
		"histogram_quantile(%.4f, sum by (le) (%s))",
		percentile,
		metric,
	)

	p.logger.Info().
		Str("metric", metric).
		Str("query", query).
		Float64("percentile", percentile).
		Msg("Prometheus percentile (instant) query")

	// Single evaluation at endTime.
	result, warnings, err := p.api.Query(ctx, query, time.Now())
	if err != nil {
		return 0, fmt.Errorf("failed to query Prometheus: %w", err)
	}

	if len(warnings) > 0 {
		p.logger.Warn().
			Strs("warnings", warnings).
			Str("query", query).
			Msg("Prometheus percentile query returned warnings")
	}

	vector, ok := result.(model.Vector)
	if !ok {
		return 0, fmt.Errorf("unexpected result type: %T (expected model.Vector)", result)
	}

	if len(vector) == 0 {
		return 0, fmt.Errorf("no data found for metric %s", metric)
	}

	// sum by (le) + histogram_quantile should yield exactly one sample; take the first.
	value := float64(vector[0].Value)

	p.logger.Info().
		Str("metric", metric).
		Float64("percentile", percentile).
		Float64("value", value).
		Str("query", query).
		Msg("Retrieved percentile metric (instant)")

	return value, nil
}

func (p *PrometheusHelper) GetCurrentCounter(
	ctx context.Context,
	metric string,
) (int, error) {
	// Wrap metric in sum() so we get one aggregated value.
	query := fmt.Sprintf("sum(%s)", metric)

	p.logger.Info().
		Str("metric", metric).
		Str("query", query).
		Msg("Prometheus current-counter query")

	result, warnings, err := p.api.Query(ctx, query, time.Now())
	if err != nil {
		return 0, fmt.Errorf("failed to query Prometheus: %w", err)
	}

	if len(warnings) > 0 {
		p.logger.Warn().
			Strs("warnings", warnings).
			Str("query", query).
			Msg("Prometheus query returned warnings")
	}

	vector, ok := result.(model.Vector)
	if !ok {
		return 0, fmt.Errorf("unexpected result type: %T (expected model.Vector)", result)
	}

	if len(vector) == 0 {
		return 0, fmt.Errorf("no data found for metric %s", metric)
	}

	// sum(...) should give exactly one sample; we take the first.
	value := int(vector[0].Value)

	p.logger.Info().
		Str("metric", metric).
		Int("value", value).
		Str("query", query).
		Msg("Retrieved current counter metric value")

	return value, nil
}
