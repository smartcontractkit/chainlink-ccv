package e2e

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/rs/zerolog"

	"github.com/smartcontractkit/chainlink-ccv/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/devenv/tests/e2e/logasserter"
	"github.com/smartcontractkit/chainlink-ccv/devenv/tests/e2e/metrics"

	ccv "github.com/smartcontractkit/chainlink-ccv/devenv"
	pb "github.com/smartcontractkit/chainlink-protos/chainlink-ccv/go/v1"
)

type TestingContext struct {
	T                *testing.T
	Ctx              context.Context
	Impl             map[uint64]cciptestinterfaces.CCIP17ProductConfiguration
	AggregatorClient *ccv.AggregatorClient
	IndexerClient    *ccv.IndexerClient
	LogAsserter      *logasserter.LogAsserter
	Timeout          time.Duration
	logger           zerolog.Logger
}

func NewTestingContext(t *testing.T, ctx context.Context, impl map[uint64]cciptestinterfaces.CCIP17ProductConfiguration, aggregatorClient *ccv.AggregatorClient, indexerClient *ccv.IndexerClient) TestingContext {
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
