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

const (
	// DefaultLokiURL is the default Loki WebSocket URL for log streaming in tests.
	DefaultLokiURL     = "ws://localhost:3030"
	DefaultExecTimeout = 40 * time.Second
	DefaultSentTimeout = 10 * time.Second
)

// MissingPrerequisite describes a single absent prerequisite in the environment,
// such as a contract that has not been deployed or a service that is not running.
// It implements the error interface so it can be used with errors.Join and
// testify assertions.
type MissingPrerequisite struct {
	// Name is a human-readable label identifying what is missing.
	Name string
	// Err is the underlying error returned by the lookup that failed.
	Err error
}

func (m MissingPrerequisite) Error() string {
	return fmt.Sprintf("%s: %v", m.Name, m.Err)
}

// TestCase represents a test case that can be run in a variety of environments.
// Implementations may resolve environment-specific configuration (e.g. contract
// addresses) during CheckPrerequisites or Run.
type TestCase interface {
	// Name returns the name of the test case.
	Name() string

	// Run runs the test case.
	// The context is typically derived from the *testing.T's Context() method.
	// Implementations hydrate any required configuration before executing; callers
	// do not need to call CheckPrerequisites first. Returns an error if prerequisites
	// are not met.
	Run(ctx context.Context) error

	// CheckPrerequisites checks whether this test case can run in the current
	// environment (e.g. required contracts deployed, services running).
	// The context is typically derived from the *testing.T's Context() method.
	// Returns a non-empty slice of MissingPrerequisite when the environment lacks
	// one or more expected components — callers should skip the test without
	// treating it as a failure. Returns a non-nil error when the check itself
	// could not complete (e.g. data store unavailable, unknown chain selector);
	// callers should treat this as an unexpected failure. When it succeeds,
	// subsequent Run calls reuse the hydration state.
	CheckPrerequisites(ctx context.Context) ([]MissingPrerequisite, error)
}

// DefaultV3ExecutionGasLimit is the execution gas limit used when SendConfig and MessageOptions omit it.
const DefaultV3ExecutionGasLimit uint32 = 200_000

// RunConfig holds optional overrides for wait/confirm timeouts in TCAPI Run methods.
// Zero values use the fallback passed to SentTimeout or ExecTimeout.
type RunConfig struct {
	// ConfirmSentTimeout overrides ConfirmSendOnSource when non-zero.
	ConfirmSentTimeout time.Duration
	// ConfirmExecTimeout overrides AssertMessage and ConfirmExecOnDest when non-zero.
	ConfirmExecTimeout time.Duration
}

// SentTimeout returns ConfirmSentTimeout when set, otherwise fallback.
func (r RunConfig) SentTimeout(fallback time.Duration) time.Duration {
	if r.ConfirmSentTimeout != 0 {
		return r.ConfirmSentTimeout
	}
	return fallback
}

// ExecTimeout returns ConfirmExecTimeout when set, otherwise fallback.
func (r RunConfig) ExecTimeout(fallback time.Duration) time.Duration {
	if r.ConfirmExecTimeout != 0 {
		return r.ConfirmExecTimeout
	}
	return fallback
}

// SendArgs holds pair-level settings for building and sending ExtraArgsV3 CCIP messages in tcapi tests.
type SendArgs struct {
	ExecutionGasLimit   uint32 // 0: use opts if set, else DefaultV3ExecutionGasLimit
	ExtraArgsParams     any    // passed to dest MessageV3Destination.GetExecutorArgs
	TokenArgsParams     any    // passed to dest GetTokenArgs
	TokenReceiverParams any    // passed to dest GetTokenReceiver
	SendOption          cciptestinterfaces.ChainSendOption
}

// SendV3Message builds and sends a V3 message using BuildV3ExtraArgs, BuildChainMessage, and SendChainMessage.
func SendV3Message(
	ctx context.Context,
	src, dst cciptestinterfaces.CCIP17,
	destSelector uint64,
	fields cciptestinterfaces.MessageFields,
	opts cciptestinterfaces.MessageOptions,
	sendArgs SendArgs,
) (cciptestinterfaces.MessageSentEvent, error) {
	chainAsSource, ok := src.(cciptestinterfaces.ChainAsSource)
	if !ok {
		return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("source chain does not implement ChainAsSource")
	}
	v3Source, ok := src.(cciptestinterfaces.MessageV3Source)
	if !ok {
		return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("source chain does not support V3 message")
	}
	v3Dest, ok := dst.(cciptestinterfaces.MessageV3Destination)
	if !ok {
		return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("dest chain does not support V3 message")
	}

	if sendArgs.ExecutionGasLimit != 0 {
		opts.ExecutionGasLimit = sendArgs.ExecutionGasLimit
	} else if opts.ExecutionGasLimit == 0 {
		opts.ExecutionGasLimit = DefaultV3ExecutionGasLimit
	}

	extraArgs, err := v3Source.BuildV3ExtraArgs(opts, v3Dest, sendArgs.ExtraArgsParams, sendArgs.TokenReceiverParams, sendArgs.TokenArgsParams)
	if err != nil {
		return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("failed to encode V3 extra args: %w", err)
	}

	msg, err := chainAsSource.BuildChainMessage(ctx, fields, extraArgs)
	if err != nil {
		return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("failed to build chain message: %w", err)
	}

	sent, _, err := chainAsSource.SendChainMessage(ctx, destSelector, msg, sendArgs.SendOption)
	if err != nil {
		return cciptestinterfaces.MessageSentEvent{}, fmt.Errorf("failed to send chain message: %w", err)
	}
	return sent, nil
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
