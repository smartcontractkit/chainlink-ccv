package zk

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	oteltrace "go.opentelemetry.io/otel/trace"

	"github.com/smartcontractkit/chainlink-ccv/common/monitoring/tracing"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/commit"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/monitoring"
	verifier "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vtypes"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

const provider = "zk"

// There is a distinction for the message block not being proven yet and RPC/any other errors.
// The not proven retry follows the light client cadence and is configured, the other retry is fixed.
const (
	anyErrorRetry = 30 * time.Second
	// witnessTimeout bounds one witness attempt with all its RPC requests. Tasks are verified one after the other,
	// so an attempt that never returns would stop the whole coordinator.
	witnessTimeout = 2 * time.Minute
)

// Verifier is responsible for verifying messages by building their witness from source chain data
// and the light client, and preparing VerifierNodeResult for storage. Retries are handled by the upper-layer
// processor, but Verifier indicates whether an error is retriable or not.
type Verifier struct {
	lggr       logger.Logger
	monitoring verifier.Monitoring
	verifierID string

	lanes              map[LaneKey]LaneReaders
	ccvVerifierVersion protocol.ByteSlice

	notProvenRetry time.Duration
	anyErrorRetry  time.Duration
}

func NewVerifier(
	lggr logger.Logger,
	monitoring verifier.Monitoring,
	verifierID string,
	config ZKConfig,
	lanes map[LaneKey]LaneReaders,
) verifier.Verifier {
	return &Verifier{
		lggr:               lggr,
		monitoring:         monitoring,
		verifierID:         verifierID,
		lanes:              lanes,
		ccvVerifierVersion: config.VerifierVersion,
		notProvenRetry:     config.NotProvenRetry,
		anyErrorRetry:      anyErrorRetry,
	}
}

func (v *Verifier) VerifyMessages(
	ctx context.Context,
	tasks []verifier.VerificationTask,
) []verifier.VerificationResult {
	results := make([]verifier.VerificationResult, 0, len(tasks))
	for _, task := range tasks {
		results = append(results, v.processVerificationTask(ctx, task))
	}
	return results
}

func (v *Verifier) processVerificationTask(ctx context.Context, task verifier.VerificationTask) verifier.VerificationResult {
	lggr := logger.With(v.lggr, protocol.LogKeyMessageID, task.MessageID, "txHash", task.TxHash)
	lggr.Debugw("Verifying ZK task")

	// Open a child span under the task-verifier attempt span so this witness
	// build extends the base message trace opened by the source reader. The attempt
	// span is carried by the task's TraceContext (the batch ctx passed to
	// VerifyMessages carries no live span), so parent off that span context.
	//
	// IMPORTANT: task.TraceContext is derived from context.WithoutCancel, so inject the attempt
	// span context into ctx to keep its deadline/cancellation for the actual build.
	parentCtx := ctx
	if task.TraceContext != nil {
		if attemptSC := oteltrace.SpanContextFromContext(task.TraceContext); attemptSC.IsValid() {
			parentCtx = oteltrace.ContextWithSpanContext(ctx, attemptSC)
		}
	}
	messageID, _ := protocol.NewBytes32FromString(task.MessageID)
	buildCtx, span := v.monitoring.Tracing().StartMessageSpan(
		parentCtx,
		monitoring.TokenAttestationSpanName(v.verifierID),
		messageID,
		attribute.String(tracing.TokenProviderKey, provider),
		attribute.String(tracing.TxHashKey, task.TxHash.String()),
		attribute.String(tracing.SourceChainSelectorKey, task.Message.SourceChainSelector.String()),
		attribute.String(tracing.SourceChainNameKey, task.Message.SourceChainSelector.ChainName()),
	)
	defer span.End()
	buildStartedAt := time.Now()
	recordOutcome := func(outcome string) {
		v.monitoring.Metrics().IncrementTokenAttestationFetch(buildCtx, provider, outcome)
		v.monitoring.Metrics().RecordTokenAttestationDuration(buildCtx, provider, time.Since(buildStartedAt))
		span.SetAttributes(attribute.String(tracing.TokenOutcomeKey, outcome))
	}

	lane, ok := v.lanes[LaneKey{SourceChainSelector: task.Message.SourceChainSelector, DestChainSelector: task.Message.DestChainSelector}]
	if !ok {
		// No light client serves this lane, so no retry can succeed.
		err := fmt.Errorf("no lane configured from chain %d to chain %d", task.Message.SourceChainSelector, task.Message.DestChainSelector)
		lggr.Errorw("Message uses a lane the verifier does not serve", "err", err)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		recordOutcome(monitoring.TokenAttestationFetchOutcomeError)
		verificationError := verifier.NewVerificationError(err, task)
		return verifier.VerificationResult{Error: &verificationError}
	}

	// 1. Build the witness. Run under the span with a deadline so one stuck RPC request cannot stop the coordinator.
	buildCtx, cancel := context.WithTimeout(buildCtx, witnessTimeout)
	defer cancel()
	message := SentMessage{
		BlockNumber: task.BlockNumber,
		OnRamp:      common.BytesToAddress(task.Message.OnRampAddress),
		MessageID:   common.Hash(messageID),
	}
	witness, err := BuildWitness(buildCtx, lane.Source, lane.Proven, message)
	if errors.Is(err, errNotProven) {
		lggr.Debugw("Message block not proven yet", "err", err)
		span.AddEvent(monitoring.EventAttestationNotReady, oteltrace.WithAttributes(attribute.String(tracing.TokenProviderKey, provider)))
		recordOutcome(monitoring.TokenAttestationFetchOutcomeNotReady)
		verificationError := v.notProvenErrorRetry(err, task)
		return verifier.VerificationResult{Error: &verificationError}
	}
	if err != nil {
		lggr.Warnw("Failed to build witness", "err", err)
		span.AddEvent(monitoring.EventAttestationFetchFailed, oteltrace.WithAttributes(attribute.String(tracing.TokenProviderKey, provider)))
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		recordOutcome(monitoring.TokenAttestationFetchOutcomeError)
		verificationError := v.errorRetry(err, task)
		return verifier.VerificationResult{Error: &verificationError}
	}

	verifierResults, err := witness.Encode(v.ccvVerifierVersion)
	if err != nil {
		lggr.Errorw("Failed to encode witness", "err", err)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		recordOutcome(monitoring.TokenAttestationFetchOutcomeError)
		verificationError := v.errorRetry(err, task)
		return verifier.VerificationResult{Error: &verificationError}
	}

	lggr.Debugw(
		"Witness built successfully",
		"provenBlockNumber", witness.ProvenBlockNumber,
		"headers", len(witness.Headers),
		"proofNodes", len(witness.ProofNodes),
	)

	span.AddEvent(monitoring.EventAttestationFetchSucceeded, oteltrace.WithAttributes(attribute.String(tracing.TokenProviderKey, provider)))
	recordOutcome(monitoring.TokenAttestationFetchOutcomeSuccess)

	// 2. Create VerifierNodeResult
	result, err := commit.CreateVerifierNodeResult(
		&task,
		verifierResults,
		v.ccvVerifierVersion,
	)
	if err != nil {
		lggr.Errorw("CreateVerifierNodeResult: Failed to create VerifierNodeResult", "err", err)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		recordOutcome(monitoring.TokenAttestationFetchOutcomeError)
		verificationError := v.errorRetry(err, task)
		return verifier.VerificationResult{Error: &verificationError}
	}

	span.SetStatus(codes.Ok, "")

	// 3. Return successful result
	// PER-MESSAGE LOG (status): witness complete; storage write is the terminal success.
	lggr.Infow("VerifierResults: Successfully verified message", protocol.LogTypeKey, protocol.LogTypeMessageStatus, "provenBlockNumber", witness.ProvenBlockNumber, "headers", len(witness.Headers))
	return verifier.VerificationResult{Result: result}
}

func (v *Verifier) notProvenErrorRetry(err error, task verifier.VerificationTask) verifier.VerificationError {
	return verifier.NewRetriableVerificationError(err, task, v.notProvenRetry)
}

func (v *Verifier) errorRetry(err error, task verifier.VerificationTask) verifier.VerificationError {
	return verifier.NewRetriableVerificationError(err, task, v.anyErrorRetry)
}
