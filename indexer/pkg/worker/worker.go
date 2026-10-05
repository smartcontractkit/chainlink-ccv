package worker

import (
	"context"
	"strconv"

	"go.opentelemetry.io/otel/attribute"

	commontracing "github.com/smartcontractkit/chainlink-ccv/common/monitoring/tracing"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// Execute processes a task by finding missing verifiers, loading verifier readers,
// enqueueing verifier calls, and storing the results.
func Execute(ctx context.Context, task *Task) (*TaskResult, error) {
	var spanOpts []commontracing.SpanOption
	// Always sample the first 5 attempts so every task is visible at least once.
	if task.attempt <= 5 {
		spanOpts = append(spanOpts, commontracing.AlwaysSampled())
	}
	ctx, span := task.tracer().StartMessageSpan(ctx, monitoring.ProcessMessageSpanName, task.messageID, spanOpts...)
	defer span.End()
	span.SetAttributes(attribute.String(commontracing.AttemptKey, strconv.Itoa(task.attempt)))

	// Find what verifications we're currently missing
	// This does a storage lookup to see what verifications
	// we currently have for the message.
	//
	// The storage uses a write-through cache so this should be
	// a low cost call.
	existingVerifiers, _ := task.getExistingVerifiers(ctx)
	missing, err := task.getMissingVerifiers(ctx)
	totalVerifiers := task.getVerifiers()
	if err != nil {
		// If we're unable to query the storage, we'll return the error
		// such that we can retry the task later.
		span.RecordError(err)
		return nil, err
	}

	task.logger.Infof("Attempting to retrieve %d verifications for the message. Total Verifiers: %d", len(missing), len(totalVerifiers))

	// Load all missing verifier readers from the registry
	//
	// Verifiers the indexer does not have context of are returned in unknownCCVs
	// These can then be handled by discovery hooks to acquire the readers
	// for further tasks. However for this task they will be excluded.
	verifierReaders, attemptingToRetrieve, unknownCCVs := task.loadVerifierReaders(missing)

	// Process all verifier calls concurrently and collect successful results.
	// Each verifier reader returns a channel that will emit one result when ready.
	//
	// Collects the results from the channels and returns any successful verifications.
	results := task.collectVerifierResults(ctx, verifierReaders)

	// PER-MESSAGE LOG (status): Info on the first attempt, Debug on retries to keep
	// per-message Info volume bounded; terminal outcome is logged separately.
	logAttempt := task.logger.Infow
	if task.attempt > 1 {
		logAttempt = task.logger.Debugw
	}
	logAttempt("Processed verification attempt",
		protocol.LogTypeKey, protocol.LogTypeMessageStatus,
		"messageID", task.messageID.String(),
		"attempt", task.attempt,
		"total", len(totalVerifiers),
		"existing", len(existingVerifiers),
		"missing", len(missing),
		"attempting", len(attemptingToRetrieve),
		"unknown", len(unknownCCVs),
		"collected", len(results),
	)

	if len(results) > 0 {
		err = task.storage.InsertVerifierResults(ctx, results)
		if err != nil {
			span.RecordError(err)
			return nil, err
		}
		span.AddEvent(monitoring.EventResultsStored)
	}

	// The result of the task determines if the message will need to be retried.
	// Retry conditions are handled within the worker pool logic
	return &TaskResult{
		UnknownCCVs:             len(unknownCCVs),
		SuccessfulVerifications: len(results),
		UnavailableCCVs:         len(verifierReaders) - len(results),
	}, nil
}
