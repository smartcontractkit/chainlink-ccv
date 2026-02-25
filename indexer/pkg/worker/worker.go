package worker

import "context"

// Execute processes a task by finding missing verifiers, loading verifier readers,
// enqueueing verifier calls, and storing the results.
func Execute(ctx context.Context, task *Task) (*TaskResult, error) {
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
		return nil, err
	}

	task.logger.Infof("Attempting to retrieve %d verifications for the message. Total Verifiers: %d", len(missing), len(totalVerifiers))

	// Load all missing verifier readers from the registry
	//
	// Verifiers the indexer does not have context of are returned in unknownCCVs
	// These can then be handled by discovery hooks to acquire the readers
	// for further tasks. However for this task they will be excluded.
	verifierReaders, attemptingToRetrieve, unknownCCVs := task.loadVerifierReaders(missing)
	if len(unknownCCVs) != 0 {
		task.logger.Infof("Detected %d unknown verifiers within the message, ignoring them for this run.", len(unknownCCVs))
	}

	// Log out useful information about this run
	task.logger.Infof("Source Specified CCVs %s", totalVerifiers)
	task.logger.Infof("Exisiting Verifications %s", existingVerifiers)
	task.logger.Infof("Attempting to Retrieve %s", attemptingToRetrieve)
	task.logger.Infof("Unknown CCVs %s", unknownCCVs)

	// Process all verifier calls concurrently and collect successful results.
	// Each verifier reader returns a channel that will emit one result when ready.
	//
	// Collects the results from the channels and returns any successful verifications.
	results := task.collectVerifierResults(ctx, verifierReaders)
	if len(results) > 0 {
		task.logger.Infof("Collected %d new verifications for the message", len(results))
		err = task.storage.InsertVerifierResults(ctx, results)
		if err != nil {
			return nil, err
		}
	}

	// The result of the task determines if the message will need to be retried.
	// Retry conditions are handled within the worker pool logic
	return &TaskResult{
		UnknownCCVs:             len(unknownCCVs),
		SuccessfulVerifications: len(results),
		UnavailableCCVs:         len(verifierReaders) - len(results),
	}, nil
}
