package worker

import "fmt"

// Execute processes a task by finding missing verifiers, loading verifier readers,
// enqueueing verifier calls, and storing the results.
func Execute(task *Task) (*TaskResult, error) {
	// Find what verifications we're currently missing
	// This does a storage lookup to see what verifications
	// we currently have for the message.
	//
	// The storage uses a write-through cache so this should be
	// a low cost call.
	missing, err := task.getMissingVerifiers()
	if err != nil {
		// If we're unable to query the storage, we'll return the error
		// such that we can retry the task later.
		return nil, err
	}

	// Load all missing verifier readers from the registry
	//
	// Verifiers the indexer does not have context of are returned in missingReaders
	// These can then be handled by discovery hooks to acquire the readers
	// for further tasks. However for this task they will be excluded.
	verifierReaders, missingReaders := task.loadVerifierReaders(missing)
	if len(missingReaders) != 0 {
		task.logger.Infow(
			fmt.Sprintf("Detected %d unknown verifiers within the message, ignoring them for this run.", len(missingReaders)),
			"messageID", task.messageID.String())
	}

	// Process all verifier calls concurrently and collect successful results.
	// Each verifier reader returns a channel that will emit one result when ready.
	//
	// Collects the results from the channels and returns any successful verifications.
	results := task.collectVerifierResults(verifierReaders)
	if len(results) > 0 {
		err = task.storage.BatchInsertCCVData(task.ctx, results)
		if err != nil {
			return nil, err
		}
	}

	// The result of the task determines if the message will need to be retried.
	// Retry conditions are handled within the worker pool logic
	return &TaskResult{
		MissingVerifiers:    len(missingReaders),
		SuccessfulVerifiers: len(results),
		FailedVerifiers:     len(verifierReaders) - len(results),
	}, nil
}
