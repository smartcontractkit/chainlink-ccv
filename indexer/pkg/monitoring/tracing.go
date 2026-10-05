package monitoring

// Span event names emitted across the indexer's discovery/verification pipeline.
const (
	EventResultsStored        = "results_stored"
	EventVerificationFound    = "verification_found"
	EventVerificationNotFound = "verification_not_found"
	// EventAttempt marks one Task.Execute retry on the task-lifetime process span.
	// Per-attempt detail (missing/attempting/collected counts) is logged, not on the span.
	EventAttempt = "attempt"
)

// DiscoverySpanName is the span opened per message discovered in a single poll tick's
// batch response, closed once the whole batch has been pushed to the worker pool.
const DiscoverySpanName = "indexer.message.discovery"

// ProcessMessageSpanName is the span opened once for a Task's whole lifetime (every
// retry attempt is a child/event on it, not a new span), closed on the terminal
// success or DLQ outcome.
const ProcessMessageSpanName = "indexer.message.process"

// FetchVerificationSpanName is the child span opened per offchain verifier backend
// queried for a message within one attempt; the backend is identified by the
// verifier_name/verifier_address attributes, not the span name.
const FetchVerificationSpanName = "indexer.message.fetch_verification"
