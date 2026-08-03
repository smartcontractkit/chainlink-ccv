package monitoring

// Span event names emitted across the verifier message pipeline (sourcereader,
// taskverifier, storagewriter). Kept as constants so debugging/alerting
// tooling can match on them without risking drift from ad-hoc string
// literals at each call site.
const (
	// sourcereader.
	EventChainEventDiscovered    = "event_discovered"
	EventTaskFormed              = "task_formed"
	EventReorgRemovedPending     = "reorg_removed_pending"
	EventReorgRemovedSent        = "reorg_removed_sent"
	EventAddedToPending          = "added_to_pending"
	EventCursedDropped           = "cursed_dropped"
	EventDisabledDropped         = "disabled_dropped"
	EventNotReadyForVerification = "not_ready_for_verification"
	EventReadyForVerification    = "ready_for_verification"
	EventTaskPublished           = "task_published"
	EventAlreadyTracked          = "already_tracked"
	EventAlreadySent             = "already_sent"

	// taskverifier.
	EventJobDiscovered   = "job_discovered"
	EventResultPublished = "result_published"
	EventRetryScheduled  = "retry_scheduled"

	// storagewriter.
	EventWriteSucceeded = "write_succeeded"
)

// MessageDiscoverySpanName returns the name of the per-message span opened by the
// verifier's sourcereader when it first observes a message on-chain, scoped
// to the verifier instance identified by verifierID.
func MessageDiscoverySpanName(verifierID string) string {
	return "verifier.message.discovery@" + verifierID
}

// MessageTaskSendSpanName returns the name of the span opened by the verifier's
// sourcereader for each pending-task send attempt (curse/disablement checks
// and, if the task is ready, publish to the task verifier queue), scoped to
// the verifier instance identified by verifierID.
func MessageTaskSendSpanName(verifierID string) string {
	return "verifier.message.task_send@" + verifierID
}

// TaskVerifierAttemptSpanName returns the name of the span opened by the task
// verifier for each verification attempt of a task, scoped to the verifier
// instance identified by verifierID.
func TaskVerifierAttemptSpanName(verifierID string) string {
	return "taskverifier.message.attempt@" + verifierID
}

// StorageWriterWriteSpanName returns the name of the span opened by the
// storage writer for each result write attempt, scoped to the verifier
// instance identified by verifierID.
func StorageWriterWriteSpanName(verifierID string) string {
	return "storagewriter.message.write@" + verifierID
}
