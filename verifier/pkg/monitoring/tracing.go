package monitoring

// Span event names emitted across the verifier message pipeline (sourcereader,
// taskverifier, storagewriter). Kept as constants so debugging/alerting
// tooling can match on them without risking drift from ad-hoc string
// literals at each call site.
const (
	// sourcereader.
	EventChainEventDiscovered = "event_discovered"
	EventTaskFormed           = "task_formed"
	EventReorgRemovedPending  = "reorg_removed_pending"
	EventReorgRemovedSent     = "reorg_removed_sent"
	EventAddedToPending       = "added_to_pending"
	EventCursedDropped        = "cursed_dropped"
	EventDisabledDropped      = "disabled_dropped"
	EventReadyForVerification = "ready_for_verification"
	EventTaskPublished        = "task_published"
	EventAlreadyTracked       = "already_tracked"
	EventAlreadySent          = "already_sent"

	// taskverifier.
	EventJobDiscovered               = "job_discovered"
	EventResultPublished             = "result_published"
	EventRetryScheduled              = "retry_scheduled"
	EventVerificationFailedPermanent = "verification_failed_permanent"

	// storagewriter.
	EventWriteSucceeded       = "write_succeeded"
	EventWriteFailedPermanent = "write_failed_permanent"
)

// MessageSpanName returns the name of the per-message span opened by the
// verifier's sourcereader when it first observes a message on-chain, scoped
// to the verifier instance identified by verifierID.
func MessageSpanName(verifierID string) string {
	return "verifier.message@" + verifierID
}
