package monitoring

// Span event names emitted across the executor message pipeline (coordinator
// discovery/attempt spans and ChainlinkExecutor.HandleMessage). Kept as
// constants so debugging/alerting tooling can match on them without risking
// drift from ad-hoc string literals at each call site.
const (
	EventMessageDiscovered        = "message_discovered"
	EventMessageScheduled         = "message_scheduled"
	EventDuplicateRejected        = "duplicate_rejected"
	EventMessageExpired           = "message_expired"
	EventExecutionFailedPermanent = "execution_failed_permanent"
	EventMessageExecuted          = "message_executed"
	EventRetryScheduled           = "retry_scheduled"

	EventInvalidMessageSkipped          = "invalid_message_skipped"
	EventDelayedCurseStateUnknown       = "delayed_curse_state_unknown"
	EventDelayedCursed                  = "delayed_cursed"
	EventDelayedExecutionStateUnknown   = "delayed_execution_state_unknown"
	EventAlreadyExecuted                = "already_executed"
	EventDelayedVerifierResultsError    = "delayed_verifier_results_error"
	EventDelayedNoVerifierResults       = "delayed_no_verifier_results"
	EventUnrecoverableQuorumImpossible  = "unrecoverable_quorum_impossible"
	EventDelayedQuorumNotMet            = "delayed_quorum_not_met"
	EventDelayedPollerNotReady          = "delayed_poller_not_ready"
	EventDelayedHonestAttemptCheckError = "delayed_honest_attempt_check_error"
	EventSkippedHonestAttemptExists     = "skipped_honest_attempt_exists"
	EventUnrecoverableEncodingError     = "unrecoverable_encoding_error"
	EventDelayedTransmitContended       = "delayed_transmit_contended"
	EventMessageTransmitted             = "message_transmitted"
)

// DiscoverySpanName returns the name of the per-message discovery span opened
// when the coordinator identified by executorID first observes a message.
func DiscoverySpanName(executorID string) string {
	return "executor.message@" + executorID
}
