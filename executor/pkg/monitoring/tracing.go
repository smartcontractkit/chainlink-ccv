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
	EventMessageExecuted          = "message_executed"
	EventRetryScheduled           = "retry_scheduled"

	EventInvalidMessageSkipped          = "invalid_message_skipped"
	EventDelayedCurseStateUnknown       = "delayed_curse_state_unknown"
	EventDelayedCursed                  = "delayed_cursed"
	EventDelayedExecutionStateUnknown   = "delayed_execution_state_unknown"
	EventAlreadyExecuted                = "already_executed"
	EventUnrecoverableQuorumImpossible  = "unrecoverable_quorum_impossible"
	EventDelayedPollerNotReady          = "delayed_poller_not_ready"
	EventSkippedHonestAttemptExists     = "skipped_honest_attempt_exists"
	EventMessageTransmitted             = "message_transmitted"
)

// DiscoverySpanName returns the name of the per-message discovery span opened
// when the coordinator identified by executorID first observes a message.
func DiscoverySpanName(executorID string) string {
	return "executor.message.discovery@" + executorID
}

// ProcessPayloadSpanName returns the name of the per-attempt span opened by
// the coordinator each time a message is popped off the delayed heap for
// execution, scoped to the executor instance identified by executorID.
func ProcessPayloadSpanName(executorID string) string {
	return "executor.message.process@" + executorID
}
