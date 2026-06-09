package protocol

// LogType classifies a structured log line so that logs can be filtered and
// aggregated consistently across services. Emit it under the LogTypeKey field,
// e.g. logger.Infow("Report submitted successfully", protocol.LogTypeKey, protocol.LogTypeMessageSuccess).
type LogType string

// LogTypeKey is the structured-log field key under which a LogType value is emitted.
const LogTypeKey = "log_type"

const (
	// LogTypeMessageSuccess marks the terminal per-message success event: a message
	// has been fully verified (indexer) or its aggregated report submitted (aggregator).
	// There is at most one of these per message on the happy path.
	LogTypeMessageSuccess LogType = "message_success"

	// LogTypeMessageFailure marks the terminal per-message failure event: a message
	// could not be completed (e.g. it timed out and entered the dead-letter queue).
	// Like LogTypeMessageSuccess, it is a terminal outcome — a message ends as one or
	// the other.
	LogTypeMessageFailure LogType = "message_failure"

	// LogTypeMessageStatus marks a non-terminal per-message progress event, such as a
	// verification being received, a message pending quorum, or a processing attempt.
	// These can fire multiple times per message as it advances.
	LogTypeMessageStatus LogType = "message_status"

	// LogTypeServiceStatus marks a service-level status event that is not tied to a
	// specific message, such as a periodic health summary.
	LogTypeServiceStatus LogType = "service_status"
)

// Canonical structured-log field keys. Prefer these constants over string literals
// when logging these fields, so a field's key name stays identical across every
// service and cannot drift via typo (e.g. messageID vs message_id vs messageId).
const (
	// LogKeyMessageID is the field key for a CCIP message ID.
	LogKeyMessageID = "messageID"
	// LogKeySourceChain is the field key for a source chain selector.
	LogKeySourceChain = "sourceChain"
	// LogKeyDestChain is the field key for a destination chain selector.
	LogKeyDestChain = "destChain"
	// LogKeyChainSel is the field key for a generic (single) chain selector.
	LogKeyChainSel = "chainSel"
	// LogKeyNonce is the field key for a message sequence number / nonce.
	LogKeyNonce = "nonce"
	// LogKeyJobID is the field key for a job-queue job ID.
	LogKeyJobID = "jobID"
)
