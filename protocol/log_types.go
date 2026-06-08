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

	// LogTypeMessageStatus marks a non-terminal per-message progress event, such as a
	// verification being received, a message pending quorum, or a processing attempt.
	// These can fire multiple times per message as it advances.
	LogTypeMessageStatus LogType = "message_status"

	// LogTypeServiceStatus marks a service-level status event that is not tied to a
	// specific message, such as a periodic health summary.
	LogTypeServiceStatus LogType = "service_status"
)
