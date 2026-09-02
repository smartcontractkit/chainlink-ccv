package logasserter

func MessageReachedVerifier() LogStage {
	return LogStage{
		Name:       "MessageReachedVerifier",
		Service:    "verifier",
		LogPattern: "Added message to pending queue",
	}
}

func MessageDroppedInVerifier() LogStage {
	return LogStage{
		Name:       "MessageDroppedInVerifier",
		Service:    "verifier",
		LogPattern: "Dropping task",
	}
}

// MessageDroppedByPolicyHook is the terminal drop a committee node logs when the operator's
// policy endpoint answers FAIL. Its pattern is a superset of MessageDroppedInVerifier's
// "Dropping task", so identifyStage must test this stage first.
func MessageDroppedByPolicyHook() LogStage {
	return LogStage{
		Name:       "MessageDroppedByPolicyHook",
		Service:    "verifier",
		LogPattern: "Dropping task - policy hook returned FAIL",
	}
}

// PolicyHookVerdictUnavailable is the non-terminal line a committee node logs when it could not
// get a verdict — a 4xx, 5xx, timeout, or unreachable endpoint — and scheduled a retry.
func PolicyHookVerdictUnavailable() LogStage {
	return LogStage{
		Name:       "PolicyHookVerdictUnavailable",
		Service:    "verifier",
		LogPattern: "Policy hook verdict unavailable",
	}
}

func MessageSigned() LogStage {
	return LogStage{
		Name:       "MessageSigned",
		Service:    "verifier",
		LogPattern: "Message signed successfully",
	}
}

func SentToChainInExecutor() LogStage {
	return LogStage{
		Name:       "SentToChainInExecutor",
		Service:    "executor",
		LogPattern: "submitted tx to chain",
	}
}

func ProcessingInExecutor() LogStage {
	return LogStage{
		Name:       "ProcessingInExecutor",
		Service:    "executor",
		LogPattern: "processing message with ID",
	}
}

func FinalityViolationDetected() LogStage {
	return LogStage{
		Name:       "FinalityViolationDetected",
		Service:    "verifier",
		LogPattern: "FINALITY VIOLATION",
	}
}

func SourceReaderStopped() LogStage {
	return LogStage{
		Name:       "SourceReaderStopped",
		Service:    "verifier",
		LogPattern: "Stopping Service",
	}
}
