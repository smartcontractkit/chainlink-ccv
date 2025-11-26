package logasserter

func MessageReachedVerifier() LogStage {
	return LogStage{
		Name:       "MessageReachedVerifier",
		Service:    "verifier",
		LogPattern: "Message added to finality queue",
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
		LogPattern: "FINALITY VIOLATION DETECTED",
	}
}
