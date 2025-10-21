package logasserter

func ProcessingInExecutor() LogStage {
	return LogStage{
		Name:       "ProcessingInExecutor",
		Service:    "executor",
		LogPattern: "processing message with ID",
	}
}

func MessageSigned() LogStage {
	return LogStage{
		Name:       "MessageSigned",
		Service:    "verifier",
		LogPattern: "Message signed successfully",
	}
}
