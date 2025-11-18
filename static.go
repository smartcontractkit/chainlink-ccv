package chainlink_ccv

import _ "embed"

// Executor configuration.
var (
	//go:embed cmd/executor/executor_config.toml
	DefaultExecutorConfigTOML string
)
