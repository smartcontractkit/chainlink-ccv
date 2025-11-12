package chainlink_ccv

import _ "embed"

// Aggregator configuration.
var (
	//go:embed build/devenv/configs/aggregator/default/aggregator.toml
	DefaultAggregatorConfigTOML string

	//go:embed build/devenv/configs/aggregator/secondary/aggregator.toml
	SecondaryAggregatorConfigTOML string

	//go:embed build/devenv/configs/aggregator/tertiary/aggregator.toml
	TertiaryAggregatorConfigTOML string
)

// Verifier configuration.
var (
	//go:embed cmd/verifier/testconfig/default/verifier-1.toml
	DefaultVerifier1ConfigTOML string

	//go:embed cmd/verifier/testconfig/default/verifier-2.toml
	DefaultVerifier2ConfigTOML string

	//go:embed cmd/verifier/testconfig/secondary/verifier-1.toml
	SecondaryVerifier1ConfigTOML string

	//go:embed cmd/verifier/testconfig/secondary/verifier-2.toml
	SecondaryVerifier2ConfigTOML string

	//go:embed cmd/verifier/testconfig/tertiary/verifier-1.toml
	TertiaryVerifier1ConfigTOML string

	//go:embed cmd/verifier/testconfig/tertiary/verifier-2.toml
	TertiaryVerifier2ConfigTOML string
)

// Executor configuration.
var (
	//go:embed cmd/executor/executor_config.toml
	DefaultExecutorConfigTOML string
)

/*
// Indexer configuration.
var (
	//go:embed indexer/config.toml
	DefaultIndexerConfigTOML string
)
*/
