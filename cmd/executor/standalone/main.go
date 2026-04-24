package main

import (
	"fmt"
	"os"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap"
	cmdexecutor "github.com/smartcontractkit/chainlink-ccv/cmd/executor"
	executorsvc "github.com/smartcontractkit/chainlink-ccv/executor"
)

const configPathEnvVar = "EXECUTOR_CONFIG_PATH"

func main() {
	configPath := executorsvc.DefaultConfigFile
	if len(os.Args) > 1 {
		configPath = os.Args[1]
	}
	if envConfig := os.Getenv(configPathEnvVar); envConfig != "" {
		configPath = envConfig
	}

	err := bootstrap.Run(
		"Executor",
		cmdexecutor.NewFactory(),
		bootstrap.WithTOMLAppConfig(configPath),
	)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Failed to run executor: %v\n", err)
		os.Exit(1)
	}
}
