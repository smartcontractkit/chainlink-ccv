package main

import (
	"fmt"
	"os"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap"
	cmdexecutor "github.com/smartcontractkit/chainlink-ccv/cmd/executor"
	_ "github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evm" // evm accessor driver
	"github.com/smartcontractkit/chainlink-common/keystore"
)

func main() {
	err := bootstrap.Run(
		"Executor",
		cmdexecutor.NewFactory(),
		bootstrap.WithKey("default_evm_key", "signing", keystore.ECDSA_S256),
	)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Failed to run executor: %v\n", err)
		os.Exit(1)
	}
}
