package main

import (
	"fmt"
	"os"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap"
	"github.com/smartcontractkit/chainlink-ccv/bootstrap/keys"
	cmdexecutor "github.com/smartcontractkit/chainlink-ccv/cmd/executor"
	_ "github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evm" // evm accessor driver
	"github.com/smartcontractkit/chainlink-common/keystore"
)

func main() {
	err := bootstrap.Run(
		"Executor",
		cmdexecutor.NewFactory(),
		bootstrap.WithKey(keys.DefaultCSAKeyName, "csa", keystore.Ed25519),   // node identity key for JD communication
		bootstrap.WithKey("default_evm_key", "signing", keystore.ECDSA_S256), // EVM signing key for OffRamp transaction submission
	)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Failed to run executor: %v\n", err)
		os.Exit(1)
	}
}
