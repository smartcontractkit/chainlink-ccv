package main

import (
	"fmt"
	"os"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap"
	cmdexecutor "github.com/smartcontractkit/chainlink-ccv/cmd/executor"
	_ "github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evm" // evm accessor driver
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/contracttransmitter"
	"github.com/smartcontractkit/chainlink-common/keystore"
)

func main() {
	if len(os.Args) >= 2 && os.Args[1] == "ccv" {
		cmdexecutor.RunCCVCLI(os.Args[1:])
		return
	}

	// The lifecycle is chosen by the bootstrap config's app_config_mode key (not a flag or env var):
	// "jd_app_config" (default) runs against a Job Distributor; "local_app_config" reads the app
	// config from local_app_config_path with no JD.
	err := bootstrap.Run(
		"Executor",
		cmdexecutor.NewFactory(),
		bootstrap.WithKey(contracttransmitter.DefaultKeyName, "transmitting", keystore.ECDSA_S256), // EVM signing key for OffRamp transaction submission
	)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Failed to run executor: %v\n", err)
		os.Exit(1)
	}
}
