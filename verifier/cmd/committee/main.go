package main

import (
	"fmt"
	"os"

	_ "github.com/lib/pq"
	"go.uber.org/zap/zapcore"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap"
	_ "github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evm" // evm accessor driver
	cmd "github.com/smartcontractkit/chainlink-ccv/verifier/cmd"
)

func main() {
	if len(os.Args) >= 2 && os.Args[1] == "ccv" {
		cmd.RunCCVCLI(os.Args[1:])
		return
	}

	if err := bootstrap.Run(
		"EVMCommitteeVerifier",
		cmd.NewCommitteeVerifierServiceFactory(),
		bootstrap.WithLogLevel[bootstrap.JobSpec](zapcore.InfoLevel),
	); err != nil {
		panic(fmt.Sprintf("failed to run EVM committee verifier: %s", err.Error()))
	}
}
