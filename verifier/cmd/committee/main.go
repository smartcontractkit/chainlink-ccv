package main

import (
	"fmt"
	"os"

	_ "github.com/lib/pq"
	"go.uber.org/zap/zapcore"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccv/bootstrap"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evm"
	cmd "github.com/smartcontractkit/chainlink-ccv/verifier/cmd"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/commit"
)

func main() {
	if len(os.Args) >= 2 && os.Args[1] == "ccv" {
		cmd.RunCCVCLI(os.Args[1:])
		return
	}

	if err := bootstrap.Run(
		"EVMCommitteeVerifier",
		cmd.NewCommitteeVerifierServiceFactory[evm.Info](
			chainsel.FamilyEVM),
		bootstrap.WithLogLevel[commit.JobSpec](zapcore.InfoLevel),
	); err != nil {
		panic(fmt.Sprintf("failed to run EVM committee verifier: %s", err.Error()))
	}
}
