package main

import (
	"fmt"

	_ "github.com/lib/pq"
	"go.uber.org/zap/zapcore"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccv/bootstrap"
	cmd "github.com/smartcontractkit/chainlink-ccv/cmd/verifier"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/commit"
)

func main() {
	if err := bootstrap.Run(
		"EVMCommitteeVerifier",
		cmd.NewCommitteeVerifierServiceFactory(
			chainsel.FamilyEVM,
			cmd.DeprecatedEVMCreateAccessorFactory),
		bootstrap.WithLogLevel[commit.JobSpec](zapcore.InfoLevel),
	); err != nil {
		panic(fmt.Sprintf("failed to run EVM committee verifier: %s", err.Error()))
	}
}
