package main

import (
	"fmt"

	_ "github.com/lib/pq"
	"go.uber.org/zap/zapcore"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap"
	cmd "github.com/smartcontractkit/chainlink-ccv/cmd/verifier"
)

func main() {
	if err := bootstrap.Run(
		"EVMCommitteeVerifier",
		cmd.NewServiceFactory(),
		bootstrap.WithLogLevel(zapcore.InfoLevel),
		bootstrap.WithEnsureECDSASigningKey(),
	); err != nil {
		panic(fmt.Sprintf("failed to run evm committee verifier: %s", err.Error()))
	}
}
