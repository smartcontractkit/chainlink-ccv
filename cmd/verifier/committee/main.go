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
		"CommitteeVerifier",
		cmd.NewServiceFactory(),
		bootstrap.WithLogLevel(zapcore.InfoLevel),
	); err != nil {
		panic(fmt.Sprintf("failed to run committee verifier: %s", err.Error()))
	}
}
