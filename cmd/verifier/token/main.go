package main

import (
	"fmt"
	"os"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap"
	cmd "github.com/smartcontractkit/chainlink-ccv/cmd/verifier"
	_ "github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evm" // evm accessor driver
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vsecrets"
)

func main() {
	if len(os.Args) >= 2 && os.Args[1] == "ccv" {
		// The CLI loads the verifier secrets itself from the token verifier's path (it runs before
		// bootstrap.Run, so the service factory has not loaded them yet).
		cmd.RunCCVCLI(os.Args[1:], vsecrets.TokenVerifierSecretsPathEnv, vsecrets.DefaultTokenVerifierSecretsPath)
		return
	}

	err := bootstrap.Run(
		"TokenVerifier",
		cmd.NewTokenVerifierServiceFactory(),
	)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Failed to run token verifier: %v\n", err)
		os.Exit(1)
	}
}
