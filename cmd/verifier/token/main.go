package main

import (
	"fmt"
	"os"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap"
	cmd "github.com/smartcontractkit/chainlink-ccv/cmd/verifier"
	_ "github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evm/register" // evm accessor driver
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vsecrets"
)

func main() {
	if len(os.Args) >= 2 && os.Args[1] == "ccv" {
		// The CLI loads the verifier secrets itself from the token verifier's path (it runs before
		// bootstrap.Run, so the service factory has not loaded them yet).
		cmd.RunCCVCLI(os.Args[1:], vsecrets.TokenVerifierSecretsPathEnv, vsecrets.DefaultTokenVerifierSecretsPath)
		return
	}

	if len(os.Args) >= 2 && os.Args[1] == "validate-config" {
		// Strictly decodes the app config and validates it, with no secrets, DB, or JD. CI-safe.
		cmd.RunValidateConfig(os.Args[2:], cmd.NewTokenVerifierServiceFactory())
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
