package main

import (
	"fmt"
	"os"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap"
	"github.com/smartcontractkit/chainlink-ccv/verifier/token"
)

func main() {
	err := bootstrap.Run(
		"TokenVerifier",
		&tokenVerifierFactory{},
		// TODO: remove the AppConfig generic type to streamline this API, update factory to accept config as a string.
		bootstrap.WithTOMLAppConfig[token.ConfigWithBlockchainInfos]("/etc/config.toml"),
	)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Failed to run token verifier: %v\n", err)
		os.Exit(1)
	}
}
