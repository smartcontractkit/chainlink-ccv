package main

import (
	"fmt"
	"os"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap"
)

func main() {
	// TODO: add a "direct config" mode to bootstrap that skips JD. It should automatically parse
	//       the expected config file from the bootstrap config location and pass the result as an.
	err := bootstrap.Run("TokenVerifier", &tokenVerifierFactory{})
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Failed to run token verifier: %v\n", err)
		os.Exit(1)
	}
}
