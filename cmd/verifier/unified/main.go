package main

import (
	"fmt"
	"os"

	_ "github.com/lib/pq"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap"
	cmd "github.com/smartcontractkit/chainlink-ccv/cmd/verifier"
	_ "github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evm/register" // evm accessor driver
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/commit"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vsecrets"
	"github.com/smartcontractkit/chainlink-common/keystore"
)

func main() {
	if len(os.Args) >= 2 && os.Args[1] == "ccv" {
		// The CLI loads the verifier secrets itself (it runs before bootstrap.Run, so the
		// service factory has not loaded them yet).
		cmd.RunCCVCLI(os.Args[1:], vsecrets.VerifierSecretsPathEnv, vsecrets.DefaultVerifierSecretsPath)
		return
	}

	if err := bootstrap.Run(
		"EVMVerifier",
		cmd.NewUnifiedVerifierServiceFactory(),
		// ECDSA key for signing verification results. Always declared: unused when no committee
		// entry is configured, and local mode without [db]/[keystore] runs keystore-less anyway.
		bootstrap.WithKey(commit.DefaultECDSASigningKeyName, "signing", keystore.ECDSA_S256),
	); err != nil {
		panic(fmt.Sprintf("failed to run unified verifier: %s", err.Error()))
	}
}
