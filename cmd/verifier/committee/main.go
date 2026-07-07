package main

import (
	"fmt"
	"os"

	_ "github.com/lib/pq"
	"go.uber.org/zap/zapcore"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap"
	cmd "github.com/smartcontractkit/chainlink-ccv/cmd/verifier"
	_ "github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evm" // evm accessor driver
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/commit"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vsecrets"
	"github.com/smartcontractkit/chainlink-common/keystore"
)

func main() {
	// Load the verifier secrets file once (DB URL + aggregator HMAC credentials); an absent file is
	// fine and falls back to environment variables. Shared by both the CLI and the service.
	secretsPath := vsecrets.ResolveSecretsPath(vsecrets.CommitteeVerifierSecretsPathEnv, vsecrets.DefaultCommitteeVerifierSecretsPath)
	secrets, err := vsecrets.Load(secretsPath)
	if err != nil {
		panic(fmt.Sprintf("failed to load committee verifier secrets: %s", err.Error()))
	}

	if len(os.Args) >= 2 && os.Args[1] == "ccv" {
		cmd.RunCCVCLI(os.Args[1:], secrets)
		return
	}

	if err := bootstrap.Run(
		"EVMCommitteeVerifier",
		cmd.NewCommitteeVerifierServiceFactory(secrets),
		bootstrap.WithLogLevelFromEnv(zapcore.InfoLevel),
		bootstrap.WithKey(commit.DefaultECDSASigningKeyName, "signing", keystore.ECDSA_S256), // ECDSA key for signing verification results
	); err != nil {
		panic(fmt.Sprintf("failed to run EVM committee verifier: %s", err.Error()))
	}
}
