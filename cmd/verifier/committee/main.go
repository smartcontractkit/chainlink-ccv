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
	if len(os.Args) >= 2 && os.Args[1] == "ccv" {
		// The CLI loads the verifier secrets itself from the committee verifier's path (it runs
		// before bootstrap.Run, so the service factory has not loaded them yet).
		cmd.RunCCVCLI(os.Args[1:], vsecrets.CommitteeVerifierSecretsPathEnv, vsecrets.DefaultCommitteeVerifierSecretsPath)
		return
	}

	// The lifecycle is chosen by the bootstrap config's app_config_mode key (not a flag or env var):
	// "jd_app_config" (default) runs against a Job Distributor; "local_app_config" reads the app
	// config from local_app_config_path with no JD, for the CCV starter kit / local testing.
	if err := bootstrap.Run(
		"EVMCommitteeVerifier",
		cmd.NewCommitteeVerifierServiceFactory(),
		bootstrap.WithLogLevelFromEnv(zapcore.InfoLevel),
		bootstrap.WithKey(commit.DefaultECDSASigningKeyName, "signing", keystore.ECDSA_S256), // ECDSA key for signing verification results
	); err != nil {
		panic(fmt.Sprintf("failed to run EVM committee verifier: %s", err.Error()))
	}
}
