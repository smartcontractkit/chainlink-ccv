package main

import (
	"fmt"
	"os"

	_ "github.com/lib/pq"
	"go.uber.org/zap/zapcore"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap"
	"github.com/smartcontractkit/chainlink-ccv/bootstrap/keys"
	cmd "github.com/smartcontractkit/chainlink-ccv/cmd/verifier"
	_ "github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evm" // evm accessor driver
	"github.com/smartcontractkit/chainlink-common/keystore"
)

func main() {
	if len(os.Args) >= 2 && os.Args[1] == "ccv" {
		cmd.RunCCVCLI(os.Args[1:])
		return
	}

	if err := bootstrap.Run(
		"EVMCommitteeVerifier",
		cmd.NewCommitteeVerifierServiceFactory(),
		bootstrap.WithLogLevel(zapcore.InfoLevel),
		bootstrap.WithKey(keys.DefaultECDSASigningKeyName, "signing", keystore.ECDSA_S256), // ECDSA key for signing verification results
	); err != nil {
		panic(fmt.Sprintf("failed to run EVM committee verifier: %s", err.Error()))
	}
}
