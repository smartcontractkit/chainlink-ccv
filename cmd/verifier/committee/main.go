package main

import (
	"fmt"
	"os"

	_ "github.com/lib/pq"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap"
	cmd "github.com/smartcontractkit/chainlink-ccv/cmd/verifier"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evm/cli/blocks"
	evmregister "github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evm/register"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/commit"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vsecrets"
	"github.com/smartcontractkit/chainlink-common/keystore"
)

func main() {
	if len(os.Args) >= 2 && os.Args[1] == "validate-config" {
		cmd.RunValidateConfig(os.Args[2:], cmd.NewCommitteeVerifierServiceFactory())
		return
	}
	if len(os.Args) >= 2 && os.Args[1] == "ccv" {
		cmd.RunCCVCLI(os.Args[1:], vsecrets.CommitteeVerifierSecretsPathEnv, vsecrets.DefaultCommitteeVerifierSecretsPath, blocks.Command)
		return
	}

	if err := bootstrap.Run(
		"EVMCommitteeVerifier",
		cmd.NewCommitteeVerifierServiceFactory(),
		bootstrap.WithKey(commit.DefaultECDSASigningKeyName, "signing", keystore.ECDSA_S256), // ECDSA key for signing verification results
		bootstrap.WithDeclaredChainInventoryChecker(evmregister.CheckDeclaredChainInventory),
	); err != nil {
		panic(fmt.Sprintf("failed to run EVM committee verifier: %s", err.Error()))
	}
}
