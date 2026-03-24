package main

import (
	"context"
	"fmt"
	"os"

	_ "github.com/lib/pq"
	"go.uber.org/zap/zapcore"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccv/bootstrap"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evm"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/blockchain"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	cmd "github.com/smartcontractkit/chainlink-ccv/verifier/cmd"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/commit"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// deprecatedCreateAccessorFactory is a wrapper around the shared EVM constructor to avoid changing the verifier
// function signature in a breaking way.
func deprecatedCreateAccessorFactory(ctx context.Context, lggr logger.Logger, infos blockchain.Infos, cfg commit.Config) (chainaccess.AccessorFactory, error) {
	return evm.CreateAccessorFactory(ctx, lggr, infos, cfg.OnRampAddresses, cfg.RMNRemoteAddresses)
}

func main() {
	if len(os.Args) >= 2 && os.Args[1] == "ccv" {
		cmd.RunCCVCLI(os.Args[1:])
		return
	}
	if err := bootstrap.Run(
		"EVMCommitteeVerifier",
		cmd.NewCommitteeVerifierServiceFactory(
			chainsel.FamilyEVM,
			deprecatedCreateAccessorFactory),
		bootstrap.WithLogLevel[commit.JobSpec](zapcore.InfoLevel),
	); err != nil {
		panic(fmt.Sprintf("failed to run EVM committee verifier: %s", err.Error()))
	}
}
