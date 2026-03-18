package main

import (
	"context"
	"fmt"

	_ "github.com/lib/pq"
	"go.uber.org/zap/zapcore"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccv/bootstrap"
	cmd "github.com/smartcontractkit/chainlink-ccv/cmd/verifier"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evm"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/blockchain"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/commit"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// deprecatedCreateAccessorFactory is a wrapper around EVMCreateAccessorFactory to avoid changing the verifier
// function signature in a breaking way.
func deprecatedCreateAccessorFactory(ctx context.Context, lggr logger.Logger, blockchainInfos map[string]*blockchain.Info, cfg commit.Config) (chainaccess.AccessorFactory, error) {
	return evm.CreateAccessorFactory(ctx, lggr, blockchainInfos, cfg.OnRampAddresses, cfg.RMNRemoteAddresses)
}

func main() {
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
