package main

import (
	"context"
	"fmt"

	_ "github.com/lib/pq"
	"go.uber.org/zap/zapcore"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccv/bootstrap"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg"
	evmaccessor "github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evm"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/blockchain"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/sourcereader"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/token"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-evm/pkg/client"
	"github.com/smartcontractkit/chainlink-evm/pkg/heads"
)

func main() {
	if err := bootstrap.Run(
		"EVMTokenVerifier",
		NewTokenVerifierServiceFactory(
			chainsel.FamilyEVM,
			func(ctx context.Context, lggr logger.Logger, blockchainInfos map[string]*blockchain.Info, cfg token.Config) (chainaccess.AccessorFactory, error) {
				helper := blockchain.NewHelper(blockchainInfos)

				chainClients := make(map[protocol.ChainSelector]client.Client)
				for _, selector := range helper.GetAllChainSelectors() {
					family, err := chainsel.GetSelectorFamily(uint64(selector))
					if err != nil {
						lggr.Errorw("❌ Failed to get selector family - update chain-selectors library?", "chainSelector", selector, "error", err)
						continue
					}
					if family != chainsel.FamilyEVM {
						continue
					}
					chainClients[selector] = pkg.CreateHealthyMultiNodeClient(ctx, helper, lggr, selector)
				}

				headTrackers := make(map[protocol.ChainSelector]heads.Tracker)
				for _, selector := range helper.GetAllChainSelectors() {
					family, err := chainsel.GetSelectorFamily(uint64(selector))
					if err != nil {
						lggr.Errorw("❌ Failed to get selector family - update chain-selectors library?", "chainSelector", selector, "error", err)
						continue
					}
					if family != chainsel.FamilyEVM {
						continue
					}
					headTrackers[selector] = sourcereader.NewSimpleHeadTrackerWrapper(chainClients[selector], lggr)
				}

				return evmaccessor.NewFactory(lggr, helper, cfg.OnRampAddresses, cfg.RMNRemoteAddresses, headTrackers, chainClients), nil
			}),
		bootstrap.WithLogLevel[token.JobSpec](zapcore.InfoLevel),
	); err != nil {
		panic(fmt.Sprintf("failed to run EVM token verifier: %s", err.Error()))
	}
}
