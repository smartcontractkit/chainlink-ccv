package main

import (
	"context"
	"fmt"

	_ "github.com/lib/pq"
	"go.uber.org/zap/zapcore"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccv/bootstrap"
	cmd "github.com/smartcontractkit/chainlink-ccv/cmd/verifier"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg"
	evmaccessor "github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evm"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/blockchain"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/sourcereader"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/commit"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-evm/pkg/client"
	"github.com/smartcontractkit/chainlink-evm/pkg/heads"
)

func main() {
	if err := bootstrap.Run(
		"EVMCommitteeVerifier",
		cmd.NewServiceFactory(
			chainsel.FamilyEVM,
			func(ctx context.Context, lggr logger.Logger, helper *blockchain.Helper, cfg commit.Config) (chainaccess.AccessorFactory, error) {
				// Create the chain clients then the head trackers
				chainClients := make(map[protocol.ChainSelector]client.Client)
				for _, selector := range helper.GetAllChainSelectors() {
					family, err := chainsel.GetSelectorFamily(uint64(selector))
					if err != nil {
						lggr.Errorw("❌ Failed to get selector family - update chain-selectors library?", "chainSelector", selector, "error", err)
						continue
					}
					if family != chainsel.FamilyEVM {
						// Skip non-EVM chains in EVM registration.
						continue
					}
					chainClient := pkg.CreateHealthyMultiNodeClient(ctx, helper, lggr, selector)
					chainClients[selector] = chainClient
				}

				headTrackers := make(map[protocol.ChainSelector]heads.Tracker)
				for _, selector := range helper.GetAllChainSelectors() {
					family, err := chainsel.GetSelectorFamily(uint64(selector))
					if err != nil {
						lggr.Errorw("❌ Failed to get selector family - update chain-selectors library?", "chainSelector", selector, "error", err)
						continue
					}
					if family != chainsel.FamilyEVM {
						// Skip non-EVM chains in EVM registration.
						continue
					}
					headTracker := sourcereader.NewSimpleHeadTrackerWrapper(chainClients[selector], lggr)
					headTrackers[selector] = headTracker
				}

				return evmaccessor.NewFactory(lggr, helper, cfg.OnRampAddresses, cfg.RMNRemoteAddresses, headTrackers, chainClients), nil
			}),
		bootstrap.WithLogLevel[commit.JobSpec](zapcore.InfoLevel),
	); err != nil {
		panic(fmt.Sprintf("failed to run EVM committee verifier: %s", err.Error()))
	}
}
