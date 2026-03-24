package evm

import (
	"context"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/blockchain"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/sourcereader"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	"github.com/smartcontractkit/chainlink-evm/pkg/client"
	"github.com/smartcontractkit/chainlink-evm/pkg/heads"
)

// CreateAccessorFactory creates a factory that can build EVM chain accessors.
func CreateAccessorFactory(
	ctx context.Context,
	lggr logger.Logger,
	infos blockchain.Infos,
	onRampAddresses map[string]string,
	rmnRemoteAddresses map[string]string,
) (chainaccess.AccessorFactory, error) {
	// Create the chain clients then the head trackers
	chainClients := make(map[protocol.ChainSelector]client.Client)
	headTrackers := make(map[protocol.ChainSelector]heads.Tracker)
	for _, selector := range infos.GetAllChainSelectors() {
		family, err := chainsel.GetSelectorFamily(uint64(selector))
		if err != nil {
			lggr.Errorw("❌ Failed to get selector family - update chain-selectors library?", "chainSelector", selector, "error", err)
			continue
		}
		if family != chainsel.FamilyEVM {
			// Skip non-EVM chains in EVM registration.
			continue
		}
		chainClient, err := pkg.CreateHealthyMultiNodeClient(ctx, infos, lggr, selector)
		if err != nil {
			lggr.Errorw("❌ Failed to create multi-node EVM client - bad RPC?", "chainSelector", selector, "error", err)
			continue
		}
		chainClients[selector] = chainClient

		headTracker := sourcereader.NewSimpleHeadTrackerWrapper(chainClient, lggr)
		headTrackers[selector] = headTracker
	}

	return NewFactory(lggr, infos, onRampAddresses, rmnRemoteAddresses, headTrackers, chainClients), nil
}
