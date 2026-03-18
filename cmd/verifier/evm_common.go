package verifier

import (
	"context"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg"
	evmaccessor "github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evm"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/blockchain"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/sourcereader"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/commit"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	"github.com/smartcontractkit/chainlink-evm/pkg/client"
	"github.com/smartcontractkit/chainlink-evm/pkg/heads"
)

// DeprecatedEVMCreateAccessorFactory is a wrapper around EVMCreateAccessorFactory to avoid changing the verifier
// function signature in a breaking way.
func DeprecatedEVMCreateAccessorFactory(ctx context.Context, lggr logger.Logger, blockchainInfos map[string]*blockchain.Info, cfg commit.Config) (chainaccess.AccessorFactory, error) {
	return EVMCreateAccessorFactory(ctx, lggr, blockchainInfos, cfg.OnRampAddresses, cfg.RMNRemoteAddresses)
}

// EVMCreateAccessorFactory creates the EVMAccessorFactory.
func EVMCreateAccessorFactory(
	ctx context.Context,
	lggr logger.Logger,
	blockchainInfos map[string]*blockchain.Info,
	OnRampAddresses map[string]string,
	RMNRemoteAddresses map[string]string,
) (chainaccess.AccessorFactory, error) {
	helper := blockchain.NewHelper(blockchainInfos)
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

	return evmaccessor.NewFactory(lggr, helper, OnRampAddresses, RMNRemoteAddresses, headTrackers, chainClients), nil
}
