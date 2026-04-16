package evm

import (
	"context"
	"fmt"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/sourcereader"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	"github.com/smartcontractkit/chainlink-evm/pkg/client"
	"github.com/smartcontractkit/chainlink-evm/pkg/heads"
)

func init() {
	chainaccess.Register(chainsel.FamilyEVM, CreateEVMAccessorFactory)
}

var _ chainaccess.AccessorFactoryConstructor = CreateEVMAccessorFactory

// CreateEVMAccessorFactory is registered with chainaccess.Register to construct EVM accessors.
//
// Per-chain EVM settings are read from `blockchain_infos.<selector>` entries, for
// example:
//
//	[blockchain_infos.5009297550715157269]
//	# EVM-specific Info fields for selector 5009297550715157269
//
// Shared sections from chainaccess.GenericConfig (for example on-ramp or RMN
// remote addresses) may also be present and are used when constructing the
// accessor factory.
//
// It will take all config values it needs from all available config. Note that it would be
// very unusual for a config to have more than one of Committee/Token/Executor configs.
func CreateEVMAccessorFactory(lggr logger.Logger, genericConfig chainaccess.GenericConfig) (chainaccess.AccessorFactory, error) {
	// Convert Infos[string] -> Infos[evm.Info]
	evmInfos := make(map[string]Info)
	err := genericConfig.GetAllConcreteConfig(chainsel.FamilyEVM, &evmInfos)
	if err != nil {
		return nil, fmt.Errorf("error getting evm info: %s", err)
	}

	return CreateAccessorFactory(context.Background(), lggr, genericConfig, evmInfos)
}

// CreateAccessorFactory creates a factory that can build EVM chain accessors.
// TODO: Defer geth client and head tracker creation until GetAccessor is called.
func CreateAccessorFactory(
	ctx context.Context,
	lggr logger.Logger,
	generic chainaccess.GenericConfig,
	infos chainaccess.Infos[Info],
) (chainaccess.AccessorFactory, error) {
	// Create the chain clients then the head trackers
	chainClients := make(map[protocol.ChainSelector]client.Client)
	headTrackers := make(map[protocol.ChainSelector]heads.Tracker)
	for _, selector := range infos.GetAllChainSelectors() {
		lggr.Infow("Creating EVM client and head tracker for chain selector", "chainSelector", selector)
		family, err := chainsel.GetSelectorFamily(uint64(selector))
		if err != nil {
			lggr.Errorw("Failed to get selector family - update chain-selectors library?", "chainSelector", selector, "error", err)
			continue
		}
		if family != chainsel.FamilyEVM {
			lggr.Infow("Skipping non EVM info", "chainSelector", selector)
			// Skip non-EVM chains in EVM registration.
			continue
		}
		chainClient, err := CreateHealthyMultiNodeClient(ctx, infos, lggr, selector)
		if err != nil {
			lggr.Errorw("Failed to create multi-node EVM client - bad RPC?", "chainSelector", selector, "error", err)
			continue
		}
		chainClients[selector] = chainClient

		headTracker := sourcereader.NewSimpleHeadTrackerWrapper(chainClient, lggr)
		headTrackers[selector] = headTracker
	}

	// Convert from map[string]string -> map[chainsel]string
	onRampInfos := chainaccess.Infos[string](generic.OnRampAddresses).GetAllInfos()
	rmnRemoteInfos := chainaccess.Infos[string](generic.RMNRemoteAddresses).GetAllInfos()

	return NewFactory(lggr, onRampInfos, rmnRemoteInfos, headTrackers, chainClients), nil
}
