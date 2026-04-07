package evm

import (
	"context"
	"fmt"

	"github.com/BurntSushi/toml"

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

// CreateEVMAccessorFactory expects a toml config file in the format:
//
//	 type Config struct {
//	   Infos[string]string `toml:"blockchain_infos"`
//	   CommitteeConfig     `toml:"???"`
//	   TokenConfig         `toml:"???"`
//	   ExecutorConfig      `toml:"???"`
//	}
//
// It will take all config values it needs from all available config. Note that it would be
// very unusual for a config to have more than one of Committee/Token/Executor configs.
func CreateEVMAccessorFactory(lggr logger.Logger, cfg string) (chainaccess.AccessorFactory, error) {
	var genericConfig chainaccess.GenericConfig
	if _, err := toml.Decode(cfg, &genericConfig); err != nil {
		return nil, fmt.Errorf("failed to decode generic config: %w", err)
	}

	// Convert Infos[string] -> Infos[evm.Info]
	evmInfos := make(map[string]Info)

	for selector, configStr := range genericConfig.ChainConfig.GetAllInfos() {
		// Verify chain family.
		isEvm, err := chainsel.IsEvm(uint64(selector))
		if err != nil {
			return nil, fmt.Errorf("failed to determine if selector(%d) is evm: %w", selector, err)
		}
		if !isEvm {
			lggr.Debugw("skipping non-EVM chain selector in EVM accessor factory construction", "chainSelector", selector)
			continue
		}

		var info Info
		if _, err = toml.Decode(configStr, &info); err != nil {
			return nil, fmt.Errorf("failed to decode EVM info for selector(%d): %w", selector, err)
		}
		evmInfos[fmt.Sprintf("%d", selector)] = info
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
		family, err := chainsel.GetSelectorFamily(uint64(selector))
		if err != nil {
			lggr.Errorw("❌ Failed to get selector family - update chain-selectors library?", "chainSelector", selector, "error", err)
			continue
		}
		if family != chainsel.FamilyEVM {
			// Skip non-EVM chains in EVM registration.
			continue
		}
		chainClient, err := CreateHealthyMultiNodeClient(ctx, infos, lggr, selector)
		if err != nil {
			lggr.Errorw("❌ Failed to create multi-node EVM client - bad RPC?", "chainSelector", selector, "error", err)
			continue
		}
		chainClients[selector] = chainClient

		headTracker := sourcereader.NewSimpleHeadTrackerWrapper(chainClient, lggr)
		headTrackers[selector] = headTracker
	}

	return NewFactory(lggr, generic.OnRampAddresses, generic.RMNRemoteAddresses, headTrackers, chainClients), nil
}
