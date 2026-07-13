package evm

import (
	"context"
	"fmt"
	"os"

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

func loadConfig(path string) (*Config, error) {
	var cfg Config
	md, err := toml.DecodeFile(path, &cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal config file %s: %w", path, err)
	}
	if len(md.Undecoded()) > 0 {
		return nil, fmt.Errorf("unknown fields in config: %v", md.Undecoded())
	}

	return &cfg, nil
}

// CreateEVMAccessorFactory is registered with chainaccess.Register to construct EVM accessors.
//
// Per-chain EVM settings are read from `blockchain_infos.<selector>` entries in
// the EVM-local config file, for
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
func CreateEVMAccessorFactory(lggr logger.Logger, genericConfig chainaccess.GenericConfig) (chainaccess.AccessorFactory, error) { //nolint:staticcheck // SA1019: GenericConfig still carries shared application config
	configPath, ok := os.LookupEnv(EVMConfigPathEnv)
	if !ok {
		configPath = DefaultEVMConfigPath
	}

	evmConfig, err := loadConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load EVM config: %w", err)
	}
	lggr.Infow("loaded EVM config", "numChains", len(evmConfig.BlockchainInfos))

	return CreateAccessorFactory(context.Background(), lggr, genericConfig, evmConfig.BlockchainInfos)
}

// CreateAccessorFactory creates a factory that can build EVM chain accessors.
// TODO: Defer geth client and head tracker creation until GetAccessor is called.
// generic param is chainaccess.GenericConfig until CCIP-11840.
func CreateAccessorFactory(
	ctx context.Context,
	lggr logger.Logger,
	generic chainaccess.GenericConfig, //nolint:staticcheck // SA1019: registry still decodes the deprecated GenericConfig until CCIP-11840
	infos chainaccess.Infos[Info],
) (chainaccess.AccessorFactory, error) {
	// Create the chain clients, head trackers, and collect primary RPC URLs.
	chainClients := make(map[protocol.ChainSelector]client.Client)
	headTrackers := make(map[protocol.ChainSelector]heads.Tracker)
	rpcURLs := make(map[protocol.ChainSelector]string)
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
		headTrackers[selector] = sourcereader.NewSimpleHeadTrackerWrapper(chainClient, lggr)

		if info, err := infos.GetBlockchainByChainSelector(selector); err == nil {
			if node, err := info.GetFirstNode(); err == nil {
				rpcURLs[selector] = node.InternalHTTPUrl
			}
		}
	}

	// Convert from map[string]T -> map[chainsel]T
	onRampInfos := chainaccess.Infos[string](generic.OnRampAddresses).GetAllInfos()
	rmnRemoteInfos := chainaccess.Infos[string](generic.RMNRemoteAddresses).GetAllInfos()
	destChainConfigs := chainaccess.Infos[chainaccess.DestinationChainConfig](generic.ChainConfiguration).GetAllInfos()

	return NewFactory(lggr, onRampInfos, rmnRemoteInfos, headTrackers, chainClients, destChainConfigs, generic.MaxRetryDuration, rpcURLs), nil
}
