package evm

import (
	"context"
	"fmt"
	"os"
	"strconv"

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

func resolveConfigPath() string {
	if configPath := os.Getenv(EVMConfigPathEnv); configPath != "" {
		return configPath
	}
	return DefaultEVMConfigPath
}

// toInfos reconstructs the accessor's Infos[Info] from the operator-local config, deriving each
// chain's ID and family from its selector. Only connection and tuning settings live in the mounted
// file; enumeration metadata is recovered here.
func (c Config) toInfos() (chainaccess.Infos[Info], error) {
	infos := make(chainaccess.Infos[Info], len(c.Chains))
	for selector, chain := range c.Chains {
		sel, err := strconv.ParseUint(selector, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid chain selector %q: %w", selector, err)
		}
		chainID, err := chainsel.GetChainIDFromSelector(sel)
		if err != nil {
			return nil, fmt.Errorf("chain selector %s: %w", selector, err)
		}
		family, err := chainsel.GetSelectorFamily(sel)
		if err != nil {
			return nil, fmt.Errorf("chain selector %s: %w", selector, err)
		}
		infos[selector] = Info{
			ChainID:         chainID,
			Type:            chain.ChainType,
			Family:          family,
			UniqueChainName: chain.UniqueChainName,
			Nodes:           chain.Nodes,
		}
	}
	return infos, nil
}

// CreateEVMAccessorFactory is registered with chainaccess.Register to construct EVM accessors.
//
// Per-chain EVM settings are read from `chains.<selector>` entries in the EVM-local
// config file, for example:
//
//	[chains.5009297550715157269]
//	chain_type = "optimismBedrock"
//	[[chains.5009297550715157269.nodes]]
//	internal_http_url = "http://evm-node:8545"
//	internal_ws_url = "ws://evm-node:8546"
//
// Chain ID and family are derived from the selector; only connection details and
// chain-type tuning are stored in the file. Shared application settings from
// chainaccess.GenericConfig (for example on-ramp or RMN remote addresses) are supplied
// separately through genericConfig and used when constructing the accessor factory.
//
// It will take all config values it needs from all available config. Note that it would be
// very unusual for a config to have more than one of Committee/Token/Executor configs.
func CreateEVMAccessorFactory(lggr logger.Logger, genericConfig chainaccess.GenericConfig) (chainaccess.AccessorFactory, error) {
	configPath := resolveConfigPath()
	evmConfig, err := loadConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load EVM config: %w", err)
	}
	infos, err := evmConfig.toInfos()
	if err != nil {
		return nil, fmt.Errorf("failed to build EVM chain infos: %w", err)
	}
	lggr.Infow("loaded EVM config", "numChains", len(infos))

	return CreateAccessorFactory(context.Background(), lggr, genericConfig, infos)
}

// CreateAccessorFactory creates a factory that can build EVM chain accessors.
// TODO: Defer geth client and head tracker creation until GetAccessor is called.
// generic param is chainaccess.GenericConfig until CCIP-11840.
func CreateAccessorFactory(
	ctx context.Context,
	lggr logger.Logger,
	generic chainaccess.GenericConfig,
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
