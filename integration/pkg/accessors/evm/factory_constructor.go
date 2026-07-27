package evm

import (
	"context"
	"fmt"
	"os"
	"strconv"

	"github.com/BurntSushi/toml"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
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
// chain's ID and family from its selector. Only operator-owned connection and
// runtime settings live in the mounted file; enumeration metadata is recovered here.
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
			ChainID:       chainID,
			Family:        family,
			Nodes:         chain.Nodes,
			FinalityDepth: chain.FinalityDepth,
			TXMBlockTime:  chain.TXMBlockTime,
		}
	}
	return infos, nil
}

// CreateEVMAccessorFactory is registered with chainaccess.Register to construct EVM accessors.
//
// Per-chain EVM settings are read from `chains.<selector>` entries in the EVM-local
// config file, for example:
//
//	[chains.3734403246176062136]
//	finality_depth = 15
//	txm_block_time = "2s"
//	[[chains.3734403246176062136.nodes]]
//	name = "primary"
//	internal_http_url = "http://evm-node:8545"
//	internal_ws_url = "ws://evm-node:8546"
//
// Chain ID, family, and chain type are derived from the selector. Shared
// application settings from chainaccess.GenericConfig (for example on-ramp or
// RMN remote addresses) are supplied separately through genericConfig and used
// when constructing the accessor factory.
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

	return CreateAccessorFactory(lggr, genericConfig, infos)
}

// CreateAccessorFactory creates a lazy factory that starts one production
// chainlink-evm runtime per accessor. Deferring network work until GetAccessor
// lets standalone processes construct their registry while an RPC endpoint is
// unavailable; the multi-node pool then manages endpoint failover at runtime.
// generic is chainaccess.GenericConfig until CCIP-11840.
func CreateAccessorFactory(
	lggr logger.Logger,
	generic chainaccess.GenericConfig,
	infos chainaccess.Infos[Info],
) (chainaccess.AccessorFactory, error) {
	onRampInfos := chainaccess.Infos[string](generic.OnRampAddresses).GetAllInfos()
	rmnRemoteInfos := chainaccess.Infos[string](generic.RMNRemoteAddresses).GetAllInfos()
	destChainConfigs := chainaccess.Infos[chainaccess.DestinationChainConfig](generic.ChainConfiguration).GetAllInfos()

	return newFactory(
		lggr,
		onRampInfos,
		rmnRemoteInfos,
		destChainConfigs,
		generic.MaxRetryDuration,
		func(ctx context.Context, chainSelector protocol.ChainSelector, chainLggr logger.Logger) (chainRuntime, error) {
			info, err := infos.GetBlockchainByChainSelector(chainSelector)
			if err != nil {
				return nil, fmt.Errorf("failed to get EVM config for chain %d: %w", chainSelector, err)
			}
			return newStandaloneChain(ctx, info, chainLggr)
		},
	), nil
}
