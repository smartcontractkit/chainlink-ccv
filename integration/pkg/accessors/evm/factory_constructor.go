package evm

import (
	"context"
	"fmt"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evmconfig"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// Importing this package registers the EVM accessor factory with chainaccess, so a process that
// does not run EVM chains must not import it: chainaccess.NewRegistry constructs every registered
// factory eagerly and CreateEVMAccessorFactory fails when no EVM config is mounted. Tooling that
// only needs to read or convert EVM config imports
// github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evmconfig instead, which
// registers nothing.
func init() {
	chainaccess.Register(chainsel.FamilyEVM, CreateEVMAccessorFactory)
}

var _ chainaccess.AccessorFactoryConstructor = CreateEVMAccessorFactory

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
//	http_url = "https://evm-rpc.example.com"
//	ws_url = "wss://evm-rpc.example.com"
//
// Each node needs one HTTP URL reachable from this process; ws_url is optional and enables head
// subscriptions instead of HTTP polling.
//
// Chain ID, family, and chain type are derived from the selector. Shared
// application settings from chainaccess.GenericConfig (for example on-ramp or
// deprecated RMN remote addresses) are supplied separately through genericConfig
// and used when constructing the accessor factory.
//
// It will take all config values it needs from all available config. Note that it would be
// very unusual for a config to have more than one of Committee/Token/Executor configs.
func CreateEVMAccessorFactory(lggr logger.Logger, genericConfig chainaccess.GenericConfig) (chainaccess.AccessorFactory, error) {
	configPath := evmconfig.ResolveConfigPath()
	evmCfg, conversion, err := evmconfig.LoadConfigFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load EVM config: %w", err)
	}
	// Present only when a Chainlink node config was converted. Logged at warn so an operator who
	// mounted their node's file sees what standalone CCV could not carry over.
	if conversion != nil {
		for _, warning := range conversion.Warnings {
			lggr.Warnw("converted Chainlink node EVM config", "detail", warning)
		}
	}
	infos, err := evmCfg.ToInfos()
	if err != nil {
		return nil, fmt.Errorf("failed to build EVM chain infos: %w", err)
	}
	lggr.Infow("loaded EVM config", "numChains", len(infos), "convertedFromNodeConfig", conversion != nil)

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
	// Deprecated configured RMN remotes are carried through only so the readers can warn when
	// one disagrees with the address derived from the ramp's on-chain static config.
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
