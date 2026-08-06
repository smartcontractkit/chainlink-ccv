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
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
)

func init() {
	chainaccess.Register(chainsel.FamilyEVM, CreateEVMAccessorFactory)
}

var _ chainaccess.AccessorFactoryConstructor = CreateEVMAccessorFactory

// loadConfig reads the mounted EVM config, accepting either the standalone format or a Chainlink
// node's own TOML.
//
// Accepting the node's file directly is what keeps the CL-to-standalone migration free of a
// conversion step: an operator mounts the config their node already runs with and starts the
// process. Settings standalone CCV has no equivalent for are dropped, and the conversion's warnings
// say which, so nothing goes missing silently.
//
// The two formats are told apart by their top-level table: `chains` is the standalone format,
// `EVM` is a node config. Anything with neither is rejected by the strict decode below.
//
// The second return is the conversion, or nil when the file was already in the standalone format.
// Whether a conversion happened cannot be inferred from the warnings, since a node config that
// converts cleanly produces none.
func loadConfig(path string) (*Config, *Conversion, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: operator-provided config path
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read config file %s: %w", path, err)
	}

	isNodeConfig, err := isChainlinkNodeConfig(data)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to inspect config file %s: %w", path, err)
	}
	if isNodeConfig {
		conversion, cerr := convertChainlinkNodeConfig(data)
		if cerr != nil {
			return nil, nil, fmt.Errorf("failed to convert Chainlink node config %s: %w", path, cerr)
		}
		return &conversion.Config, &conversion, nil
	}

	var cfg Config
	md, err := toml.Decode(string(data), &cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal config file %s: %w", path, err)
	}
	if len(md.Undecoded()) > 0 {
		return nil, nil, fmt.Errorf("unknown fields in config: %v", md.Undecoded())
	}

	return &cfg, nil, nil
}

// isChainlinkNodeConfig reports whether the file carries a Chainlink node's EVM sections rather than
// the standalone `chains` table.
//
// The test is presence of the top-level EVM key, not whether it holds any chains. A file with an
// empty or malformed EVM key is a node config the operator got wrong, and routing it to the
// converter produces an error that says so; treating it as a standalone config instead would report
// the node's own section as an unknown field. Decoding into Primitive defers the shape check, so the
// table and array forms both classify rather than failing here.
//
// A file with both top-level keys is neither — a concatenation accident the converter would
// otherwise "fix" by silently ignoring the standalone section — so it is rejected outright.
func isChainlinkNodeConfig(data []byte) (bool, error) {
	var probe map[string]toml.Primitive
	if _, err := toml.Decode(string(data), &probe); err != nil {
		return false, err
	}
	_, hasEVM := probe["EVM"]
	_, hasChains := probe["chains"]
	if hasEVM && hasChains {
		return false, fmt.Errorf(
			"config has both a top-level 'EVM' table and a top-level 'chains' table: it is neither " +
				"a Chainlink node config nor a standalone one — mount one, not a concatenation of both")
	}
	return hasEVM, nil
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
//	http_url = "https://evm-rpc.example.com"
//	ws_url = "wss://evm-rpc.example.com"
//
// Each node needs one HTTP URL reachable from this process; ws_url is optional and enables head
// subscriptions instead of HTTP polling.
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
	evmConfig, conversion, err := loadConfig(configPath)
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
	infos, err := evmConfig.toInfos()
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
	rmnRemoteInfos := chainaccess.Infos[string](generic.RMNRemoteAddresses).GetAllInfos()
	destChainConfigs := chainaccess.Infos[chainaccess.DestinationChainConfig](generic.ChainConfiguration).GetAllInfos()

	return newFactory(
		lggr,
		onRampInfos,
		rmnRemoteInfos,
		destChainConfigs,
		generic.MaxRetryDuration,
		func(
			ctx context.Context,
			chainSelector protocol.ChainSelector,
			chainLggr logger.Logger,
			ds sqlutil.DataSource,
		) (chainRuntime, error) {
			info, err := infos.GetBlockchainByChainSelector(chainSelector)
			if err != nil {
				return nil, fmt.Errorf("failed to get EVM config for chain %d: %w", chainSelector, err)
			}
			return newStandaloneChain(ctx, info, chainLggr, ds)
		},
	), nil
}
