package evmconfig

import (
	"fmt"
	"os"
	"strconv"

	"github.com/BurntSushi/toml"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
)

// LoadConfigFile reads the mounted EVM config, accepting either the standalone format or a Chainlink
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
//
// Both the runtime accessor and the migration tooling (`ccv migrate inspect-config`) load through
// here, so the pre-cutover report cannot drift from what the standalone process will run.
func LoadConfigFile(path string) (*Config, *Conversion, error) {
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
		return nil, nil, fmt.Errorf("unknown fields in config file %s: %v", path, md.Undecoded())
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

// ResolveConfigPath returns the mounted EVM config path: EVM_CONFIG_PATH when set, otherwise the
// default mount point.
func ResolveConfigPath() string {
	if configPath := os.Getenv(EVMConfigPathEnv); configPath != "" {
		return configPath
	}
	return DefaultEVMConfigPath
}

// ToInfos reconstructs the accessor's Infos[Info] from the operator-local config, deriving each
// chain's ID and family from its selector. Only operator-owned connection and
// runtime settings live in the mounted file; enumeration metadata is recovered here.
func (c Config) ToInfos() (chainaccess.Infos[Info], error) {
	infos := make(chainaccess.Infos[Info], len(c.Chains))
	for selector, chain := range c.Chains {
		sel, err := strconv.ParseUint(selector, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid chain selector %q: %w", selector, err)
		}
		// The map key is carried through as the Infos key, and chainaccess looks those up by the
		// selector's canonical %d form. A key that parses but is spelled differently —
		// "0<selector>" is the only such form ParseUint accepts — would load, convert, and start
		// without complaint, then miss every lookup once a message arrives for the chain. Two keys
		// for one selector would also silently collapse to whichever the map ranged over last.
		if canonical := strconv.FormatUint(sel, 10); canonical != selector {
			return nil, fmt.Errorf(
				"chain selector %q must be written in canonical decimal form (%s)", selector, canonical)
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
