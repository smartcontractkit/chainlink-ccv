package migrate

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/urfave/cli"

	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evm"
)

// inspectConfigCommand is `ccv migrate inspect-config`: the pre-cutover settings diff. It runs
// the same config load and conversion the standalone process runs at startup and prints what each
// chain will effectively run, so deviations from the Chainlink node's behavior are reviewed and
// accepted before the cutover rather than discovered after it. Like every `ccv migrate`
// subcommand it needs no database, no secrets, and no network.
func inspectConfigCommand() cli.Command {
	return cli.Command{
		Name: "inspect-config",
		Usage: "Print the effective per-chain EVM settings standalone will run, for the " +
			"pre-cutover settings diff",
		Description: "Accepts the Chainlink node's TOML config or a standalone-format EVM config and prints " +
			"the conversion warnings (what the node config sets that standalone drops) followed by each " +
			"chain's effective settings: finality, TXM block time (flagged when the 2s fallback fired), " +
			"head-tracker persistence, and the RPC node set. RPC URLs are never printed — they can carry " +
			"API keys. See docs/migration/evm-cl-to-standalone.md.",
		Flags: []cli.Flag{
			cli.StringFlag{Name: "config", Usage: "path to the EVM config: the node's TOML or a standalone-format file", Required: true},
			cli.StringFlag{Name: "chain-selector", Usage: "optional: print only this chain"},
		},
		Action: func(c *cli.Context) error {
			report, err := buildConfigReport(c.String("config"), c.String("chain-selector"))
			if err != nil {
				return err
			}
			data, err := json.MarshalIndent(report, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to render the config report: %w", err)
			}
			fmt.Println(string(data)) //nolint:forbidigo // CLI user output
			return nil
		},
	}
}

// configReport is what `ccv migrate inspect-config` prints.
type configReport struct {
	ConvertedFromNodeConfig bool                          `json:"converted_from_node_config"`
	Warnings                []string                      `json:"warnings,omitempty"`
	Chains                  map[string]evm.EffectiveChain `json:"chains"`
}

func buildConfigReport(configPath, chainSelector string) (*configReport, error) {
	cfg, conversion, err := evm.LoadConfigFile(configPath)
	if err != nil {
		return nil, err
	}
	chains, err := evm.EffectiveChainConfigs(*cfg)
	if err != nil {
		return nil, err
	}

	report := &configReport{ConvertedFromNodeConfig: conversion != nil, Chains: chains}
	if conversion != nil {
		report.Warnings = conversion.Warnings
	}

	if chainSelector != "" {
		if _, err := strconv.ParseUint(chainSelector, 10, 64); err != nil {
			return nil, fmt.Errorf("--chain-selector must be a decimal chain selector: %w", err)
		}
		chain, ok := chains[chainSelector]
		if !ok {
			return nil, fmt.Errorf("chain selector %s is not in %s", chainSelector, configPath)
		}
		report.Chains = map[string]evm.EffectiveChain{chainSelector: chain}
	}
	return report, nil
}
