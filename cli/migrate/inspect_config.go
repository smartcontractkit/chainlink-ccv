package migrate

import (
	"encoding/json"
	"fmt"
	"strconv"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/urfave/cli"

	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/accessors/evmconfig"
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
			"the conversion warnings (what the node config sets that standalone drops), the chains the " +
			"conversion skipped whole (failed_chains, with reasons), the top-level sections the " +
			"conversion ignores, and each chain's effective settings: finality, TXM block time (with " +
			"the default source — operator, curated chain default, or generic 2s fallback), " +
			"head-tracker persistence, and the RPC node set. " +
			"RPC URLs are never printed — they can carry API keys. See docs/migration/evm-cl-to-standalone.md.",
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
	ConvertedFromNodeConfig bool     `json:"converted_from_node_config"`
	Warnings                []string `json:"warnings,omitempty"`
	// IgnoredSections names the node config's top-level sections the conversion does not read.
	// They are file-level, so --chain-selector narrows the chains and warnings but not this list.
	IgnoredSections []string `json:"ignored_top_level_sections,omitempty"`
	// FailedChains are the chains the conversion skipped whole, with reasons — the chains that
	// will not be served at all. They narrow with --chain-selector like the warnings.
	FailedChains []evmconfig.ChainFailure            `json:"failed_chains,omitempty"`
	Chains       map[string]evmconfig.EffectiveChain `json:"chains"`
}

func buildConfigReport(configPath, chainSelector string) (*configReport, error) {
	cfg, conversion, err := evmconfig.LoadConfigFile(configPath)
	if err != nil {
		return nil, err
	}
	chains, err := evmconfig.EffectiveChainConfigs(*cfg)
	if err != nil {
		return nil, err
	}

	report := &configReport{ConvertedFromNodeConfig: conversion != nil, Chains: chains}
	if conversion != nil {
		report.Warnings = conversion.Warnings
		report.IgnoredSections = conversion.IgnoredSections
		report.FailedChains = conversion.FailedChains
	}

	if chainSelector != "" {
		selector, err := strconv.ParseUint(chainSelector, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("--chain-selector must be a decimal chain selector: %w", err)
		}
		chain, ok := chains[chainSelector]
		if !ok {
			// A chain the conversion skipped is not in the projection, but it is the chain an
			// operator narrowing to it most needs to see: report the failure instead of a bare
			// "not in config" error.
			if conversion != nil {
				if chainID, idErr := chainsel.GetChainIDFromSelector(selector); idErr == nil {
					for _, failure := range conversion.FailedChains {
						if failure.ChainID == chainID {
							report.Chains = map[string]evmconfig.EffectiveChain{}
							report.Warnings = conversion.WarningsByChainID[chainID]
							report.FailedChains = []evmconfig.ChainFailure{failure}
							return report, nil
						}
					}
				}
			}
			return nil, fmt.Errorf("chain selector %s is not in %s", chainSelector, configPath)
		}
		report.Chains = map[string]evmconfig.EffectiveChain{chainSelector: chain}
		// The warnings and failures narrow with the chains: a multi-chain node config would
		// otherwise print every other chain's dropped settings next to this one chain's settings,
		// which reads as this chain's deviations. IgnoredSections does not narrow: it is
		// file-level.
		if conversion != nil {
			report.Warnings = conversion.WarningsByChainID[chain.ChainID]
			report.FailedChains = nil
			for _, failure := range conversion.FailedChains {
				if failure.ChainID == chain.ChainID {
					report.FailedChains = []evmconfig.ChainFailure{failure}
				}
			}
		}
	}
	return report, nil
}
