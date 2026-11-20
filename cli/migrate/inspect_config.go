package migrate

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/BurntSushi/toml"
	"github.com/urfave/cli"

	chainsel "github.com/smartcontractkit/chain-selectors"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap"
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
			"the conversion warnings (where standalone runs differently from the node config), the chains the " +
			"conversion skipped whole (failed_chains, with reasons), the top-level sections the " +
			"conversion ignores, the chain defaults the settings resolve against (chainlink-evm's with CCIP's " +
			"overrides, as on a ccip node image), and each chain's effective settings: finality, TXM block time (with " +
			"the default source — operator, curated chain default, or generic 2s fallback), " +
			"head-tracker persistence, and the RPC node set. " +
			"RPC URLs are never printed — they can carry API keys. See docs/verifier/evm-standalone.md#evm-config-conversion.",
		Flags: []cli.Flag{
			cli.StringFlag{Name: "config", Usage: "path to the EVM config: the node's TOML or a standalone-format file", Required: true},
			cli.StringFlag{Name: "bootstrap-config", Usage: "optional: reconcile this bootstrap file's [[chains]] with the EVM inventory and fail on any mismatch"},
			cli.StringFlag{Name: "chain-selector", Usage: "optional: print only this chain"},
		},
		Action: func(c *cli.Context) error {
			report, err := buildConfigReportWithBootstrap(c.String("config"), c.String("chain-selector"), c.String("bootstrap-config"))
			if err != nil {
				return err
			}
			data, err := json.MarshalIndent(report, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to render the config report: %w", err)
			}
			fmt.Println(string(data)) //nolint:forbidigo // CLI user output
			if report.ChainInventory != nil {
				return report.ChainInventory.Err()
			}
			return nil
		},
	}
}

// configReport is what `ccv migrate inspect-config` prints.
type configReport struct {
	ConvertedFromNodeConfig bool `json:"converted_from_node_config"`
	// ChainDefaults names the chain defaults every chain's settings resolve against. The problems are
	// default files or keys that did not load and were skipped; a release has none.
	ChainDefaults         string   `json:"chain_defaults"`
	ChainDefaultsProblems []string `json:"chain_defaults_problems,omitempty"`
	Warnings              []string `json:"warnings,omitempty"`
	// IgnoredSections names the node config's top-level sections the conversion does not read.
	// They are file-level, so --chain-selector narrows the chains and warnings but not this list.
	IgnoredSections []string `json:"ignored_top_level_sections,omitempty"`
	// FailedChains are the chains the conversion skipped whole, with reasons — the chains that
	// will not be served at all. They narrow with --chain-selector like the warnings.
	FailedChains             []evmconfig.ChainFailure             `json:"failed_chains,omitempty"`
	Chains                   map[string]evmconfig.EffectiveChain  `json:"chains"`
	ConversionReviewRequired bool                                 `json:"conversion_review_required"`
	BroadcastEndpoints       []evmconfig.BroadcastEndpointSummary `json:"broadcast_endpoints,omitempty"`
	ChainInventory           *evmconfig.ChainInventoryReport      `json:"chain_inventory,omitempty"`
}

func buildConfigReport(configPath, chainSelector string) (*configReport, error) {
	return buildConfigReportWithBootstrap(configPath, chainSelector, "")
}

func buildConfigReportWithBootstrap(configPath, chainSelector, bootstrapPath string) (*configReport, error) {
	cfg, conversion, err := evmconfig.LoadConfigFile(configPath)
	if err != nil {
		return nil, err
	}
	chains, err := evmconfig.EffectiveChainConfigs(*cfg)
	if err != nil {
		return nil, err
	}

	report := &configReport{
		ConvertedFromNodeConfig: conversion != nil,
		ChainDefaults:           evmconfig.ChainDefaultsSource(),
		ChainDefaultsProblems:   evmconfig.ChainDefaultsProblems(),
		Chains:                  chains,
	}
	if conversion != nil {
		report.Warnings = conversion.Warnings
		report.IgnoredSections = conversion.IgnoredSections
		report.FailedChains = conversion.FailedChains
		report.BroadcastEndpoints = conversion.BroadcastEndpoints
		report.ConversionReviewRequired = len(conversion.Warnings) > 0 || len(conversion.FailedChains) > 0
	}
	if bootstrapPath != "" {
		var bootstrapConfig bootstrap.NonSecretConfig
		if _, err := toml.DecodeFile(bootstrapPath, &bootstrapConfig); err != nil {
			return nil, fmt.Errorf("failed to read bootstrap config %s: %w", bootstrapPath, err)
		}
		declarations := make([]evmconfig.ChainDeclaration, 0, len(bootstrapConfig.Chains))
		for _, chain := range bootstrapConfig.Chains {
			declarations = append(declarations, evmconfig.ChainDeclaration{Type: chain.Type, ID: chain.ID})
		}
		inventory, err := evmconfig.ReconcileChainInventory(cfg, conversion, declarations)
		if err != nil {
			return nil, err
		}
		report.ChainInventory = inventory
	}

	if chainSelector != "" {
		if err := narrowReportToChain(report, conversion, chains, chainSelector, configPath); err != nil {
			return nil, err
		}
	}
	return report, nil
}

// narrowReportToChain restricts the report to one chain selector, in place.
//
// Warnings and failures narrow with the chains: a multi-chain node config would otherwise print
// every other chain's dropped settings next to this one chain's settings, which reads as this
// chain's deviations. IgnoredSections does not narrow; it is file-level.
func narrowReportToChain(
	report *configReport,
	conversion *evmconfig.Conversion,
	chains map[string]evmconfig.EffectiveChain,
	chainSelector, configPath string,
) error {
	selector, err := strconv.ParseUint(chainSelector, 10, 64)
	if err != nil {
		return fmt.Errorf("--chain-selector must be a decimal chain selector: %w", err)
	}
	chain, ok := chains[chainSelector]
	if !ok {
		return narrowToSkippedChain(report, conversion, selector, chainSelector, configPath)
	}

	report.Chains = map[string]evmconfig.EffectiveChain{chainSelector: chain}
	if conversion == nil {
		return nil
	}
	report.Warnings = conversion.WarningsByChainID[chain.ChainID]
	report.FailedChains = nil
	report.BroadcastEndpoints = nil
	for _, summary := range conversion.BroadcastEndpoints {
		if summary.ChainID == chain.ChainID {
			report.BroadcastEndpoints = []evmconfig.BroadcastEndpointSummary{summary}
		}
	}
	for _, failure := range conversion.FailedChains {
		if failure.ChainID == chain.ChainID {
			report.FailedChains = []evmconfig.ChainFailure{failure}
		}
	}
	return nil
}

// narrowToSkippedChain handles a selector the conversion skipped whole. Such a chain is absent
// from the projection, yet it is the one an operator narrowing to it most needs to see, so the
// report carries its failure and warnings rather than a bare "not in config" error.
func narrowToSkippedChain(
	report *configReport,
	conversion *evmconfig.Conversion,
	selector uint64,
	chainSelector, configPath string,
) error {
	notFound := fmt.Errorf("chain selector %s is not in %s", chainSelector, configPath)
	if conversion == nil {
		return notFound
	}
	chainID, err := chainsel.GetChainIDFromSelector(selector)
	if err != nil {
		return notFound
	}
	for _, failure := range conversion.FailedChains {
		if failure.ChainID != chainID {
			continue
		}
		report.Chains = make(map[string]evmconfig.EffectiveChain)
		report.Warnings = conversion.WarningsByChainID[chainID]
		report.FailedChains = []evmconfig.ChainFailure{failure}
		report.BroadcastEndpoints = nil
		return nil
	}
	return notFound
}
