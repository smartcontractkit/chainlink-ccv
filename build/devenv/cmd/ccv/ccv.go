package main

import (
	"context"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/docker/docker/client"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/committee_verifier"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/mock_receiver"
	"github.com/smartcontractkit/chainlink-ccv/devenv/gencfg"
	"github.com/smartcontractkit/chainlink-ccv/devenv/services"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	hmacutil "github.com/smartcontractkit/chainlink-ccv/protocol/common/hmac"
	"github.com/smartcontractkit/chainlink-testing-framework/framework"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"

	ccv "github.com/smartcontractkit/chainlink-ccv/devenv"
	"github.com/smartcontractkit/chainlink-ccv/devenv/cmd/ccv/send"
	"github.com/smartcontractkit/chainlink-ccv/devenv/evm"
)

const (
	LocalWASPLoadDashboard = "http://localhost:3000/d/WASPLoadTests/wasp-load-test?orgId=1&from=now-5m&to=now&refresh=5s"
	LocalCCVDashboard      = "http://localhost:3000/d/f8a04cef-653f-46d3-86df-87c532300672/ccv-services?orgId=1&refresh=5s"
)

var rootCmd = &cobra.Command{
	Use:   "ccv",
	Short: "A CCV local environment tool",
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		debug, err := cmd.Flags().GetBool("debug")
		if err != nil {
			return err
		}
		if debug {
			framework.L.Info().Msg("Debug mode enabled, setting CTF_CLNODE_DLV=true")
			os.Setenv("CTF_CLNODE_DLV", "true")
		}
		return nil
	},
}

var restartCmd = &cobra.Command{
	Use:     "restart",
	Aliases: []string{"r"},
	Args:    cobra.RangeArgs(0, 1),
	Short:   "Restart development environment, remove apps and apply default configuration again",
	RunE: func(cmd *cobra.Command, args []string) error {
		var configFile string
		if len(args) > 0 {
			configFile = args[0]
		} else {
			configFile = "env.toml"
		}
		framework.L.Info().Str("Config", configFile).Msg("Reconfiguring development environment")
		_ = os.Setenv("CTF_CONFIGS", configFile)
		_ = os.Setenv("TESTCONTAINERS_RYUK_DISABLED", "true")
		framework.L.Info().Msg("Tearing down the development environment")
		err := framework.RemoveTestContainers()
		if err != nil {
			return fmt.Errorf("failed to clean Docker resources: %w", err)
		}
		_, err = ccv.NewEnvironment()
		return err
	},
}

var upCmd = &cobra.Command{
	Use:     "up",
	Aliases: []string{"u"},
	Short:   "Spin up the development environment",
	Args:    cobra.RangeArgs(0, 1),
	RunE: func(cmd *cobra.Command, args []string) error {
		var configFile string
		if len(args) > 0 {
			configFile = args[0]
		} else {
			configFile = "env.toml"
		}
		framework.L.Info().Str("Config", configFile).Msg("Creating development environment")
		_ = os.Setenv("CTF_CONFIGS", configFile)
		_ = os.Setenv("TESTCONTAINERS_RYUK_DISABLED", "true")
		_, err := ccv.NewEnvironment()
		if err != nil {
			return err
		}
		return nil
	},
}

var downCmd = &cobra.Command{
	Use:     "down",
	Aliases: []string{"d"},
	Short:   "Tear down the development environment",
	RunE: func(cmd *cobra.Command, args []string) error {
		framework.L.Info().Msg("Tearing down the development environment")
		err := framework.RemoveTestContainers()
		if err != nil {
			return fmt.Errorf("failed to clean Docker resources: %w", err)
		}
		return nil
	},
}

var dumpLogsCmd = &cobra.Command{
	Use:     "dump-logs",
	Aliases: []string{"dl"},
	Short:   "Dump the logs of the development environment",
	RunE: func(cmd *cobra.Command, args []string) error {
		dirSuffix, _ := cmd.Flags().GetString("dir-suffix")
		if dirSuffix == "" {
			return fmt.Errorf("dir-suffix is required")
		}

		framework.L.Info().Msg("Dumping the logs of all docker containers in the development environment")
		_, err := framework.SaveContainerLogs(fmt.Sprintf("%s-%s", framework.DefaultCTFLogsDir, dirSuffix))
		if err != nil {
			return fmt.Errorf("failed to dump logs: %w", err)
		}
		framework.L.Info().Msg("Logs dumped successfully")
		return nil
	},
}

var bsCmd = &cobra.Command{
	Use:   "bs",
	Short: "Manage the Blockscout EVM block explorer",
	Long:  "Spin up or down the Blockscout EVM block explorer",
}

var bsUpCmd = &cobra.Command{
	Use:     "up",
	Aliases: []string{"u"},
	Short:   "Spin up Blockscout EVM block explorer",
	RunE: func(cmd *cobra.Command, args []string) error {
		url, _ := bsCmd.Flags().GetString("url")
		chainID, _ := bsCmd.Flags().GetString("chain-id")
		return framework.BlockScoutUp(url, chainID)
	},
}

var bsDownCmd = &cobra.Command{
	Use:     "down",
	Aliases: []string{"d"},
	Short:   "Spin down Blockscout EVM block explorer",
	RunE: func(cmd *cobra.Command, args []string) error {
		url, _ := bsCmd.Flags().GetString("url")
		return framework.BlockScoutDown(url)
	},
}

var bsRestartCmd = &cobra.Command{
	Use:     "restart",
	Aliases: []string{"r"},
	Short:   "Restart the Blockscout EVM block explorer",
	RunE: func(cmd *cobra.Command, args []string) error {
		url, _ := bsCmd.Flags().GetString("url")
		chainID, _ := bsCmd.Flags().GetString("chain-id")
		if err := framework.BlockScoutDown(url); err != nil {
			return err
		}
		return framework.BlockScoutUp(url, chainID)
	},
}

var obsCmd = &cobra.Command{
	Use:   "obs",
	Short: "Manage the observability stack",
	Long:  "Spin up or down the observability stack with subcommands 'up' and 'down'",
}

var obsUpCmd = &cobra.Command{
	Use:     "up",
	Aliases: []string{"u"},
	Short:   "Spin up the observability stack",
	RunE: func(cmd *cobra.Command, args []string) error {
		mode, _ := cmd.Flags().GetString("mode")
		var err error
		switch mode {
		case "full":
			err = framework.ObservabilityUpFull()
		case "loki":
			err = framework.ObservabilityUpOnlyLoki()
		default:
			err = framework.ObservabilityUp()
		}
		if err != nil {
			return fmt.Errorf("observability up failed: %w", err)
		}
		ccv.Plog.Info().Msgf("CCV Dashboard: %s", LocalCCVDashboard)
		ccv.Plog.Info().Msgf("CCV Load Test Dashboard: %s", LocalWASPLoadDashboard)
		return nil
	},
}

var deployCommitVerifierCmd = &cobra.Command{
	Use:   "deploy-commit-contracts",
	Short: "Deploy contracts for a new commit verifier across all chains with a signature quorum to the existing environment",
	Args:  cobra.RangeArgs(1, 1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		ctx = ccv.Plog.WithContext(ctx)

		in, err := ccv.LoadOutput[ccv.Cfg]("env-out.toml")
		if err != nil {
			return fmt.Errorf("failed to load environment output: %w", err)
		}
		components := strings.Split(args[0], ",")
		if len(components) < 2 {
			return fmt.Errorf("expected at least 2 arguments (threshold,signer1), got %d", len(components))
		}

		threshold, err := strconv.ParseUint(components[0], 10, 8)
		if err != nil {
			return fmt.Errorf("failed to parse threshold: %w", err)
		}
		var addresses []common.Address
		for _, addr := range components[1:] {
			if !common.IsHexAddress(addr) {
				return fmt.Errorf("invalid address: %s", addr)
			}
			addresses = append(addresses, common.HexToAddress(addr))
		}

		selectors, e, err := ccv.NewCLDFOperationsEnvironment(in.Blockchains, in.CLDF.DataStore)
		if err != nil {
			return fmt.Errorf("creating CLDF operations environment: %w", err)
		}

		signatureConfigBySelector := make(map[uint64]committee_verifier.SignatureConfig)
		for _, selector := range selectors {
			signatureConfigBySelector[selector] = committee_verifier.SignatureConfig{
				Threshold: uint8(threshold),
				Signers:   addresses,
			}
		}
		allAddrs, err := evm.DeployAndConfigureNewCommitCCV(ctx, e, in.CLDF.Addresses, signatureConfigBySelector)
		if err != nil {
			return fmt.Errorf("deploying commit verifier contracts: %w", err)
		}
		in.CLDF.Addresses = append(in.CLDF.Addresses, allAddrs...)
		return framework.Store(in)
	},
}

var deployReceiverCmd = &cobra.Command{
	Use:   "deploy-mock-receiver",
	Short: "Deploy a mock receiver contract to a given chain selector with a specific config",
	Args:  cobra.RangeArgs(1, 1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		ctx = ccv.Plog.WithContext(ctx)
		in, err := ccv.LoadOutput[ccv.Cfg]("env-out.toml")
		if err != nil {
			return fmt.Errorf("failed to load environment output: %w", err)
		}

		components := strings.Split(args[0], ",")
		if len(components) < 2 {
			return fmt.Errorf("expected at least 2 arguments (chainSelector,required1,optionalThreshold), got %d", len(components))
		}
		selector, err := strconv.ParseUint(components[0], 10, 64)
		if err != nil {
			return fmt.Errorf("failed to parse chain selector: %w", err)
		}
		var required, optional []common.Address
		var optionalThreshold uint64
		if len(components) >= 2 {
			for addr := range strings.SplitSeq(components[1], ";") {
				if !common.IsHexAddress(addr) {
					return fmt.Errorf("invalid required verifier address: %s", addr)
				}
				required = append(required, common.HexToAddress(addr))
			}
		}
		if len(components) >= 3 {
			optionalThreshold, err = strconv.ParseUint(components[2], 10, 8)
			if err != nil {
				return fmt.Errorf("failed to parse optional threshold: %w", err)
			}
		}
		if len(components) >= 4 {
			for addr := range strings.SplitSeq(components[3], ";") {
				if !common.IsHexAddress(addr) {
					return fmt.Errorf("invalid optional verifier address: %s", addr)
				}
				optional = append(optional, common.HexToAddress(addr))
			}
		}

		constructorArgs := mock_receiver.ConstructorArgs{
			RequiredVerifiers: required,
			OptionalVerifiers: optional,
			OptionalThreshold: uint8(optionalThreshold),
		}

		_, e, err := ccv.NewCLDFOperationsEnvironment(in.Blockchains, in.CLDF.DataStore)
		if err != nil {
			return fmt.Errorf("creating CLDF operations environment: %w", err)
		}

		allAddrs, err := evm.DeployMockReceiver(ctx, e, in.CLDF.Addresses, selector, constructorArgs)
		if err != nil {
			return fmt.Errorf("creating mock receiver contract: %w", err)
		}
		in.CLDF.Addresses = append(in.CLDF.Addresses, allAddrs...)
		return framework.Store(in)
	},
}

var obsDownCmd = &cobra.Command{
	Use:     "down",
	Aliases: []string{"d"},
	Short:   "Spin down the observability stack",
	RunE: func(cmd *cobra.Command, args []string) error {
		return framework.ObservabilityDown()
	},
}

var obsRestartCmd = &cobra.Command{
	Use:     "restart",
	Aliases: []string{"r"},
	Short:   "Restart the observability stack (data wipe)",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := framework.ObservabilityDown(); err != nil {
			return fmt.Errorf("observability down failed: %w", err)
		}
		mode, _ := cmd.Flags().GetString("mode")
		var err error
		switch mode {
		case "full":
			err = framework.ObservabilityUpFull()
		case "loki":
			err = framework.ObservabilityUpOnlyLoki()
		default:
			err = framework.ObservabilityUp()
		}
		if err != nil {
			return fmt.Errorf("observability up failed: %w", err)
		}
		ccv.Plog.Info().Msgf("CCV Dashboard: %s", LocalCCVDashboard)
		ccv.Plog.Info().Msgf("CCV Load Test Dashboard: %s", LocalWASPLoadDashboard)
		return nil
	},
}

var testCmd = &cobra.Command{
	Use:     "test",
	Aliases: []string{"t"},
	Short:   "Run the tests",
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) != 1 {
			return fmt.Errorf("specify the test suite: smoke or load")
		}
		var testPattern string
		switch args[0] {
		case "smoke":
			testPattern = "TestE2ESmoke"
		case "smoke-v2":
			testPattern = "TestE2ESmoke/test_extra_args_v2_messages"
		case "smoke-v3":
			testPattern = "TestE2ESmoke/test_extra_args_v3_messages"
		case "load":
			testPattern = "TestE2ELoad/clean"
		case "rpc-latency":
			testPattern = "TestE2ELoad/rpc_latency"
		case "gas-spikes":
			testPattern = "TestE2ELoad/gas"
		case "reorg":
			testPattern = "TestE2ELoad/reorg"
		case "chaos":
			testPattern = "TestE2ELoad/chaos"
		case "indexer-load":
			testPattern = "TestIndexerLoad"
		case "multi_chain_load":
			testPattern = "TestE2ELoad/multi_chain_load"
		default:
			return fmt.Errorf("test suite %s is unknown, choose between smoke or load", args[0])
		}
		originalDir, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("failed to get current directory: %w", err)
		}
		defer os.Chdir(originalDir)

		if isServiceLoadTest(testPattern) {
			if err := os.Chdir("tests/services/load"); err != nil {
				return fmt.Errorf("failed to change to tests/services/load directory: %w", err)
			}
		} else {
			if err := os.Chdir("tests/e2e"); err != nil {
				return fmt.Errorf("failed to change to tests/e2e directory: %w", err)
			}
		}

		testCmd := exec.Command("go", "test", "-v", "-run", testPattern, "-timeout=0")
		testCmd.Stdout = os.Stdout
		testCmd.Stderr = os.Stderr
		testCmd.Stdin = os.Stdin

		if err := testCmd.Run(); err != nil {
			if exitError, ok := err.(*exec.ExitError); ok {
				if status, ok := exitError.Sys().(syscall.WaitStatus); ok {
					os.Exit(status.ExitStatus())
				}
				os.Exit(1)
			}
			return fmt.Errorf("failed to run test command: %w", err)
		}
		return nil
	},
}

var indexerDBShellCmd = &cobra.Command{
	Use:     "db-shell",
	Aliases: []string{"db"},
	Short:   "Inspect Service Database",
	RunE: func(cmd *cobra.Command, args []string) error {
		psqlPath, err := exec.LookPath("psql")
		if err != nil {
			return fmt.Errorf("psql not found in PATH, are you inside 'nix develop' shell?: %w", err)
		}
		if len(args) != 1 {
			return fmt.Errorf("db cannot be empty, choose between: indexer, aggregator, verifier or executor")
		}
		var url string
		switch args[0] {
		case "indexer":
			url = services.DefaultIndexerDBConnectionString
		case "verifier":
			url = services.DefaultVerifierDBConnectionString
		default:
			return fmt.Errorf("service %s is unknown, choose between indexer, aggregator, verifier, executor", args[0])
		}
		psqlArgs := []string{
			"psql",
			url,
		}
		if len(args) > 0 {
			psqlArgs = append(psqlArgs, args...)
		}
		env := syscall.Environ()
		return syscall.Exec(psqlPath, psqlArgs, env)
	},
}

var printAddressesCmd = &cobra.Command{
	Use:   "addresses",
	Short: "Pretty-print all on-chain contract addresses data",
	RunE: func(cmd *cobra.Command, args []string) error {
		in, err := ccv.LoadOutput[ccv.Cfg]("env-out.toml")
		if err != nil {
			return fmt.Errorf("failed to load environment output: %w", err)
		}
		return ccv.PrintCLDFAddresses(in)
	},
}

var generateConfigsCmd = &cobra.Command{
	Use:   "generate-configs",
	Short: "Generate the verifier and executor jobspecs (CL deployment only), and the aggregator and indexer TOML configuration files for the environment. Requires gh tool to authenticate to CLD repo.",
	RunE: func(cmd *cobra.Command, args []string) error {
		cldDomain, err := cmd.Flags().GetString("cld-domain")
		if err != nil {
			return err
		}
		verifierPubKeys, err := cmd.Flags().GetStringSlice("verifier-pubkeys")
		if err != nil {
			return err
		}
		numExecutors, err := cmd.Flags().GetInt("num-executors")
		if err != nil {
			return err
		}
		createPR, err := cmd.Flags().GetBool("create-pr")
		if err != nil {
			return err
		}

		_, err = gencfg.GenerateConfigs(cldDomain, verifierPubKeys, numExecutors, createPR)
		if err != nil {
			return fmt.Errorf("failed to generate configs: %w", err)
		}
		return nil
	},
}

var generateHMACSecretCmd = &cobra.Command{
	Use:   "generate-hmac-secret",
	Short: "Generate cryptographically secure HMAC credentials (API key and secret) for aggregator authentication",
	RunE: func(cmd *cobra.Command, args []string) error {
		count, err := cmd.Flags().GetInt("count")
		if err != nil {
			return err
		}

		for i := range count {
			creds, err := hmacutil.GenerateCredentials()
			if err != nil {
				return fmt.Errorf("failed to generate HMAC credentials: %w", err)
			}
			fmt.Printf("api_key = %q\n", creds.APIKey)
			fmt.Printf("secret  = %q\n", creds.Secret)
			if i < count-1 {
				fmt.Println()
			}
		}
		return nil
	},
}

var fundAddressesCmd = &cobra.Command{
	Use:   "fund-addresses --env <env>--chain-id <chain-id> --addresses <address1,address2,...> --amount <amount>",
	Short: "Fund addresses with ETH",
	RunE: func(cmd *cobra.Command, args []string) error {
		chainSelector, err := cmd.Flags().GetUint64("chain-selector")
		if err != nil {
			return fmt.Errorf("failed to parse chain-selector: %w", err)
		}
		addresses, err := cmd.Flags().GetStringSlice("addresses")
		if err != nil {
			return fmt.Errorf("failed to parse addresses: %w", err)
		}
		amount, err := cmd.Flags().GetString("amount")
		if err != nil {
			return fmt.Errorf("failed to parse amount flag: %w", err)
		}
		env, err := cmd.Flags().GetString("env")
		if err != nil {
			return fmt.Errorf("failed to parse env: %w", err)
		}

		in, err := ccv.LoadOutput[ccv.Cfg](fmt.Sprintf("env-%s.toml", env))
		if err != nil {
			return fmt.Errorf("failed to load environment output: %w", err)
		}

		amountBig, ok := new(big.Int).SetString(amount, 10)
		if !ok {
			return fmt.Errorf("failed to parse amount into big int: %w", err)
		}

		unknownAddresses := make([]protocol.UnknownAddress, 0, len(addresses))
		for _, addr := range addresses {
			unknownAddress, err := protocol.NewUnknownAddressFromHex(addr)
			if err != nil {
				return fmt.Errorf("failed to parse address: %w", err)
			}
			unknownAddresses = append(unknownAddresses, unknownAddress)
		}

		chainID, err := chainsel.ChainIdFromSelector(chainSelector)
		if err != nil {
			return fmt.Errorf("failed to get chain details: %w", err)
		}
		chainIDStr := strconv.FormatUint(chainID, 10)

		var input *blockchain.Input
		for _, bc := range in.Blockchains {
			if bc.ChainID == chainIDStr {
				input = bc
				break
			}
		}

		if input == nil {
			return fmt.Errorf("blockchain with chain ID %s not found, please update the env file or use a different chain-selector", chainIDStr)
		}

		impl, err := ccv.NewProductConfigurationFromNetwork(input.Type)
		if err != nil {
			return fmt.Errorf("failed to create product configuration: %w", err)
		}

		err = impl.FundAddresses(cmd.Context(), input, unknownAddresses, amountBig)
		if err != nil {
			return fmt.Errorf("failed to fund addresses: %w", err)
		}

		return nil
	},
}

var monitorContractsCmd = &cobra.Command{
	Use:   "upload-on-chain-metrics <source> <dest>",
	Short: "Reads on-chain EVM contract events and temporary exposes them as Prometheus metrics endpoint to be scraped",
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) != 2 {
			return fmt.Errorf("expected 2 arguments (source,dest), got %d", len(args))
		}
		source, err := strconv.ParseUint(args[0], 10, 64)
		if err != nil {
			return fmt.Errorf("failed to parse source: %w", err)
		}
		dest, err := strconv.ParseUint(args[1], 10, 64)
		if err != nil {
			return fmt.Errorf("failed to parse dest: %w", err)
		}

		ctx := cmd.Context()
		ctx = ccv.Plog.WithContext(ctx)
		l := zerolog.Ctx(ctx)
		impl, err := ccv.NewImpl(l, "env-out.toml", source)
		if err != nil {
			return fmt.Errorf("failed to create product configuration: %w", err)
		}

		_, reg, err := impl.ExposeMetrics(cmd.Context(), source, dest)
		if err != nil {
			return fmt.Errorf("failed to expose metrics: %w", err)
		}
		if err := ccv.ExposePrometheusMetricsFor(reg, 10*time.Second); err != nil {
			return err
		}
		ccv.Plog.Info().Str("Dashboard", LocalCCVDashboard).Msg("Metrics upload finished")
		return nil
	},
}

var txInfoCmd = &cobra.Command{
	Use:   "tx-receipt <tx hash>",
	Short: "Get transaction receipt information",
	Args:  cobra.RangeArgs(1, 1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) != 1 {
			return fmt.Errorf("expected 1 argument (tx hash), got %d", len(args))
		}
		txHash := common.HexToHash(args[0])
		ctx := ccv.Plog.WithContext(cmd.Context())
		in, err := ccv.LoadOutput[ccv.Cfg]("env-out.toml")
		if err != nil {
			return fmt.Errorf("failed to load environment output: %w", err)
		}

		var found bool
		for _, bc := range in.Blockchains {
			if found {
				break
			}
			client, err := ethclient.Dial(bc.Out.Nodes[0].ExternalWSUrl)
			if err != nil {
				return fmt.Errorf("failed to dial client: %w", err)
			}
			receipt, err := client.TransactionReceipt(ctx, txHash)
			if err != nil {
				continue
			}
			tx, _, err := client.TransactionByHash(ctx, txHash)
			if err != nil {
				continue
			}
			// check gas specified in the transaction and gas used in the receipt
			ccv.Plog.Info().Msgf("gas specified in tx: %d, gas used in receipt: %d", tx.Gas(), receipt.GasUsed)
			found = true
		}
		if !found {
			return fmt.Errorf("transaction not found in any of the enabled chains")
		}
		return nil
	},
}

func init() {
	rootCmd.PersistentFlags().BoolP("debug", "d", false, "Enable running services with dlv to allow remote debugging.")

	// Fund addresses
	rootCmd.AddCommand(fundAddressesCmd)
	fundAddressesCmd.Flags().String("env", "out", "Select environment file to use (e.g., 'staging' for env-staging.toml, defaults to env-out.toml)")
	fundAddressesCmd.Flags().Uint64("chain-selector", 0, "Chain selector to fund addresses for")
	fundAddressesCmd.Flags().StringSlice("addresses", []string{}, "Addresses to fund (comma separated)")
	fundAddressesCmd.Flags().String("amount", "", "Amount to fund (in ETH, not in wei)")

	_ = fundAddressesCmd.MarkFlagRequired("env")
	_ = fundAddressesCmd.MarkFlagRequired("chain-selector")
	_ = fundAddressesCmd.MarkFlagRequired("addresses")
	_ = fundAddressesCmd.MarkFlagRequired("amount")

	// Blockscout, on-chain debug
	bsCmd.PersistentFlags().StringP("url", "u", "http://host.docker.internal:8555", "EVM RPC node URL (default to dst chain on 8555")
	bsCmd.PersistentFlags().StringP("chain-id", "c", "2337", "RPC's Chain ID")
	bsCmd.AddCommand(bsUpCmd)
	bsCmd.AddCommand(bsDownCmd)
	bsCmd.AddCommand(bsRestartCmd)
	rootCmd.AddCommand(bsCmd)

	// observability
	obsCmd.PersistentFlags().StringP("mode", "m", "full", "Run some configuration of observability stack")
	obsCmd.AddCommand(obsRestartCmd)
	obsCmd.AddCommand(obsUpCmd)
	obsCmd.AddCommand(obsDownCmd)
	rootCmd.AddCommand(obsCmd)

	// main env commands
	rootCmd.AddCommand(upCmd)
	rootCmd.AddCommand(restartCmd)
	rootCmd.AddCommand(downCmd)

	// utility
	rootCmd.AddCommand(testCmd)
	rootCmd.AddCommand(indexerDBShellCmd)
	rootCmd.AddCommand(printAddressesCmd)

	rootCmd.AddCommand(send.Command())

	// on-chain monitoring
	rootCmd.AddCommand(monitorContractsCmd)
	rootCmd.AddCommand(txInfoCmd)

	// contract management
	rootCmd.AddCommand(deployCommitVerifierCmd)
	rootCmd.AddCommand(deployReceiverCmd)

	// config generation
	rootCmd.AddCommand(generateConfigsCmd)
	generateConfigsCmd.Flags().String("cld-domain", "", "CLD Domain to target for config generation. Current options: staging_testnet")
	generateConfigsCmd.Flags().StringSlice("verifier-pubkeys", []string{}, "List of verifier public keys (hex encoded) to include in the generated configs")
	generateConfigsCmd.Flags().Int("num-executors", 1, "Number of executor jobspecs to generate")
	generateConfigsCmd.Flags().Bool("create-pr", false, "Create a pull request with the generated configs")

	_ = generateConfigsCmd.MarkFlagRequired("cld-domain")
	_ = generateConfigsCmd.MarkFlagRequired("verifier-pubkeys")
	_ = generateConfigsCmd.MarkFlagRequired("num-executors")

	// HMAC secret generation
	rootCmd.AddCommand(generateHMACSecretCmd)
	generateHMACSecretCmd.Flags().Int("count", 1, "Number of HMAC credential pairs to generate")

	// dump logs
	rootCmd.AddCommand(dumpLogsCmd)
	dumpLogsCmd.Flags().String("dir-suffix", "", "Suffix to add to the logs directory")
	_ = dumpLogsCmd.MarkFlagRequired("dir-suffix")
}

func checkDockerIsRunning() {
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		fmt.Println("Can't create Docker client, please check if Docker daemon is running!")
		os.Exit(1)
	}
	defer cli.Close()
	_, err = cli.Ping(context.Background())
	if err != nil {
		fmt.Println("Docker is not running, please start Docker daemon first!")
		os.Exit(1)
	}
}

func main() {
	checkDockerIsRunning()
	if len(os.Args) == 2 && (os.Args[1] == "shell" || os.Args[1] == "sh") {
		_ = os.Setenv("CTF_CONFIGS", "env.toml") // Set default config for shell

		StartShell()
		return
	}
	if err := rootCmd.Execute(); err != nil {
		ccv.Plog.Err(err).Send()
		os.Exit(1)
	}
}

func isServiceLoadTest(testPattern string) bool {
	return testPattern == "TestIndexerLoad"
}
