package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/docker/docker/client"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"

	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/committee_verifier"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/mock_receiver"
	offrampoperations "github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/offramp"
	onrampoperations "github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/onramp"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_6_0/operations/rmn_remote"
	"github.com/smartcontractkit/chainlink-ccv/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/devenv/services"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-testing-framework/framework"

	executor_operations "github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/executor"
	ccv "github.com/smartcontractkit/chainlink-ccv/devenv"
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

		allAddrs, err := evm.DeployAndConfigureNewCommitCCV(ctx, e, in.CLDF.Addresses, selectors, committee_verifier.SetSignatureConfigArgs{
			Threshold: uint8(threshold),
			Signers:   addresses,
		})
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
			for _, addr := range strings.Split(components[1], ";") {
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
			for _, addr := range strings.Split(components[3], ";") {
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

		testCmd := exec.Command("go", "test", "-v", "-run", testPattern)
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
	Short: "Generate the verifier and executor jobspecs (CL deployment only), and the aggregator and indexer TOML configuration files for the environment",
	RunE: func(cmd *cobra.Command, args []string) error {
		// TODO: maybe move the actual generation logic into a function
		// so that it can potentially be re-used (maybe from CLD?)
		addressRefsPath, err := cmd.Flags().GetString("address-refs-json")
		if err != nil {
			return err
		}
		verifierPubKeys, err := cmd.Flags().GetStringSlice("verifier-pubkeys")
		if err != nil {
			return err
		}
		aggregatorAddr, err := cmd.Flags().GetString("aggregator-addr")
		if err != nil {
			return err
		}
		aggregatorPort, err := cmd.Flags().GetInt("aggregator-port")
		if err != nil {
			return err
		}
		numExecutors, err := cmd.Flags().GetInt("num-executors")
		if err != nil {
			return err
		}
		if numExecutors == -1 {
			numExecutors = len(verifierPubKeys)
		}
		if numExecutors > len(verifierPubKeys) {
			return fmt.Errorf("number of executors cannot be greater than number of verifiers")
		}
		indexerAddress, err := cmd.Flags().GetString("indexer-addr")
		if err != nil {
			return err
		}

		ocrThreshold := func(n int) uint8 {
			f := (n - 1) / 3    // n = 3f + 1 => f = (n - 1) / 3
			return uint8(f + 1) // OCR threshold is f + 1
		}

		ccv.Plog.Info().
			Str("address-refs-json", addressRefsPath).
			Strs("verifier-pubkeys", verifierPubKeys).
			Str("aggregator-addr", aggregatorAddr).
			Int("aggregator-port", aggregatorPort).
			Int("num-executors", numExecutors).
			Msg("Generating configs")

		// Load the address refs from the JSON file
		f, err := os.Open(addressRefsPath)
		if err != nil {
			return fmt.Errorf("failed to open address refs JSON file: %w", err)
		}
		defer f.Close()

		decoder := json.NewDecoder(f)
		var addressRefs []datastore.AddressRef
		if err := decoder.Decode(&addressRefs); err != nil {
			return fmt.Errorf("failed to decode address refs JSON: %w", err)
		}

		const (
			verifierIDPrefix = "cll-verifier-"
			executorIDPrefix = "cll-executor-"
			committeeName    = "cll"
		)
		var (
			onRampAddresses = make(map[string]string)
			// TODO: both maps below store the same data, just the key type is different
			committeeVerifierAddresses              = make(map[string]string)
			committeeVerifierResolverProxyAddresses = make(map[uint64]string)
			defaultExecutorOnRampAddresses          = make(map[string]string)
			rmnRemoteAddresses                      = make(map[string]string)
			offRampAddresses                        = make(map[uint64]string)
			thresholdPerSource                      = make(map[uint64]uint8)
		)
		for _, ref := range addressRefs {
			chainSelectorStr := strconv.FormatUint(ref.ChainSelector, 10)
			switch ref.Type {
			case datastore.ContractType(onrampoperations.ContractType):
				onRampAddresses[chainSelectorStr] = ref.Address
			case datastore.ContractType(committee_verifier.ResolverProxyType):
				committeeVerifierAddresses[chainSelectorStr] = ref.Address
				committeeVerifierResolverProxyAddresses[ref.ChainSelector] = ref.Address
			case datastore.ContractType(executor_operations.ContractType):
				defaultExecutorOnRampAddresses[chainSelectorStr] = ref.Address
			case datastore.ContractType(rmn_remote.ContractType):
				rmnRemoteAddresses[chainSelectorStr] = ref.Address
			case datastore.ContractType(offrampoperations.ContractType):
				offRampAddresses[ref.ChainSelector] = ref.Address
			}
			thresholdPerSource[ref.ChainSelector] = ocrThreshold(len(verifierPubKeys))
		}

		// create temporary directory to store the generated configs
		tempDir, err := os.MkdirTemp("", "ccv-configs")
		if err != nil {
			return fmt.Errorf("failed to create temporary directory: %w", err)
		}
		ccv.Plog.Info().Str("temp-dir", tempDir).Msg("Created temporary directory for configs")

		// create the VerifierInput for each verifier
		verifierInputs := make([]*services.VerifierInput, 0, len(verifierPubKeys))
		for i, pubKey := range verifierPubKeys {
			verifierInputs = append(verifierInputs, &services.VerifierInput{
				ContainerName:                  fmt.Sprintf("%s%d", verifierIDPrefix, i),
				AggregatorAddress:              fmt.Sprintf("%s:%d", aggregatorAddr, aggregatorPort),
				SigningKeyPublic:               pubKey,
				CommitteeVerifierAddresses:     committeeVerifierAddresses,
				OnRampAddresses:                onRampAddresses,
				DefaultExecutorOnRampAddresses: defaultExecutorOnRampAddresses,
				RMNRemoteAddresses:             rmnRemoteAddresses,
				CommitteeName:                  committeeName,
			})
		}
		// generate and print the job spec to stdout for now
		for _, verifierInput := range verifierInputs {
			verifierJobSpec, err := verifierInput.GenerateJobSpec()
			if err != nil {
				return fmt.Errorf("failed to generate verifier job spec: %w", err)
			}
			ccv.Plog.Info().Msg("Generated verifier job spec, writing to temporary directory as a separate file")
			// write to a file in the temporary directory generated above
			filePath := filepath.Join(tempDir, fmt.Sprintf("verifier-%s-job-spec.toml", verifierInput.ContainerName))
			if err := os.WriteFile(filePath, []byte(verifierJobSpec), 0o644); err != nil {
				return fmt.Errorf("failed to write verifier job spec to file: %w", err)
			}
			ccv.Plog.Info().Str("file-path", filePath).Msg("Wrote verifier job spec to file")
		}

		// create the ExecutorInput for each executor
		executorInputs := make([]services.ExecutorInput, 0, numExecutors)
		// create executor pool first
		executorPool := make([]string, 0, numExecutors)
		for i := 0; i < numExecutors; i++ {
			executorPool = append(executorPool, fmt.Sprintf("%s%d", executorIDPrefix, i))
		}
		for i := 0; i < numExecutors; i++ {
			executorInputs = append(executorInputs, services.ExecutorInput{
				ExecutorID:       fmt.Sprintf("%s%d", executorIDPrefix, i),
				ExecutorPool:     executorPool,
				OfframpAddresses: offRampAddresses,
				IndexerAddress:   indexerAddress,
			})
		}
		// generate and print the config to stdout for now
		for _, executorInput := range executorInputs {
			executorJobSpec, err := executorInput.GenerateJobSpec()
			if err != nil {
				return fmt.Errorf("failed to generate executor job spec: %w", err)
			}
			ccv.Plog.Info().Msg("Generated executor job spec, writing to temporary directory as a separate file")
			// write to a file in the temporary directory generated above
			filePath := filepath.Join(tempDir, fmt.Sprintf("executor-%s-job-spec.toml", executorInput.ExecutorID))
			if err := os.WriteFile(filePath, []byte(executorJobSpec), 0o644); err != nil {
				return fmt.Errorf("failed to write executor job spec to file: %w", err)
			}
			ccv.Plog.Info().Str("file-path", filePath).Msg("Wrote executor job spec to file")
		}

		// Create the AggregatorInput
		aggregatorInput := services.AggregatorInput{
			CommitteeName:                           committeeName,
			CommitteeVerifierResolverProxyAddresses: committeeVerifierResolverProxyAddresses,
			ThresholdPerSource:                      thresholdPerSource,
		}
		// generate and print the config to stdout for now
		aggregatorConfig, err := aggregatorInput.GenerateConfig(verifierInputs)
		if err != nil {
			return fmt.Errorf("failed to generate aggregator config: %w", err)
		}
		ccv.Plog.Info().Msg("Generated aggregator config:")
		// write to a file in the temporary directory generated above
		filePath := filepath.Join(tempDir, "aggregator-config.toml")
		if err := os.WriteFile(filePath, aggregatorConfig, 0o644); err != nil {
			return fmt.Errorf("failed to write aggregator config to file: %w", err)
		}
		ccv.Plog.Info().Str("file-path", filePath).Msg("Wrote aggregator config to file")

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
		ctx := context.Background()
		ctx = ccv.Plog.WithContext(ctx)
		in, err := ccv.LoadOutput[ccv.Cfg]("env-out.toml")
		if err != nil {
			return fmt.Errorf("failed to load environment output: %w", err)
		}
		chainIDs, wsURLs := make([]string, 0), make([]string, 0)
		for _, bc := range in.Blockchains {
			chainIDs = append(chainIDs, bc.ChainID)
			wsURLs = append(wsURLs, bc.Out.Nodes[0].ExternalWSUrl)
		}
		_, e, err := ccv.NewCLDFOperationsEnvironment(in.Blockchains, in.CLDF.DataStore)
		if err != nil {
			return fmt.Errorf("failed to create CLDF operations environment: %w", err)
		}
		ctx = ccv.Plog.WithContext(ctx)
		l := zerolog.Ctx(ctx)
		impl, err := evm.NewCCIP17EVM(ctx, *l, e, chainIDs, wsURLs)
		if err != nil {
			return fmt.Errorf("failed to create CCIP17EVM: %w", err)
		}
		_, reg, err := impl.ExposeMetrics(ctx, source, dest, chainIDs, wsURLs)
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

var sendCmd = &cobra.Command{
	Use:     "send <src>,<dest>[,<finality>]",
	Aliases: []string{"s"},
	Args:    cobra.RangeArgs(1, 1),
	Short:   "Send a message",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		ctx = ccv.Plog.WithContext(ctx)

		// Read the env flag, default to "out"
		envName, err := cmd.Flags().GetString("env")
		if err != nil {
			return fmt.Errorf("failed to parse 'env' flag: %w", err)
		}
		envFile := fmt.Sprintf("env-%s.toml", envName)

		in, err := ccv.LoadOutput[ccv.Cfg](envFile)
		if err != nil {
			return fmt.Errorf("failed to load environment output: %w", err)
		}
		sels := strings.Split(args[0], ",")

		// Support both V2 (2 params) and V3 (3 params) formats
		if len(sels) != 2 && len(sels) != 3 {
			return fmt.Errorf("expected 2 or 3 parameters (src,dest for V2 or src,dest,finality for V3), got %d", len(sels))
		}

		src, err := strconv.ParseUint(sels[0], 10, 64)
		if err != nil {
			return fmt.Errorf("failed to parse source chain selector: %w", err)
		}
		dest, err := strconv.ParseUint(sels[1], 10, 64)
		if err != nil {
			return fmt.Errorf("failed to parse destination chain selector: %w", err)
		}

		chainIDs, wsURLs := make([]string, 0), make([]string, 0)
		for _, bc := range in.Blockchains {
			chainIDs = append(chainIDs, bc.ChainID)
			wsURLs = append(wsURLs, bc.Out.Nodes[0].ExternalWSUrl)
		}

		_, e, err := ccv.NewCLDFOperationsEnvironment(in.Blockchains, in.CLDF.DataStore)
		if err != nil {
			return fmt.Errorf("creating CLDF operations environment: %w", err)
		}
		ctx = ccv.Plog.WithContext(ctx)
		l := zerolog.Ctx(ctx)
		impl, err := evm.NewCCIP17EVM(ctx, *l, e, chainIDs, wsURLs)
		if err != nil {
			return fmt.Errorf("failed to create CCIP17EVM: %w", err)
		}

		mockReceiverRef, err := in.CLDF.DataStore.Addresses().Get(
			datastore.NewAddressRefKey(
				dest,
				datastore.ContractType(mock_receiver.ContractType),
				semver.MustParse(mock_receiver.Deploy.Version()),
				evm.DefaultReceiverQualifier))
		if err != nil {
			return fmt.Errorf("failed to get mock receiver address: %w", err)
		}
		// Use V3 if finality config is provided, otherwise use V2
		var result cciptestinterfaces.MessageSentEvent
		if len(sels) == 3 {
			// V3 format with finality config
			finality, err := strconv.ParseUint(sels[2], 10, 32)
			if err != nil {
				return fmt.Errorf("failed to parse finality config: %w", err)
			}

			committeeVerifierProxyRef, err := in.CLDF.DataStore.Addresses().Get(
				datastore.NewAddressRefKey(
					src,
					datastore.ContractType(committee_verifier.ResolverProxyType),
					semver.MustParse(committee_verifier.Deploy.Version()),
					evm.DefaultCommitteeVerifierQualifier))
			if err != nil {
				return fmt.Errorf("failed to get committee verifier proxy address: %w", err)
			}
			executorRef, err := in.CLDF.DataStore.Addresses().Get(
				datastore.NewAddressRefKey(
					src,
					datastore.ContractType(executor_operations.ContractType),
					semver.MustParse(executor_operations.Deploy.Version()),
					""))
			if err != nil {
				return fmt.Errorf("failed to get executor address: %w", err)
			}
			result, err = impl.SendMessage(ctx, src, dest, cciptestinterfaces.MessageFields{
				Receiver: protocol.UnknownAddress(common.HexToAddress(mockReceiverRef.Address).Bytes()), // mock receiver
				Data:     []byte{},
			}, cciptestinterfaces.MessageOptions{
				Version:        3,
				FinalityConfig: uint16(finality),
				Executor:       protocol.UnknownAddress(common.HexToAddress(executorRef.Address).Bytes()), // executor address
				ExecutorArgs:   nil,
				TokenArgs:      nil,
				CCVs: []protocol.CCV{
					{
						CCVAddress: common.HexToAddress(committeeVerifierProxyRef.Address).Bytes(),
						Args:       []byte{},
						ArgsLen:    0,
					},
				},
			})
			if err != nil {
				return fmt.Errorf("failed to send message: %w", err)
			}
		} else {
			// V2 format - use the dedicated V2 function
			result, err = impl.SendMessage(ctx, src, dest, cciptestinterfaces.MessageFields{
				Receiver: protocol.UnknownAddress(common.HexToAddress(mockReceiverRef.Address).Bytes()), // mock receiver
				Data:     []byte{},
			}, cciptestinterfaces.MessageOptions{
				Version:             2,
				ExecutionGasLimit:   200_000,
				OutOfOrderExecution: true,
			})
			if err != nil {
				return fmt.Errorf("failed to send message: %w", err)
			}
		}
		ccv.Plog.Info().Msgf("Message ID: %s", hexutil.Encode(result.MessageID[:]))
		ccv.Plog.Info().Msgf("Receipt issuers: %s", result.ReceiptIssuers)
		return nil
	},
}

func init() {
	rootCmd.PersistentFlags().BoolP("debug", "d", false, "Enable running services with dlv to allow remote debugging.")

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
	rootCmd.AddCommand(sendCmd)
	sendCmd.Flags().String("env", "out", "Select environment file to use (e.g., 'staging' for env-staging.toml, defaults to env-out.toml)")

	// on-chain monitoring
	rootCmd.AddCommand(monitorContractsCmd)
	rootCmd.AddCommand(txInfoCmd)

	// contract management
	rootCmd.AddCommand(deployCommitVerifierCmd)
	rootCmd.AddCommand(deployReceiverCmd)

	// config generation
	rootCmd.AddCommand(generateConfigsCmd)
	generateConfigsCmd.Flags().String("address-refs-json", "", "Path to the CLD address_refs.json file")
	generateConfigsCmd.Flags().StringSlice("verifier-pubkeys", []string{}, "List of verifier public keys (comma separated), implies number of verifiers to generate configs for")
	generateConfigsCmd.Flags().String("aggregator-addr", "", "Aggregator gRPC address")
	generateConfigsCmd.Flags().Int("aggregator-port", 0, "Aggregator gRPC port")
	generateConfigsCmd.Flags().String("indexer-addr", "", "Indexer HTTP/s URL address")
	generateConfigsCmd.Flags().Int("num-executors", -1, "Number of executors to generate configs for, defaults to number of verifiers if not provided")

	_ = generateConfigsCmd.MarkFlagRequired("address-refs-json")
	_ = generateConfigsCmd.MarkFlagRequired("verifier-pubkeys")
	_ = generateConfigsCmd.MarkFlagRequired("aggregator-addr")
	_ = generateConfigsCmd.MarkFlagRequired("aggregator-port")
	_ = generateConfigsCmd.MarkFlagRequired("indexer-addr")
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
