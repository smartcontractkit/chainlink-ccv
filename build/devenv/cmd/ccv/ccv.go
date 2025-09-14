package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/docker/docker/client"
	"github.com/spf13/cobra"

	"github.com/smartcontractkit/chainlink-ccv/devenv/services"

	"github.com/smartcontractkit/chainlink-testing-framework/framework"

	ccv "github.com/smartcontractkit/chainlink-ccv/devenv"
)

const (
	LocalWASPLoadDashboard = "http://localhost:3000/d/WASPLoadTests/wasp-load-test?orgId=1&from=now-5m&to=now&refresh=5s"
	LocalCCVDashboard      = "http://localhost:3000/d/f8a04cef-653f-46d3-86df-87c532300672/ccv-services?orgId=1&refresh=5s"
)

var rootCmd = &cobra.Command{
	Use:   "ccv",
	Short: "A CCV local environment tool",
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
		remote, _ := rootCmd.Flags().GetBool("remote")
		url, _ := bsCmd.Flags().GetString("url")
		if remote {
			return fmt.Errorf("remote mode: %v, Blockscout can only be used in 'local' mode", remote)
		}
		return framework.BlockScoutUp(url)
	},
}

var bsDownCmd = &cobra.Command{
	Use:     "down",
	Aliases: []string{"d"},
	Short:   "Spin down Blockscout EVM block explorer",
	RunE: func(cmd *cobra.Command, args []string) error {
		remote, _ := rootCmd.Flags().GetBool("remote")
		url, _ := bsCmd.Flags().GetString("url")
		if remote {
			return fmt.Errorf("remote mode: %v, Blockscout can only be used in 'local' mode", remote)
		}
		return framework.BlockScoutDown(url)
	},
}

var bsRestartCmd = &cobra.Command{
	Use:     "restart",
	Aliases: []string{"r"},
	Short:   "Restart the Blockscout EVM block explorer",
	RunE: func(cmd *cobra.Command, args []string) error {
		url, _ := bsCmd.Flags().GetString("url")
		if err := framework.BlockScoutDown(url); err != nil {
			return err
		}
		return framework.BlockScoutUp(url)
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
		full, _ := cmd.Flags().GetBool("full")
		var err error
		if full {
			err = framework.ObservabilityUpFull()
		} else {
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
		full, _ := cmd.Flags().GetBool("full")
		var err error
		if full {
			err = framework.ObservabilityUpFull()
		} else {
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
		default:
			return fmt.Errorf("test suite %s is unknown, choose between smoke or load", args[0])
		}
		originalDir, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("failed to get current directory: %w", err)
		}
		defer os.Chdir(originalDir)
		if err := os.Chdir("tests/e2e"); err != nil {
			return fmt.Errorf("failed to change to tests/e2e directory: %w", err)
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
		case "aggregator":
			url = services.DefaultAggregatorDBConnectionString
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

var sendCmd = &cobra.Command{
	Use:     "send",
	Aliases: []string{"s"},
	Args:    cobra.RangeArgs(1, 1),
	Short:   "Send a message",
	RunE: func(cmd *cobra.Command, args []string) error {
		in, err := ccv.LoadOutput[ccv.Cfg]("env-out.toml")
		if err != nil {
			return fmt.Errorf("failed to load environment output: %w", err)
		}
		sels := strings.Split(args[0], ",")
		if len(sels) != 2 {
			return fmt.Errorf("expected 2 chain selectors, got %d", len(sels))
		}
		src, err := strconv.ParseUint(sels[0], 10, 64)
		if err != nil {
			return fmt.Errorf("failed to parse source chain selector: %w", err)
		}
		dest, err := strconv.ParseUint(sels[1], 10, 64)
		if err != nil {
			return fmt.Errorf("failed to parse destination chain selector: %w", err)
		}

		return ccv.SendExampleArgsV2Message(in, src, dest)
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

var monitorContractsCmd = &cobra.Command{
	Use:   "upload-on-chain-metrics",
	Short: "Reads on-chain EVM contract events and temporary exposes them as Prometheus metrics endpoint to be scraped",
	RunE: func(cmd *cobra.Command, args []string) error {
		in, err := ccv.LoadOutput[ccv.Cfg]("env-out.toml")
		if err != nil {
			return fmt.Errorf("failed to load environment output: %w", err)
		}
		if err := ccv.MonitorOnChainLogs(in); err != nil {
			return err
		}
		return ccv.ExposePrometheusMetricsFor(10 * time.Second)
	},
}

func init() {
	rootCmd.PersistentFlags().StringP("blockscout_url", "u", "http://host.docker.internal:8545", "EVM RPC node URL")

	// Blockscout, on-chain debug
	bsCmd.AddCommand(bsUpCmd)
	bsCmd.AddCommand(bsDownCmd)
	bsCmd.AddCommand(bsRestartCmd)
	rootCmd.AddCommand(bsCmd)

	// observability
	obsCmd.PersistentFlags().BoolP("full", "f", false, "Enable full observability stack with additional components")
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

	// on-chain monitoring
	rootCmd.AddCommand(monitorContractsCmd)
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
		StartShell()
		return
	}
	if err := rootCmd.Execute(); err != nil {
		ccv.Plog.Err(err).Send()
		os.Exit(1)
	}
}
