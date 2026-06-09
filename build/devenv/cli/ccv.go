package cli

import (
	"context"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/google/uuid"
	"github.com/moby/moby/client"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/operations/committee_verifier"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/operations/mock_receiver_v2"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services/committeeverifier"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	hmacutil "github.com/smartcontractkit/chainlink-ccv/protocol/common/hmac"
	"github.com/smartcontractkit/chainlink-testing-framework/framework"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"

	ccv "github.com/smartcontractkit/chainlink-ccv/build/devenv"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/chainreg"
	ccldf "github.com/smartcontractkit/chainlink-ccv/build/devenv/cldf"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cli/log"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cli/send"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/evm"
)

const (
	LocalWASPLoadDashboard = "http://localhost:3000/d/WASPLoadTests/wasp-load-test?orgId=1&from=now-5m&to=now&refresh=5s"
	LocalCCVDashboard      = "http://localhost:3000/d/f8a04cef-653f-46d3-86df-87c532300672/ccv-services?orgId=1&refresh=5s"
)

// newEnvFn is set by PersistentPreRunE based on the --env-mode flag.
var newEnvFn func() error

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
		mode, err := cmd.Flags().GetString("env-mode")
		if err != nil {
			return err
		}
		switch mode {
		case "legacy":
			// Both env constructors return a value that the up/restart commands
			// discard, so adapt them to the error-only fn.
			newEnvFn = func() error {
				_, err := ccv.NewEnvironment()
				return err
			}
		case "phased":
			newEnvFn = func() error {
				_, err := ccv.NewPhasedEnvironment()
				return err
			}
		default:
			panic(fmt.Sprintf("unknown --env-mode %q", mode))
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
		if err := applyEnvConfig(cmd, args); err != nil {
			return err
		}
		framework.L.Info().Msg("Tearing down the development environment")
		if err := framework.RemoveTestContainers(); err != nil {
			return fmt.Errorf("failed to clean Docker resources: %w", err)
		}
		return newEnvFn()
	},
}

var upCmd = &cobra.Command{
	Use:     "up",
	Aliases: []string{"u"},
	Short:   "Spin up the development environment",
	Args:    cobra.RangeArgs(0, 1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := applyEnvConfig(cmd, args); err != nil {
			return err
		}
		return newEnvFn()
	},
}

// resolveConfigArg resolves a bare config name (no extension) to either
// name.toml or name.profile by checking which file exists on disk. If both
// exist the call is ambiguous and an error is returned. If neither exists the
// original name is returned unchanged and the caller produces the error.
// Names that already carry a recognized extension (.toml or .profile) pass
// through unmodified.
func resolveConfigArg(name string) (string, error) {
	if strings.HasSuffix(name, ".toml") || strings.HasSuffix(name, ".profile") {
		return name, nil
	}
	tomlName := name + ".toml"
	profileName := name + ".profile"
	_, tomlErr := os.Stat(tomlName)
	_, profileErr := os.Stat(profileName)
	if tomlErr != nil && !os.IsNotExist(tomlErr) {
		return "", fmt.Errorf("stat %s: %w", tomlName, tomlErr)
	}
	if profileErr != nil && !os.IsNotExist(profileErr) {
		return "", fmt.Errorf("stat %s: %w", profileName, profileErr)
	}
	hasToml := tomlErr == nil
	hasProfile := profileErr == nil
	if hasToml && hasProfile {
		return "", fmt.Errorf("ambiguous config name %q: both %s and %s exist; use the full filename", name, tomlName, profileName)
	}
	if hasToml {
		return tomlName, nil
	}
	if hasProfile {
		return profileName, nil
	}
	return name, nil
}

// applyEnvConfig resolves the environment configuration from flags/args and
// sets CTF_CONFIGS (and optionally CTF_OUTPUT) before the environment
// constructor runs. It handles three input paths:
//
//  1. --profile <file> or a positional *.profile arg → profile mode
//  2. positional *.toml arg → legacy raw-file mode (existing behavior)
//  3. no args → defaults to standard.profile
//
// Bare names without an extension (e.g. "env" or "standard") are resolved to
// the matching .toml or .profile file on disk; an error is returned when both
// exist.
//
// When a profile is active it also overrides newEnvFn to match the profile's
// declared environment type, so --env-mode is ignored.
func applyEnvConfig(cmd *cobra.Command, args []string) error {
	profileFlag, _ := cmd.Flags().GetString("profile")
	outputFlag, _ := cmd.Flags().GetString("output")

	_ = os.Setenv("TESTCONTAINERS_RYUK_DISABLED", "true")

	// Resolve positional arg and --profile flag to their actual file types.
	var positional string
	if len(args) > 0 {
		resolved, err := resolveConfigArg(args[0])
		if err != nil {
			return err
		}
		positional = resolved
	}
	if profileFlag != "" {
		resolved, err := resolveConfigArg(profileFlag)
		if err != nil {
			return err
		}
		if strings.HasSuffix(resolved, ".toml") {
			return fmt.Errorf("--profile %q resolved to a TOML config file; use the full filename or omit --profile to run in TOML mode", profileFlag)
		}
		profileFlag = resolved
	}

	// Positional TOML config file — existing behavior, no profile involved.
	if positional != "" && !strings.HasSuffix(positional, ".profile") {
		framework.L.Info().Str("Config", positional).Msg("Creating development environment")
		_ = os.Setenv("CTF_CONFIGS", positional)
		if outputFlag != "" {
			_ = os.Setenv("CTF_OUTPUT", outputFlag)
		}
		return nil
	}

	// Resolve profile path: positional *.profile > --profile flag > default.
	profilePath := profileFlag
	if positional != "" {
		if profileFlag != "" {
			return fmt.Errorf("cannot combine --profile flag with a positional config argument")
		}
		profilePath = positional
	}
	if profilePath == "" {
		profilePath = "standard.profile"
	}

	// --profile is mutually exclusive with --env-mode (when explicitly set).
	// --output is allowed: it overrides the output path derived from the profile.
	if cmd.Flags().Changed("env-mode") {
		return fmt.Errorf("cannot combine --profile with --env-mode; set environment in the profile file instead")
	}

	if err := applyProfile(profilePath); err != nil {
		return err
	}
	if outputFlag != "" {
		_ = os.Setenv("CTF_OUTPUT", outputFlag)
	}
	return nil
}

func applyProfile(profilePath string) error {
	p, err := LoadProfile(profilePath)
	if err != nil {
		return err
	}

	framework.L.Info().Str("Profile", profilePath).Strs("Configs", p.Configs).Msg("Loading profile")
	_ = os.Setenv("CTF_CONFIGS", strings.Join(p.Configs, ","))
	if p.Output != "" {
		_ = os.Setenv("CTF_OUTPUT", p.Output)
	}

	switch p.Environment {
	case "legacy":
		newEnvFn = func() error {
			_, err := ccv.NewEnvironment()
			return err
		}
	case "phased":
		newEnvFn = func() error {
			_, err := ccv.NewPhasedEnvironment()
			return err
		}
	}
	return nil
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

		selectors, e, err := ccldf.NewCLDFOperationsEnvironment(in.Blockchains, in.CLDF.DataStore)
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

		constructorArgs := mock_receiver_v2.ConstructorArgs{
			Required:  required,
			Optional:  optional,
			Threshold: uint8(optionalThreshold),
		}

		_, e, err := ccldf.NewCLDFOperationsEnvironment(in.Blockchains, in.CLDF.DataStore)
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
	Use:     "test [suite]",
	Aliases: []string{"t"},
	Short:   "Run a named test suite or raw pattern against the devenv",
	Long: `test runs a Go test suite against the devenv.

Named suites (positional argument):
  smoke, smoke-v2, smoke-v3, load, rpc-latency, gas-spikes, reorg, chaos,
  indexer-load, multi_chain_load

Without --profile the environment must already be running. With --profile
the environment is started first (written to a per-run output file so
concurrent runs do not collide).

Examples:
  ccv test smoke                                   # against running env
  ccv test smoke --profile standard                # start env, then run
  ccv test --pattern TestE2ESmoke/foo --profile p  # raw pattern, start env
  ccv test smoke --profile standard                        # build with build-docker (default)
  ccv test smoke --profile standard --build=build-docker-ci # build with build-docker-ci (CI)
  ccv test smoke --profile standard --build=false            # skip image build`,
	Args: cobra.RangeArgs(0, 1),
	RunE: func(cmd *cobra.Command, args []string) error {
		patternFlag, _ := cmd.Flags().GetString("pattern")
		profileName, _ := cmd.Flags().GetString("profile")
		timeout, _ := cmd.Flags().GetDuration("timeout")
		buildTarget, _ := cmd.Flags().GetString("build")
		logPath, _ := cmd.Flags().GetString("log")

		if len(args) > 0 && patternFlag != "" {
			return fmt.Errorf("cannot combine a suite name with --pattern")
		}
		buildEnabled := buildTarget != "" && buildTarget != "false" && profileName != ""

		// Resolve the Go test pattern and target directory.
		var testPattern, testDir string
		if patternFlag != "" {
			testPattern = patternFlag
			testDir = "tests/e2e"
		} else {
			if len(args) == 0 {
				return fmt.Errorf("specify a suite name or --pattern")
			}
			var err error
			testPattern, testDir, err = resolveTestSuite(args[0])
			if err != nil {
				return err
			}
		}

		// Set up log file: redirect ALL output (build, env startup, test) to a
		// file so the terminal only shows concise progress lines. We redirect at
		// the OS fd level (dup2) so that subprocesses, zerolog, and fmt.Print*
		// calls all land in the log regardless of how they open stdout/stderr.
		progress := func(msg string) { fmt.Fprintln(os.Stderr, msg) }
		if logPath != "" {
			lf, err := os.Create(logPath)
			if err != nil {
				return fmt.Errorf("failed to create log file %s: %w", logPath, err)
			}
			defer lf.Close()

			// Save the real terminal fds so progress messages can still reach it.
			realStdoutFd, _ := syscall.Dup(int(os.Stdout.Fd()))
			realStderrFd, _ := syscall.Dup(int(os.Stderr.Fd()))
			realTerm := os.NewFile(uintptr(realStderrFd), "real_stderr")
			defer func() {
				// Restore terminal fds on exit.
				_ = syscall.Dup2(realStdoutFd, int(os.Stdout.Fd()))
				_ = syscall.Dup2(realStderrFd, int(os.Stderr.Fd()))
				_ = syscall.Close(realStdoutFd)
				// realStderrFd is owned by realTerm; closing realTerm closes it.
				_ = realTerm.Close()
			}()

			// Redirect stdout and stderr to the log file.
			_ = syscall.Dup2(int(lf.Fd()), int(os.Stdout.Fd()))
			_ = syscall.Dup2(int(lf.Fd()), int(os.Stderr.Fd()))

			progress = func(msg string) {
				fmt.Fprintf(realTerm, "[ccv test] %s\n", msg)
			}
		}

		// Stage 1: optional image build.
		if buildEnabled {
			progress(fmt.Sprintf("building images (just %s)...", buildTarget))
			buildCmd := exec.Command("just", buildTarget)
			buildCmd.Stdout = os.Stdout
			buildCmd.Stderr = os.Stderr
			if err := buildCmd.Run(); err != nil {
				return fmt.Errorf("just %s failed: %w", buildTarget, err)
			}
		}

		// Stage 2: optional environment start.
		var extraEnv []string
		if profileName != "" {
			if !strings.HasSuffix(profileName, ".profile") {
				profileName += ".profile"
			}
			outputFile := fmt.Sprintf("test-%s-out.toml", generateRunID())
			absOutput, err := filepath.Abs(outputFile)
			if err != nil {
				return fmt.Errorf("failed to resolve output path: %w", err)
			}
			progress("tearing down any existing environment...")
			_ = framework.RemoveTestContainers()

			progress(fmt.Sprintf("starting environment (profile: %s, output: %s)...", profileName, absOutput))
			if err := applyProfile(profileName); err != nil {
				return err
			}
			_ = os.Setenv("CTF_OUTPUT", outputFile)
			_ = os.Setenv("TESTCONTAINERS_RYUK_DISABLED", "true")
			if err := newEnvFn(); err != nil {
				return fmt.Errorf("environment startup failed: %w", err)
			}
			extraEnv = []string{fmt.Sprintf("SMOKE_TEST_CONFIG=%s", absOutput)}
		}

		// Stage 3: run the test.
		timeoutStr := "0"
		if timeout > 0 {
			timeoutStr = timeout.String()
		}
		goTestArgs := []string{
			"test", "-v", "-count=1",
			"-run", testPattern,
			fmt.Sprintf("-timeout=%s", timeoutStr),
		}
		progress(fmt.Sprintf("running test %s...", testPattern))
		goTestCmd := exec.Command("go", goTestArgs...)
		goTestCmd.Dir = testDir
		goTestCmd.Stdout = os.Stdout
		goTestCmd.Stderr = os.Stderr
		goTestCmd.Stdin = os.Stdin
		if len(extraEnv) > 0 {
			goTestCmd.Env = append(os.Environ(), extraEnv...)
		}

		if err := goTestCmd.Run(); err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				if logPath != "" {
					progress(fmt.Sprintf("FAILED (log: %s)", logPath))
				}
				if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
					os.Exit(status.ExitStatus())
				}
				os.Exit(1)
			}
			return fmt.Errorf("test run failed: %w", err)
		}
		if logPath != "" {
			progress(fmt.Sprintf("PASSED (log: %s)", logPath))
		}
		return nil
	},
}

func resolveTestSuite(suite string) (pattern, dir string, err error) {
	switch suite {
	case "smoke":
		return "TestE2ESmoke", "tests/e2e", nil
	case "smoke-v2":
		return "TestE2ESmoke_ExtraArgsV2", "tests/e2e", nil
	case "smoke-v3":
		return "TestE2ESmoke_Basic/extra_args_v3_messaging", "tests/e2e", nil
	case "load":
		return "TestE2ELoad/clean", "tests/e2e", nil
	case "rpc-latency":
		return "TestE2ELoad/rpc_latency", "tests/e2e", nil
	case "gas-spikes":
		return "TestE2ELoad/gas", "tests/e2e", nil
	case "reorg":
		return "TestE2ELoad/reorg", "tests/e2e", nil
	case "chaos":
		return "TestE2ELoad/chaos", "tests/e2e", nil
	case "indexer-load":
		return "TestIndexerLoad", "tests/services/load", nil
	case "multi_chain_load":
		return "TestStaging/multi_chain_load", "tests/e2e", nil
	default:
		return "", "", fmt.Errorf("unknown suite %q; valid: smoke, smoke-v2, smoke-v3, load, rpc-latency, gas-spikes, reorg, chaos, indexer-load, multi_chain_load", suite)
	}
}

// generateRunID returns a short random ID for naming per-run output files.
func generateRunID() string {
	id, err := uuid.NewRandom()
	if err != nil {
		// Fallback to timestamp if crypto/rand is unavailable.
		return fmt.Sprintf("%d", time.Now().UnixMilli())
	}
	return id.String()[:8]
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
			url = committeeverifier.DefaultVerifierDBConnectionString
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

		impl, err := chainreg.NewProductConfigurationFromNetwork(input.Type)
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
	Use:   "tx-receipt --env <env> <tx hash>",
	Short: "Get transaction receipt information",
	Args:  cobra.RangeArgs(1, 1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) != 1 {
			return fmt.Errorf("expected 1 argument (tx hash), got %d", len(args))
		}
		txHash := common.HexToHash(args[0])
		ctx := ccv.Plog.WithContext(cmd.Context())
		env, err := cmd.Flags().GetString("env")
		if err != nil {
			return fmt.Errorf("failed to parse env: %w", err)
		}
		in, err := ccv.LoadOutput[ccv.Cfg](env)
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
			ccv.Plog.Info().Msgf("success: %d, gas specified in tx: %d, gas used in receipt: %d", receipt.Status, tx.Gas(), receipt.GasUsed)
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
	rootCmd.PersistentFlags().String("env-mode", "legacy", "Environment startup mode: legacy (default) or phased.")

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
	upCmd.Flags().StringP("profile", "p", "", "Profile file (*.profile) encoding the environment, config files, and output path")
	upCmd.Flags().StringP("output", "o", "", "Output file path (overrides the default derived from the first config file)")
	restartCmd.Flags().StringP("profile", "p", "", "Profile file (*.profile) encoding the environment, config files, and output path")
	restartCmd.Flags().StringP("output", "o", "", "Output file path (overrides the default derived from the first config file)")
	rootCmd.AddCommand(upCmd)
	rootCmd.AddCommand(restartCmd)
	rootCmd.AddCommand(downCmd)

	// utility
	testCmd.Flags().StringP("profile", "p", "", "Profile to start before running tests (also sets per-run output file)")
	testCmd.Flags().StringP("pattern", "r", "", "Raw Go test pattern (alternative to a named suite positional arg)")
	testCmd.Flags().Duration("timeout", 0, "Test timeout (0 = unlimited)")
	testCmd.Flags().String("build", "build-docker", "Just target to build Docker images before starting (e.g. build-docker, build-docker-ci); pass 'false' to skip; silently ignored when --profile is absent")
	testCmd.Flags().String("log", "", "Write verbose output (build, env, test) to this file; only progress lines appear on the terminal")
	rootCmd.AddCommand(testCmd)
	rootCmd.AddCommand(indexerDBShellCmd)
	rootCmd.AddCommand(printAddressesCmd)

	rootCmd.AddCommand(send.Command())
	rootCmd.AddCommand(log.Command())

	// on-chain monitoring
	rootCmd.AddCommand(monitorContractsCmd)
	rootCmd.AddCommand(txInfoCmd)
	txInfoCmd.Flags().String("env", "env-out.toml", "Select environment file to use (defaults to env-out.toml)")

	// contract management
	rootCmd.AddCommand(deployCommitVerifierCmd)
	rootCmd.AddCommand(deployReceiverCmd)

	// HMAC secret generation
	rootCmd.AddCommand(generateHMACSecretCmd)
	generateHMACSecretCmd.Flags().Int("count", 1, "Number of HMAC credential pairs to generate")

	// funds management: ccv funds distribute / ccv funds reclaim
	fundsCmd.PersistentFlags().String("selectors", "", "Comma-separated list of chain selectors (omit to use all EVM chains in the environment)")
	fundsCmd.PersistentFlags().String("env", "out", "Select environment file to use (e.g., 'staging' for env-staging.toml, defaults to env-out.toml)")
	fundsCmd.AddCommand(fundsDistributeCmd)
	fundsCmd.AddCommand(fundsReclaimCmd)
	fundsCmd.AddCommand(fundsBalancesCmd)
	rootCmd.AddCommand(fundsCmd)

	// dump logs
	rootCmd.AddCommand(dumpLogsCmd)
	dumpLogsCmd.Flags().String("dir-suffix", "", "Suffix to add to the logs directory")
	_ = dumpLogsCmd.MarkFlagRequired("dir-suffix")
}

func checkDockerIsRunning() {
	cli, err := client.New(client.FromEnv)
	if err != nil {
		fmt.Println("Can't create Docker client, please check if Docker daemon is running!")
		os.Exit(1)
	}
	defer cli.Close()
	_, err = cli.Ping(context.Background(), client.PingOptions{})
	if err != nil {
		fmt.Println("Docker is not running, please start Docker daemon first!")
		os.Exit(1)
	}
}

// RunCLI is the entrypoint for the devenv CLI.
func RunCLI() {
	checkDockerIsRunning()
	if len(os.Args) >= 2 && (os.Args[1] == "shell" || os.Args[1] == "sh") {
		profilePath, err := func() (string, error) {
			p := shellProfileArg(os.Args[2:])
			return resolveConfigArg(p)
		}()
		if err != nil {
			ccv.Plog.Err(err).Msg("Failed to resolve shell profile")
			os.Exit(1)
		}
		if err := applyProfile(profilePath); err != nil {
			ccv.Plog.Err(err).Str("profile", profilePath).Msg("Failed to load shell profile")
			os.Exit(1)
		}
		// Prime the active config so that bare "up" / "restart" in the shell
		// reuses the same profile without the user having to type it again.
		saveActiveConfig(profilePath)
		StartShell()
		return
	}
	if err := rootCmd.Execute(); err != nil {
		ccv.Plog.Err(err).Send()
		os.Exit(1)
	}
}

// shellProfileArg extracts the --profile / -p value from raw shell args,
// defaulting to "standard.profile" when not provided.
func shellProfileArg(args []string) string {
	for i, arg := range args {
		switch {
		case arg == "--profile" || arg == "-p":
			if i+1 < len(args) {
				return args[i+1]
			}
		case strings.HasPrefix(arg, "--profile="):
			return strings.TrimPrefix(arg, "--profile=")
		case strings.HasPrefix(arg, "-p="):
			return strings.TrimPrefix(arg, "-p=")
		}
	}
	return "standard.profile"
}
