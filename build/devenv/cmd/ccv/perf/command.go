package perf

import (
	"context"
	"fmt"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"

	ccv "github.com/smartcontractkit/chainlink-ccv/devenv"
	"github.com/smartcontractkit/chainlink-ccv/devenv/tests/e2e/load"
)

func Command() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "perf",
		Aliases: []string{"p"},
		Short:   "Run a load test",
		RunE: func(cmd *cobra.Command, positionalArgs []string) error {
			if len(positionalArgs) != 2 {
				return fmt.Errorf("expected environment and test configuration files as arguments")
			}
			return run(perfArgs{
				envFile:  positionalArgs[0],
				testFile: positionalArgs[1],
			})
		},
	}

	return cmd
}

type perfArgs struct {
	envFile  string
	testFile string
}

func run(args perfArgs) error {
	ctx := context.Background()
	ctx = ccv.Plog.WithContext(ctx)

	l := zerolog.Ctx(ctx)
	lib, err := ccv.NewLib(l, args.envFile)
	if err != nil {
		return err
	}

	chains, err := lib.ChainsMap(ctx)
	if err != nil {
		return fmt.Errorf("failed to get chain implementations: %w", err)
	}

	// Load or create test config
	var testConfig *load.TOMLLoadTestRoot
	if args.testFile != "" {
		testConfig, err = load.LoadTestConfigFromToml(args.testFile)
		if err != nil {
			return fmt.Errorf("failed to load test config: %w", err)
		}
	}

	verifyTestConfig(ctx, testConfig, lib)

	// // Create and run the load test
	// runner, err := load.NewLoadTestRunner(env, testConfig, srcSelector, destSelector)
	// if err != nil {
	// 	return fmt.Errorf("failed to create load test runner: %w", err)
	// }

	gun, err := load.NewEVMTransactionGunFromTestConfig(lib.cfg, testConfig.TestProfiles[0], lib.Env, chains)
	if err != nil {
		return fmt.Errorf("failed to create EVM transaction gun: %w", err)
	}

}

func verifyTestConfig(ctx context.Context, testConfig *load.TOMLLoadTestRoot, lib *ccv.Lib) error {
	chainsInTestConfig := make(map[uint64]struct{})
	for _, testProfile := range testConfig.TestProfiles {
		for _, chain := range testProfile.ChainsAsSource {
			chainsInTestConfig[uint64(chain)] = struct{}{}
		}
		for _, chain := range testProfile.ChainsAsDest {
			chainsInTestConfig[uint64(chain)] = struct{}{}
		}
	}
	chainsInEnv, err := lib.ChainsMap(ctx)
	if err != nil {
		return fmt.Errorf("failed to get chain implementations: %w", err)
	}

	for chain := range chainsInTestConfig {
		if _, ok := chainsInEnv[chain]; !ok {
			return fmt.Errorf("chain %d not found in environment", chain)
		}
	}

	return nil
}
