// Package main provides the entry point for the pricer service.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"go.uber.org/zap/zapcore"

	"github.com/smartcontractkit/chainlink-ccv/pricer/pkg/pricer"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/logging"
	commonconfig "github.com/smartcontractkit/chainlink-common/pkg/config"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	evmtoml "github.com/smartcontractkit/chainlink-evm/pkg/config/toml"
)

type Config struct {
	// Product specific config.
	pricer.Config
	// TODO: Should be able to use chainlink-common/pkg/logger Config struct.
	LogLevel zapcore.Level `toml:"loglevel"`
	// EVM chain configuration.
	EVM evmtoml.EVMConfig `toml:"EVM"`
}

func (c *Config) Validate() error {
	if err := c.Config.Validate(); err != nil {
		return fmt.Errorf("invalid pricer config: %w", err)
	}
	if err := c.EVM.ValidateConfig(); err != nil {
		return fmt.Errorf("invalid EVM config: %w", err)
	}
	return nil
}

func (c *Config) SetDefaults() {
	c.Config.SetDefaults()
	if c.LogLevel == zapcore.Level(0) {
		c.LogLevel = zapcore.InfoLevel
	}
	// Apply chain-specific defaults based on ChainID.
	if c.EVM.ChainID != nil {
		defaults := evmtoml.Defaults(c.EVM.ChainID)
		defaults.SetFrom(&c.EVM.Chain)
		c.EVM.Chain = defaults
	}
	// Node.ValidateConfig() sets defaults for Order, IsLoadBalancedRPC, etc.
	for _, n := range c.EVM.Nodes {
		_ = n.ValidateConfig()
	}
}

func main() {
	if err := NewRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

func NewRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "pricer",
		Short:        "Pricer service",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			configFile, err := cmd.Flags().GetString("config")
			if err != nil {
				return err
			}
			return run(configFile)
		},
	}
	cmd.Flags().String("config", "config.toml", "path to config file")
	return cmd
}

func run(configFile string) error {
	f, err := os.Open(configFile)
	if err != nil {
		return fmt.Errorf("failed to open config %s: %w", configFile, err)
	}
	defer f.Close()

	var cfg Config
	if err := commonconfig.DecodeTOML(f, &cfg); err != nil {
		return fmt.Errorf("failed to load config %s: %w", configFile, err)
	}
	cfg.SetDefaults()
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}

	lggr, err := logger.NewWith(logging.DevelopmentConfig(cfg.LogLevel))
	if err != nil {
		return fmt.Errorf("failed to create logger: %w", err)
	}
	lggr = logger.Named(lggr, "pricer")

	// Build the EVM client from config.
	// TODO: Move this to chainlink-evm/pkg/client.
	evmClient, err := pricer.NewEvmClientFromConfig(cfg.EVM, lggr)
	if err != nil {
		return fmt.Errorf("failed to create EVM client: %w", err)
	}
	defer evmClient.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := evmClient.Dial(ctx); err != nil {
		return fmt.Errorf("failed to dial EVM client: %w", err)
	}

	svc := pricer.New(lggr, evmClient, cfg.Config)
	if err := svc.Start(ctx); err != nil {
		return fmt.Errorf("failed to start: %w", err)
	}
	<-ctx.Done()
	return svc.Close()
}
