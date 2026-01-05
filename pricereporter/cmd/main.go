// Package main provides the entry point for the pricereporter service.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/spf13/cobra"
	"go.uber.org/zap/zapcore"

	"github.com/smartcontractkit/chainlink-ccv/pricereporter/pkg/app"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/logging"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type Config struct {
	Interval time.Duration `toml:"interval"`
	LogLevel string        `toml:"loglevel"`
}

func main() {
	if err := NewRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

func NewRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "pricereporter",
		Short:        "Price reporter service",
		SilenceUsage: true,
		RunE:         run,
	}
	cmd.Flags().String("config", "config.toml", "path to config file")
	return cmd
}

func run(cmd *cobra.Command, args []string) error {
	configFile, err := cmd.Flags().GetString("config")
	if err != nil {
		return err
	}

	var cfg Config
	if _, err := toml.DecodeFile(configFile, &cfg); err != nil {
		return fmt.Errorf("failed to load config %s: %w", configFile, err)
	}

	if cfg.Interval <= 0 {
		return fmt.Errorf("interval must be positive")
	}

	logLevel := cfg.LogLevel
	if logLevel == "" {
		logLevel = "info"
	}

	var zapLevel zapcore.Level
	if err := zapLevel.UnmarshalText([]byte(logLevel)); err != nil {
		fmt.Fprintf(os.Stderr, "invalid loglevel %q, defaulting to info\n", logLevel)
		zapLevel = zapcore.InfoLevel
	}

	lggr, err := logger.NewWith(logging.DevelopmentConfig(zapLevel))
	if err != nil {
		return fmt.Errorf("failed to create logger: %w", err)
	}
	lggr = logger.Named(lggr, "pricereporter")
	sugared := logger.Sugared(lggr)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := app.Run(ctx, sugared, cfg.Interval); err != nil {
		return err
	}

	sugared.Info("pricereporter stopped")
	return nil
}
