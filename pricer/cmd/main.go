// Package main provides the entry point for the pricer service.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/smartcontractkit/chainlink-ccv/pricer/pkg/pricer"
	commonconfig "github.com/smartcontractkit/chainlink-common/pkg/config"
)

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
			// TODO: Pull from env var.
			return run(configFile, "password", "keystore.json")
		},
	}
	cmd.Flags().String("config", "config.toml", "path to config file")
	return cmd
}

func run(configFile string, keystorePassword string, ksFile string) error {
	f, err := os.Open(configFile)
	if err != nil {
		return fmt.Errorf("failed to open config %s: %w", configFile, err)
	}
	defer f.Close()

	var cfg pricer.Config
	if err := commonconfig.DecodeTOML(f, &cfg); err != nil {
		return fmt.Errorf("failed to load config %s: %w", configFile, err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	svc, err := pricer.NewPricerFromConfig(ctx, cfg, keystorePassword, ksFile)
	if err != nil {
		return fmt.Errorf("failed to create pricer: %w", err)
	}
	if err := svc.Start(ctx); err != nil {
		return fmt.Errorf("failed to start: %w", err)
	}
	<-ctx.Done()
	return svc.Close()
}
