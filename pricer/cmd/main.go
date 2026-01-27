// Package main provides the entry point for the pricer service.
package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/smartcontractkit/chainlink-ccv/pricer/pkg/coordinator"
	kscli "github.com/smartcontractkit/chainlink-common/keystore/cli"
	commonconfig "github.com/smartcontractkit/chainlink-common/pkg/config"
)

const (
	// Environment variable names for keystore configuration.
	EnvKeystoreData     = "KEYSTORE_DATA"     // Base64-encoded encrypted keystore
	EnvKeystorePassword = "KEYSTORE_PASSWORD" // Password to decrypt keystore
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
	}
	cmd.AddCommand(NewRunCmd(), kscli.NewRootCmd())
	return cmd
}

func NewRunCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run the pricer service",
		RunE: func(cmd *cobra.Command, args []string) error {
			configFile, err := cmd.Flags().GetString("config")
			if err != nil {
				return err
			}
			f, err := os.Open(configFile) //nolint:gosec // configFile is from CLI flag, not user input
			if err != nil {
				return fmt.Errorf("failed to open config %s: %w", configFile, err)
			}
			var cfg coordinator.Config
			if err := commonconfig.DecodeTOML(f, &cfg); err != nil {
				_ = f.Close()
				return fmt.Errorf("failed to load config %s: %w", configFile, err)
			}
			_ = f.Close()

			keystoreData, err := base64.StdEncoding.DecodeString(os.Getenv(EnvKeystoreData))
			if err != nil {
				return fmt.Errorf("failed to decode %s: %w", EnvKeystoreData, err)
			}
			keystorePassword := os.Getenv(EnvKeystorePassword)

			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			svc, err := coordinator.NewPricerFromConfig(ctx, cfg, keystoreData, keystorePassword)
			if err != nil {
				return fmt.Errorf("failed to create pricer: %w", err)
			}
			if err := svc.Start(ctx); err != nil {
				return fmt.Errorf("failed to start: %w", err)
			}
			<-ctx.Done()
			return svc.Close()
		},
	}
	cmd.Flags().String("config", "config.toml", "path to config file")
	return cmd
}
