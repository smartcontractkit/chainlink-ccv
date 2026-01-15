// Package main provides the entry point for the pricer service.
package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/grafana/pyroscope-go"
	"github.com/spf13/cobra"

	"github.com/smartcontractkit/chainlink-ccv/pricer/pkg/pricer"
	kscli "github.com/smartcontractkit/chainlink-common/keystore/cli"
	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
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
			var cfg pricer.Config
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

			// Setup OTEL Monitoring (via beholder) if enabled
			if cfg.Monitoring.Enabled {
				beholderConfig := beholder.Config{
					InsecureConnection:       cfg.Monitoring.InsecureConnection,
					CACertFile:               cfg.Monitoring.CACertFile,
					OtelExporterHTTPEndpoint: cfg.Monitoring.OtelExporterHTTPEndpoint,
					OtelExporterGRPCEndpoint: cfg.Monitoring.OtelExporterGRPCEndpoint,
					LogStreamingEnabled:      cfg.Monitoring.LogStreamingEnabled,
					MetricReaderInterval:     time.Second * time.Duration(cfg.Monitoring.MetricReaderInterval),
					TraceSampleRatio:         cfg.Monitoring.TraceSampleRatio,
					TraceBatchTimeout:        time.Second * time.Duration(cfg.Monitoring.TraceBatchTimeout),
				}

				// Create the beholder client
				client, err := beholder.NewClient(beholderConfig)
				if err != nil {
					return fmt.Errorf("failed to create beholder client: %w", err)
				}

				// Set the beholder client and global otel providers
				beholder.SetClient(client)
				beholder.SetGlobalOtelProviders()

				// Initialize Pyroscope for profiling
				if _, err := pyroscope.Start(pyroscope.Config{
					ApplicationName: "pricer",
					ServerAddress:   "http://pyroscope:4040",
					ProfileTypes: []pyroscope.ProfileType{
						pyroscope.ProfileCPU,
						pyroscope.ProfileAllocObjects,
						pyroscope.ProfileAllocSpace,
						pyroscope.ProfileGoroutines,
						pyroscope.ProfileBlockDuration,
						pyroscope.ProfileMutexDuration,
					},
				}); err != nil {
					return fmt.Errorf("failed to initialize pyroscope client: %w", err)
				}
			}

			svc, err := pricer.NewPricerFromConfig(ctx, cfg, keystoreData, keystorePassword)
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
