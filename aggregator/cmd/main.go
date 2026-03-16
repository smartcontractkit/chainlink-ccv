// Package main provides the entry point for the aggregator service.
package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.uber.org/zap/zapcore"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/configuration"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/logging"
	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	aggregator "github.com/smartcontractkit/chainlink-ccv/aggregator/pkg"
)

func main() {
	// Determine log level from environment variable, defaulting to "info"
	logLevelStr := os.Getenv("LOG_LEVEL")
	if logLevelStr == "" {
		logLevelStr = "info"
	}
	var zapLevel zapcore.Level
	if err := zapLevel.UnmarshalText([]byte(logLevelStr)); err != nil {
		fmt.Fprintf(os.Stderr, "Invalid LOG_LEVEL '%s', defaulting to 'info'\n", logLevelStr)
		zapLevel = zapcore.InfoLevel
	}
	lggr, err := logger.NewWith(logging.DevelopmentConfig(zapLevel))
	if err != nil {
		panic(fmt.Sprintf("Failed to create logger: %v", err))
	}
	lggr = logger.Named(lggr, "aggregator")

	sugaredLggr := logger.Sugared(lggr)

	filePath, ok := os.LookupEnv("AGGREGATOR_CONFIG_PATH")
	if !ok {
		filePath = aggregator.DefaultConfigFile
	}
	if len(os.Args) > 1 {
		filePath = os.Args[1]
	}
	config, err := configuration.LoadConfig(filePath, sugaredLggr)
	if err != nil {
		lggr.Errorw("Failed to load configuration", "path", filePath, "error", err)
		os.Exit(1)
	}
	lggr.Infow("Loaded configuration", "config", config)

	if err := config.LoadFromEnvironment(); err != nil {
		lggr.Errorw("Failed to load configuration from environment", "path", filePath, "error", err)
		os.Exit(1)
	}
	lggr.Infow("Successfully loaded configuration from environment variables")

	var aggMonitoring common.AggregatorMonitoring = &monitoring.NoopAggregatorMonitoring{}
	if config.Monitoring.Enabled && config.Monitoring.Type == "beholder" {
		m, err := monitoring.InitMonitoring(beholder.Config{
			InsecureConnection:       config.Monitoring.Beholder.InsecureConnection,
			CACertFile:               config.Monitoring.Beholder.CACertFile,
			OtelExporterGRPCEndpoint: config.Monitoring.Beholder.OtelExporterGRPCEndpoint,
			OtelExporterHTTPEndpoint: config.Monitoring.Beholder.OtelExporterHTTPEndpoint,
			LogStreamingEnabled:      config.Monitoring.Beholder.LogStreamingEnabled,
			MetricReaderInterval:     time.Duration(config.Monitoring.Beholder.MetricReaderInterval) * time.Second,
			TraceSampleRatio:         config.Monitoring.Beholder.TraceSampleRatio,
			TraceBatchTimeout:        time.Duration(config.Monitoring.Beholder.TraceBatchTimeout) * time.Second,
		})
		if err != nil {
			sugaredLggr.Fatalf("Failed to initialize aggregator monitoring: %v", err)
		}
		aggMonitoring = m
		lggr.Info("Monitoring enabled")
	}

	server := aggregator.NewServer(sugaredLggr, config, aggMonitoring)
	ctx := context.Background()
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	lc := &net.ListenConfig{}
	lis, err := lc.Listen(ctx, "tcp", config.Server.Address)
	if err != nil {
		sugaredLggr.Fatalw("failed to listen for CCV data service", "address", config.Server.Address, "error", err)
	}

	err = server.Start(lis)
	if err != nil {
		sugaredLggr.Fatalw("failed to start CCV data service", "error", err)
	}
	aggMonitoring.RecordServiceStarted(ctx)

	<-ctx.Done()
	if err := server.Stop(); err != nil {
		sugaredLggr.Errorw("failed to stop CCV data service", "error", err)
	}
	if err := lis.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		sugaredLggr.Errorw("failed to close listener", "error", err)
	}
	sugaredLggr.Info("Aggregator service shut down gracefully")
}
