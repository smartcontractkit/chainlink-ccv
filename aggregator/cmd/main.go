// Package main provides the entry point for the aggregator service.
package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"github.com/urfave/cli"
	"go.uber.org/zap/zapcore"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/cli/chains"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/configuration"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/storage/postgres"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
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

	// Route "chains" subcommand to the CLI before treating os.Args[1] as a config path.
	if len(os.Args) >= 2 && os.Args[1] == "chains" {
		runChainsCLI(os.Args[1:], sugaredLggr)
		return
	}

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

	protocol.InitChainSelectorCache()

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

// runChainsCLI handles the "aggregator chains ..." subcommand.
// Config is read from AGGREGATOR_CONFIG_PATH env var or the default path.
func runChainsCLI(args []string, lggr logger.SugaredLogger) {
	filePath, ok := os.LookupEnv("AGGREGATOR_CONFIG_PATH")
	if !ok {
		filePath = aggregator.DefaultConfigFile
	}

	config, err := configuration.LoadConfig(filePath, lggr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		os.Exit(1)
	}
	if err := config.LoadFromEnvironment(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config from environment: %v\n", err)
		os.Exit(1)
	}

	var (
		chainsDepsOnce sync.Once
		chainsDeps     chains.Deps
	)
	getChainsDepsFn := func() chains.Deps {
		chainsDepsOnce.Do(func() {
			db, err := sql.Open("postgres", config.Storage.ConnectionURL)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to open database: %v\n", err)
				os.Exit(1)
			}
			sqlxDB := sqlx.NewDb(db, "postgres")
			if err := postgres.RunMigrations(sqlxDB, "postgres"); err != nil {
				fmt.Fprintf(os.Stderr, "failed to run migrations: %v\n", err)
				os.Exit(1)
			}
			store := postgres.NewDatabaseStorage(sqlxDB, config.Storage.PageSize, config.Storage.QueryTimeout, lggr)
			chainsDeps = chains.Deps{
				Logger:    lggr,
				Store:     store,
				Committee: config.Committee,
			}
		})
		return chainsDeps
	}

	app := cli.NewApp()
	app.Name = filepath.Base(os.Args[0])
	app.Usage = "Aggregator chain disable/enable CLI"
	app.Commands = []cli.Command{
		{
			Name:        "chains",
			Usage:       "Disable, enable, or inspect chain processing status",
			Subcommands: chains.InitChainsCommandsWithFactory(getChainsDepsFn),
		},
	}

	if err := app.Run(append([]string{app.Name}, args...)); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
