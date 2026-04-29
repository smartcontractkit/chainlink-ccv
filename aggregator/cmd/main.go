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
	"syscall"
	"time"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"github.com/urfave/cli"
	"go.uber.org/zap/zapcore"

	messagedisablementcli "github.com/smartcontractkit/chainlink-ccv/aggregator/cli/messagedisablement"
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

	var (
		messageDisablementRulesDB   *sql.DB
		messageDisablementRulesDeps messagedisablementcli.Deps
	)

	getMessageDisablementRulesDepsFn := func() messagedisablementcli.Deps {
		return messageDisablementRulesDeps
	}

	app := cli.NewApp()
	app.Name = filepath.Base(os.Args[0])
	app.Usage = "Aggregator service and message disablement CLI"
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:   "config, c",
			Usage:  "Path to config file",
			EnvVar: "AGGREGATOR_CONFIG_PATH",
			Value:  aggregator.DefaultConfigFile,
		},
	}

	app.Action = func(c *cli.Context) error {
		runServer(c.String("config"), lggr, sugaredLggr)
		return nil
	}

	app.Commands = []cli.Command{
		{
			Name:  "message-disablement-rules",
			Usage: "Create, delete, or inspect message disablement rules",
			Before: func(c *cli.Context) error {
				cfg, err := configuration.LoadConfig(c.GlobalString("config"), sugaredLggr)
				if err != nil {
					return fmt.Errorf("failed to load config: %w", err)
				}
				if err := cfg.LoadFromEnvironment(); err != nil {
					return fmt.Errorf("failed to load config from environment: %w", err)
				}
				db, err := sql.Open("postgres", cfg.Storage.ConnectionURL)
				if err != nil {
					return fmt.Errorf("failed to open database: %w", err)
				}
				messageDisablementRulesDB = db
				sqlxDB := sqlx.NewDb(db, "postgres")
				store := postgres.NewDatabaseStorage(sqlxDB, cfg.Storage.PageSize, cfg.Storage.QueryTimeout, sugaredLggr)
				messageDisablementRulesDeps = messagedisablementcli.Deps{
					Logger: lggr,
					Store:  store,
				}
				return nil
			},
			After: func(c *cli.Context) error {
				if messageDisablementRulesDB == nil {
					return nil
				}
				if err := messageDisablementRulesDB.Close(); err != nil {
					return fmt.Errorf("failed to close database: %w", err)
				}
				messageDisablementRulesDB = nil
				return nil
			},
			Subcommands: messagedisablementcli.InitMessageDisablementRulesCommandsWithFactory(getMessageDisablementRulesDepsFn),
		},
	}

	if err := app.Run(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

func runServer(configPath string, lggr logger.Logger, sugaredLggr logger.SugaredLogger) {
	config, err := configuration.LoadConfig(configPath, sugaredLggr)
	if err != nil {
		lggr.Errorw("Failed to load configuration", "path", configPath, "error", err)
		os.Exit(1)
	}
	lggr.Infow("Loaded configuration", "config", config)

	if err := config.LoadFromEnvironment(); err != nil {
		lggr.Errorw("Failed to load configuration from environment", "path", configPath, "error", err)
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
