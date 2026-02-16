package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/jdwatcher"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/logging"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"go.uber.org/zap/zapcore"
)

const (
	ConfigPathEnv     = "JD_WATCHER_CONFIG_PATH"
	DefaultConfigPath = "/etc/config.toml"
)

func main() {
	lggr, err := logger.NewWith(logging.DevelopmentConfig(zapcore.InfoLevel))
	if err != nil {
		panic(fmt.Sprintf("Failed to create logger: %v", err))
	}
	lggr = logger.Sugared(logger.Named(lggr, "JDWatcher"))

	configPath := os.Getenv(ConfigPathEnv)
	if configPath == "" {
		configPath = DefaultConfigPath
	}
	cfg, err := jdwatcher.LoadConfig(configPath)
	if err != nil {
		lggr.Fatalw("Failed to load config", "error", err)
	}

	watcher, err := jdwatcher.NewJDWatcher(lggr, cfg)
	if err != nil {
		lggr.Fatalw("Failed to create JD watcher", "error", err)
	}

	startCtx, startCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer startCancel()
	if err := watcher.Start(startCtx); err != nil {
		lggr.Fatalw("Failed to start JD watcher", "error", err)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	<-sigCh
	lggr.Infow("Received shutdown signal, stopping JD watcher...")
	if err := watcher.Stop(); err != nil {
		lggr.Fatalw("Failed to stop JD watcher", "error", err)
	}
	lggr.Infow("JD watcher stopped")
}
