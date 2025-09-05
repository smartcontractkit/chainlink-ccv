package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.uber.org/zap"

	"github.com/smartcontractkit/chainlink-ccv/executor"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func main() {
	// Setup logging - always debug level for now
	lggr, err := logger.NewWith(func(config *zap.Config) {
		config.Development = true
		config.Encoding = "console"
	})
	if err != nil {
		panic(err)
	}

	// Use SugaredLogger for better API
	lggr = logger.Sugared(lggr)

	// Create context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Create executor coordinator
	coordinator, err := executor.NewExecutorCoordinator(
		executor.WithLogger(lggr),
	)
	if err != nil {
		lggr.Errorw("Failed to create execution coordinator", "error", err)
		os.Exit(1)
	}

	if err := coordinator.Start(ctx); err != nil {
		lggr.Errorw("Failed to start execution coordinator", "error", err)
		os.Exit(1)
	}

	<-sigCh
	lggr.Infow("🛑 Shutdown signal received, stopping verifier...")

	// Graceful shutdown
	_, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	// Stop verification coordinator
	if err := coordinator.Stop(); err != nil {
		lggr.Errorw("Execution coordinator stop error", "error", err)
	}

	lggr.Infow("✅ Execution service stopped gracefully")
}
