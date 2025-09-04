package main

import (
	"context"
	"github.com/smartcontractkit/chainlink-ccv/verifier"
	"os"
	"os/signal"
	"syscall"

	"go.uber.org/zap"

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
	coordinator, err := NewExecutorCoordinator(
		verifier.WithVerifier(commitVerifier),
		verifier.WithSourceReaders(sourceReaders),
		verifier.WithStorage(storageWriter),
		verifier.WithConfig(config),
		verifier.WithLogger(lggr),
	)
}
