package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/jmoiron/sqlx"
	"go.uber.org/zap/zapcore"

	"github.com/smartcontractkit/chainlink-ccv/kmd"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/logging"
	ks "github.com/smartcontractkit/chainlink-common/keystore"
	"github.com/smartcontractkit/chainlink-common/keystore/pgstore"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

const (
	// Use the same env vars as the keystore library itself for consistency.
	KeystoreFilePath = "KEYSTORE_FILE_PATH"
	KeystoreDBURL    = "KEYSTORE_DB_URL"
	KeystorePassword = "KEYSTORE_PASSWORD"
	Port             = "KMD_PORT"
	DefaultPort      = 7788
)

func main() {
	lggr, err := logger.NewWith(logging.DevelopmentConfig(zapcore.InfoLevel))
	if err != nil {
		panic(fmt.Sprintf("Failed to create logger: %v", err))
	}
	lggr = logger.Sugared(logger.Named(lggr, "KMD"))

	keystoreFilePath := os.Getenv(KeystoreFilePath)
	keystoreDBURL := os.Getenv(KeystoreDBURL)
	keystorePassword := os.Getenv(KeystorePassword)
	if (keystoreFilePath == "" && keystoreDBURL == "") || (keystoreFilePath != "" && keystoreDBURL != "") {
		lggr.Fatalw("Exactly one of KEYSTORE_FILE_PATH or KEYSTORE_DB_URL must be set")
	}
	if keystorePassword == "" {
		lggr.Fatalw("KEYSTORE_PASSWORD is required")
	}
	port := os.Getenv(Port)
	if port == "" {
		port = strconv.Itoa(DefaultPort)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var storage ks.Storage
	if keystoreFilePath != "" {
		storage = ks.NewFileStorage(keystoreFilePath)
	} else {
		db, err := sqlx.ConnectContext(ctx, "postgres", keystoreDBURL)
		if err != nil {
			lggr.Fatalw("Failed to connect to database", "error", err)
		}
		storage = pgstore.NewStorage(db, "default")
	}

	keystore, err := ks.LoadKeystore(ctx, storage, keystorePassword)
	if err != nil {
		lggr.Fatalw("Failed to load keystore", "error", err)
	}

	serverPort, err := strconv.Atoi(port)
	if err != nil {
		lggr.Fatalw("Failed to convert port to integer", "error", err)
	}
	server := kmd.NewServer(keystore, serverPort, logger.Sugared(logger.Named(lggr, "Server")))
	if err := server.Start(); err != nil {
		lggr.Fatalw("Failed to start server", "error", err)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	<-sigCh
	lggr.Infow("Received shutdown signal, stopping server...")
	if err := server.Stop(); err != nil {
		lggr.Fatalw("Failed to stop server", "error", err)
	}
	lggr.Infow("Server stopped")
}
