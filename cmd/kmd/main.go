package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/jmoiron/sqlx"
	"github.com/spf13/cobra"
	"go.uber.org/zap/zapcore"

	"github.com/smartcontractkit/chainlink-ccv/kmd"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/logging"
	ks "github.com/smartcontractkit/chainlink-common/keystore"
	kscli "github.com/smartcontractkit/chainlink-common/keystore/cli"
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

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Run the kmd server",
	RunE: func(cmd *cobra.Command, args []string) error {
		lggr, err := logger.NewWith(logging.DevelopmentConfig(zapcore.InfoLevel))
		if err != nil {
			panic(fmt.Sprintf("Failed to create logger: %v", err))
		}
		lggr = logger.Sugared(logger.Named(lggr, "KMD"))

		keystoreFilePath := os.Getenv(KeystoreFilePath)
		keystoreDBURL := os.Getenv(KeystoreDBURL)
		keystorePassword := os.Getenv(KeystorePassword)
		if (keystoreFilePath == "" && keystoreDBURL == "") || (keystoreFilePath != "" && keystoreDBURL != "") {
			return fmt.Errorf("exactly one of KEYSTORE_FILE_PATH or KEYSTORE_DB_URL must be set")
		}
		if keystorePassword == "" {
			return fmt.Errorf("KEYSTORE_PASSWORD is required")
		}
		port := os.Getenv(Port)
		if port == "" {
			port = strconv.Itoa(DefaultPort)
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// "touch" the file at the keystoreFilePath.
		if err := touch(keystoreFilePath); err != nil {
			return fmt.Errorf("failed to touch keystore file: %w", err)
		}

		lggr.Infow("Keystore file touched", "filePath", keystoreFilePath)

		var storage ks.Storage
		if keystoreFilePath != "" {
			storage = ks.NewFileStorage(keystoreFilePath)
		} else {
			db, err := sqlx.ConnectContext(ctx, "postgres", keystoreDBURL)
			if err != nil {
				return fmt.Errorf("failed to connect to database: %w", err)
			}
			storage = pgstore.NewStorage(db, "default")
		}

		keystore, err := ks.LoadKeystore(ctx, storage, keystorePassword)
		if err != nil {
			return fmt.Errorf("failed to load keystore: %w", err)
		}

		serverPort, err := strconv.Atoi(port)
		if err != nil {
			return fmt.Errorf("failed to convert port to integer: %w", err)
		}
		server := kmd.NewServer(keystore, serverPort, logger.Sugared(logger.Named(lggr, "Server")))
		if err := server.Start(); err != nil {
			return fmt.Errorf("failed to start server: %w", err)
		}

		lggr.Infow("Server started", "port", serverPort)

		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

		<-sigCh
		lggr.Infow("Received shutdown signal, stopping server...")
		if err := server.Stop(); err != nil {
			return fmt.Errorf("failed to stop server: %w", err)
		}
		lggr.Infow("Server stopped")

		return nil
	},
}

var createKeysCmd = &cobra.Command{
	Use:   "create-keys",
	Short: "Create keys",
	RunE: func(cmd *cobra.Command, args []string) error {
		data := cmd.Flag("data").Value.String()
		if data == "" {
			return fmt.Errorf("data is required")
		}
		var req ks.CreateKeysRequest
		if err := json.Unmarshal([]byte(data), &req); err != nil {
			return fmt.Errorf("failed to unmarshal create keys request: %w", err)
		}

		fmt.Printf("Creating keys with request: %+v\n", req)

		serverPort := os.Getenv(Port)
		if serverPort == "" {
			serverPort = strconv.Itoa(DefaultPort)
		}

		kmdClient := kmd.NewClient(fmt.Sprintf("http://localhost:%s", serverPort))
		createKeysResponse, err := kmdClient.CreateKeys(cmd.Context(), req)
		if err != nil {
			return fmt.Errorf("failed to create keys: %w", err)
		}

		fmt.Printf("got response: %+v\n", createKeysResponse)

		return nil
	},
}

func main() {
	createKeysCmd.Flags().StringP("data", "d", "", "inline JSON request e.g. '{\"Keys\": [{\"KeyName\": \"key1\", \"KeyType\": \"X25519\"}]}'")
	rootCmd := &cobra.Command{
		Use: "kmd",
	}
	rootCmd.AddCommand(runCmd, kscli.NewRootCmd(), createKeysCmd)
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// touch creates a file if it doesn't exist, or updates the timestamps if it does.
func touch(filePath string) error {
	_, err := os.Open(filePath)
	if err == nil {
		// file exists, nothing to do.
		return nil
	}

	// Extract the directory from the filePath.
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// file doesn't exist, create it.
	f, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer f.Close()

	if err := f.Sync(); err != nil {
		return fmt.Errorf("failed to sync file: %w", err)
	}

	return nil
}
