// Command admin-console-demo is the demo harness (see README.md in this
// directory): it serves the real admin console package over a seeded disposable
// database, with a canned aggregator results client for the attestation read API.
package main

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq" // postgres driver
	"go.uber.org/zap/zapcore"
	"google.golang.org/grpc/codes"

	"github.com/smartcontractkit/chainlink-ccv/integration/storageaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/logging"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/admin"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/db"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// attestedID is the demo's already-attested message (0xdeadbeef x8); every other
// message ID is NotFound. Kept in sync with seed-verifier.sql and the README table.
const attestedID = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

// fakeResultsClient is the canned aggregator: the attested ID holds ccv data, every
// other message ID answers NotFound, so the reschedule gate demos both verdicts.
type fakeResultsClient struct{}

func (fakeResultsClient) GetVerifierResultsForMessage(_ context.Context, messageIDs [][]byte) ([]storageaccess.ResultEntry, error) {
	attested, err := hex.DecodeString(attestedID)
	if err != nil {
		return nil, err
	}
	entries := make([]storageaccess.ResultEntry, len(messageIDs))
	for i, id := range messageIDs {
		entries[i] = storageaccess.ResultEntry{Present: true, ErrorCode: int32(codes.NotFound), ErrorMsg: "message ID not found"}
		if string(id) == string(attested) {
			entries[i] = storageaccess.ResultEntry{Present: true, CcvData: []byte{0xde, 0xad}}
		}
	}
	return entries, nil
}

func (fakeResultsClient) Close() error { return nil }

func main() {
	if err := run(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "demo: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	dbURL := os.Getenv("DEMO_DATABASE_URL")
	if dbURL == "" {
		return errors.New("DEMO_DATABASE_URL is required (postgres://… of the demo database)")
	}
	configPath := os.Getenv(admin.ConfigPathEnv)
	if configPath == "" {
		configPath = admin.DefaultConfigPath
	}
	cfg, err := admin.LoadConfig(configPath)
	if err != nil {
		return err
	}

	sqlDB, err := sql.Open("postgres", dbURL)
	if err != nil {
		return fmt.Errorf("failed to open demo database: %w", err)
	}
	dbx := sqlx.NewDb(sqlDB, "postgres")
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := db.RunPostgresMigrationsContext(ctx, dbx); err != nil {
		return fmt.Errorf("failed to run verifier migrations: %w", err)
	}

	lggr, err := logger.NewWith(logging.GetLogProfile(zapcore.InfoLevel))
	if err != nil {
		return fmt.Errorf("failed to create logger: %w", err)
	}
	lggr = logger.Sugared(logger.Named(lggr, "admin-console-demo"))
	lggr.Infow("attestation freshness checks are served by a canned client", "attested", "0x"+attestedID)

	srv, err := admin.NewServer(cfg, admin.Deps{
		DB: dbx,
		// A non-empty address makes the freshness gate dial; the canned client
		// answers for whatever endpoint a real verifier would pass here.
		AggregatorAddress: "demo-aggregator",
		ResultsDialer: func(string) (storageaccess.ResultsClient, error) {
			return fakeResultsClient{}, nil
		},
	}, lggr)
	if err != nil {
		return err
	}

	lggr.Infow("demo ready", "address", "http://"+cfg.ListenAddress)
	if err := srv.Run(ctx); err != nil {
		return err
	}
	return dbx.Close()
}
