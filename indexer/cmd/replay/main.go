package main

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/olekukonko/tablewriter"
	"github.com/urfave/cli"
	"go.uber.org/zap/zapcore"

	ccvcommon "github.com/smartcontractkit/chainlink-ccv/common"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/config"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/readers"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/registry"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/replay"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/storage"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/hmac"
	"github.com/smartcontractkit/chainlink-ccv/protocol/common/logging"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil/pg"
)

func main() {
	app := cli.NewApp()
	app.Name = "indexer-replay"
	app.Usage = "Replay indexer data from upstream sources"
	app.Commands = replayCommands()

	if err := app.Run(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func replayCommands() []cli.Command {
	return []cli.Command{
		{
			Name:   "discovery",
			Usage:  "Replay message discovery from a sequence number",
			Action: discoveryAction,
			Flags: []cli.Flag{
				cli.Uint64Flag{
					Name:     "since",
					Usage:    "Replay discovery since this aggregator sequence number",
					Required: true,
				},
				cli.BoolFlag{
					Name:  "force",
					Usage: "Overwrite existing messages and CCV records (default: backfill only)",
				},
			},
		},
		{
			Name:   "messages",
			Usage:  "Replay CCV records for specific message IDs",
			Action: messagesAction,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:     "ids",
					Usage:    "Comma-separated list of message IDs to replay",
					Required: true,
				},
				cli.BoolFlag{
					Name:  "force",
					Usage: "Overwrite existing CCV records (default: backfill only)",
				},
			},
		},
		{
			Name:   "status",
			Usage:  "Show status of a replay job",
			Action: statusAction,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:     "id",
					Usage:    "Job UUID to check",
					Required: true,
				},
			},
		},
		{
			Name:   "list",
			Usage:  "List recent replay jobs",
			Action: listAction,
		},
		{
			Name:   "resume",
			Usage:  "Resume a failed or interrupted replay job",
			Action: resumeAction,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:     "id",
					Usage:    "Job UUID to resume",
					Required: true,
				},
			},
		},
	}
}

func discoveryAction(c *cli.Context) error {
	since := c.Uint64("since")
	if since > math.MaxInt64 {
		return fmt.Errorf("--since value %d exceeds maximum sequence number", since)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	engine, cleanup := mustBuildEngine(ctx, true)
	defer cleanup()

	req := replay.Request{
		Type:  replay.TypeDiscovery,
		Since: int64(since),
		Force: c.Bool("force"),
	}

	jobID, err := engine.Start(ctx, req)
	if err != nil {
		if jobID != "" {
			return fmt.Errorf("replay failed (job %s can be resumed): %w", jobID, err)
		}
		return fmt.Errorf("replay failed: %w", err)
	}

	fmt.Printf("Replay completed successfully. Job ID: %s\n", jobID) //nolint:forbidigo // CLI user output
	return nil
}

func messagesAction(c *cli.Context) error {
	idsStr := c.String("ids")
	ids := strings.Split(idsStr, ",")
	for i := range ids {
		ids[i] = strings.TrimSpace(ids[i])
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	engine, cleanup := mustBuildEngine(ctx, false)
	defer cleanup()

	req := replay.Request{
		Type:       replay.TypeMessages,
		MessageIDs: ids,
		Force:      c.Bool("force"),
	}

	jobID, err := engine.Start(ctx, req)
	if err != nil {
		if jobID != "" {
			return fmt.Errorf("replay failed (job %s can be resumed): %w", jobID, err)
		}
		return fmt.Errorf("replay failed: %w", err)
	}

	fmt.Printf("Replay completed successfully. Job ID: %s\n", jobID) //nolint:forbidigo // CLI user output
	return nil
}

func statusAction(c *cli.Context) error {
	ctx := context.Background()
	store := mustBuildStore(ctx)

	job, err := store.GetJob(ctx, c.String("id"))
	if err != nil {
		return err
	}

	return renderJob(job)
}

func listAction(_ *cli.Context) error {
	ctx := context.Background()
	store := mustBuildStore(ctx)

	jobs, err := store.ListJobs(ctx)
	if err != nil {
		return err
	}

	return renderJobList(jobs)
}

func resumeAction(c *cli.Context) error {
	jobID := c.String("id")

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	store := mustBuildStore(ctx)
	job, err := store.GetJob(ctx, jobID)
	if err != nil {
		return err
	}

	engine, cleanup := mustBuildEngine(ctx, job.Type == replay.TypeDiscovery)
	defer cleanup()

	if err := engine.Resume(ctx, jobID); err != nil {
		return fmt.Errorf("resume failed: %w", err)
	}

	fmt.Printf("Replay resumed and completed successfully. Job ID: %s\n", jobID) //nolint:forbidigo // CLI user output
	return nil
}

// renderJob prints a single replay job's details.
func renderJob(j *replay.Job) error {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetAutoFormatHeaders(false)
	table.SetBorder(false)
	table.SetColumnSeparator("")
	table.SetAlignment(tablewriter.ALIGN_LEFT)

	data := [][]string{
		{"Job ID", j.ID},
		{"Type", string(j.Type)},
		{"Status", string(j.Status)},
		{"Force", fmt.Sprintf("%v", j.ForceOverwrite)},
		{"Request Hash", j.RequestHash[:16]},
	}

	if j.SinceSequenceNumber != nil {
		data = append(data, []string{"Since (seq)", fmt.Sprintf("%d", *j.SinceSequenceNumber)})
	}
	if len(j.MessageIDs) > 0 {
		data = append(data, []string{"Message IDs", strings.Join(j.MessageIDs, ", ")})
	}

	data = append(data,
		[]string{"Progress", fmt.Sprintf("%d/%d (cursor: %d)", j.ProcessedItems, j.TotalItems, j.ProgressCursor)},
		[]string{"Last Heartbeat", j.LastHeartbeat.Format(time.RFC3339)},
		[]string{"Created", j.CreatedAt.Format(time.RFC3339)},
		[]string{"Updated", j.UpdatedAt.Format(time.RFC3339)},
	)
	if j.CompletedAt != nil {
		data = append(data, []string{"Completed", j.CompletedAt.Format(time.RFC3339)})
	}
	if j.ErrorMessage != nil {
		data = append(data, []string{"Error", *j.ErrorMessage})
	}

	table.AppendBulk(data)
	table.Render()
	return nil
}

// renderJobList prints a table of replay jobs.
func renderJobList(jobs []replay.Job) error {
	if len(jobs) == 0 {
		fmt.Println("No replay jobs found.") //nolint:forbidigo // CLI user output
		return nil
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetAutoFormatHeaders(false)
	table.SetBorder(false)
	table.SetHeader([]string{"ID", "Type", "Status", "Force", "Progress", "Created", "Updated"})

	for _, j := range jobs {
		progress := fmt.Sprintf("%d/%d", j.ProcessedItems, j.TotalItems)
		if j.TotalItems == 0 {
			progress = fmt.Sprintf("%d/?", j.ProcessedItems)
		}
		table.Append([]string{
			j.ID,
			string(j.Type),
			string(j.Status),
			fmt.Sprintf("%v", j.ForceOverwrite),
			progress,
			j.CreatedAt.Format(time.RFC3339),
			j.UpdatedAt.Format(time.RFC3339),
		})
	}

	table.Render()
	return nil
}

// mustBuildEngine creates the full replay engine with all dependencies.
func mustBuildEngine(ctx context.Context, needsDiscoveryReader bool) (*replay.Engine, func()) {
	cfg := mustLoadConfig()
	lggr := mustCreateLogger(cfg)
	indexerMonitoring := monitoring.NewNoopIndexerMonitoring()

	protocol.InitChainSelectorCache()

	pgCfg := cfg.Storage.Single.Postgres
	dbConfig := pg.DBConfig{
		MaxOpenConns:           max(pgCfg.MaxOpenConnections/2, 2),
		MaxIdleConns:           max(pgCfg.MaxIdleConnections/2, 1),
		IdleInTxSessionTimeout: time.Duration(pgCfg.IdleInTxSessionTimeout) * time.Second,
		LockTimeout:            time.Duration(pgCfg.LockTimeout) * time.Second,
	}

	migrationsDB, err := sqlx.Open("postgres", pgCfg.URI)
	if err != nil {
		lggr.Fatalf("Failed to open database for migrations: %v", err)
	}
	if err := ccvcommon.EnsureDBConnection(lggr, migrationsDB.DB); err != nil {
		lggr.Fatalf("Could not connect to database: %v", err)
	}
	if err := storage.RunMigrations(migrationsDB); err != nil {
		lggr.Fatalf("Failed to run database migrations: %v", err)
	}
	if err := migrationsDB.Close(); err != nil {
		lggr.Warnf("Error closing migration database connection: %v", err)
	}

	replayStore, err := replay.NewStoreFromConfig(ctx, lggr, pgCfg.URI, dbConfig)
	if err != nil {
		lggr.Fatalf("Failed to create replay store: %v", err)
	}

	indexerStorage, err := storage.NewPostgresStorage(ctx, lggr, indexerMonitoring, pgCfg.URI, pg.DriverPostgres, dbConfig)
	if err != nil {
		lggr.Fatalf("Failed to create indexer storage: %v", err)
	}

	verifierRegistry := registry.NewVerifierRegistry()
	verifierCleanups := make([]func(), 0, len(cfg.Verifiers))
	for _, vc := range cfg.Verifiers {
		vr, cleanup, err := createVerifierReader(ctx, lggr, &vc, indexerMonitoring)
		if err != nil {
			lggr.Fatalf("Failed to create verifier reader: %v", err)
		}
		verifierCleanups = append(verifierCleanups, cleanup)

		for _, address := range vc.IssuerAddresses {
			unknownAddress, err := protocol.NewUnknownAddressFromHex(address)
			if err != nil {
				lggr.Fatalf("Invalid verifier address: %v", err)
			}
			if err := verifierRegistry.AddVerifier(unknownAddress, vc.Name, vr); err != nil {
				lggr.Fatalf("Failed to register verifier: %v", err)
			}
		}
	}

	var aggFactory replay.AggregatorReaderFactory
	if needsDiscoveryReader && len(cfg.Discoveries) > 0 {
		disc := cfg.Discoveries[0]
		aggFactory = func(since int64) (*readers.ResilientReader, error) {
			return readers.NewAggregatorReader(disc.Address, lggr, since, hmac.ClientConfig{
				APIKey: disc.APIKey,
				Secret: disc.Secret,
			}, disc.InsecureConnection, config.EffectiveMaxResponseBytes(disc.MaxResponseBytes), indexerMonitoring)
		}
	}

	engine := replay.NewEngine(replayStore, indexerStorage, verifierRegistry, aggFactory, lggr)

	cleanup := func() {
		for _, c := range verifierCleanups {
			c()
		}
	}

	return engine, cleanup
}

func mustBuildStore(ctx context.Context) *replay.Store {
	cfg := mustLoadConfig()
	lggr := mustCreateLogger(cfg)

	pgCfg := cfg.Storage.Single.Postgres
	dbConfig := pg.DBConfig{
		MaxOpenConns:           2,
		MaxIdleConns:           1,
		IdleInTxSessionTimeout: time.Duration(pgCfg.IdleInTxSessionTimeout) * time.Second,
		LockTimeout:            time.Duration(pgCfg.LockTimeout) * time.Second,
	}

	store, err := replay.NewStoreFromConfig(ctx, lggr, pgCfg.URI, dbConfig)
	if err != nil {
		lggr.Fatalf("Failed to create store: %v", err)
	}
	return store
}

func mustLoadConfig() *config.Config {
	cfg, _, err := config.LoadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}
	return cfg
}

func mustCreateLogger(cfg *config.Config) logger.Logger {
	logLevel, err := zapcore.ParseLevel(cfg.LogLevel)
	if err != nil {
		logLevel = zapcore.InfoLevel
	}
	lggr, err := logger.NewWith(logging.DevelopmentConfig(logLevel))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create logger: %v\n", err)
		os.Exit(1)
	}
	return logger.Named(logger.Sugared(lggr), "indexer-replay")
}

func createVerifierReader(ctx context.Context, lggr logger.Logger, vc *config.VerifierConfig, mon common.IndexerMonitoring) (*readers.VerifierReader, func(), error) {
	var resilientReader *readers.ResilientReader
	var err error

	switch vc.Type {
	case config.ReaderTypeAggregator:
		resilientReader, err = readers.NewAggregatorReader(vc.Address, lggr, vc.Since, hmac.ClientConfig{
			APIKey: vc.APIKey,
			Secret: vc.Secret,
		}, vc.InsecureConnection, config.EffectiveMaxResponseBytes(vc.MaxResponseBytes), mon)
	case config.ReaderTypeRest:
		resilientReader = readers.NewRestReader(readers.RestReaderConfig{
			BaseURL:          vc.BaseURL,
			RequestTimeout:   time.Duration(vc.RequestTimeout),
			MaxResponseBytes: config.EffectiveMaxResponseBytes(vc.MaxResponseBytes),
			Logger:           lggr,
		})
	default:
		return nil, nil, errors.New("unknown verifier type: " + string(vc.Type))
	}
	if err != nil {
		return nil, nil, err
	}

	vr := readers.NewVerifierReader(resilientReader, vc)
	if err := vr.Start(ctx); err != nil {
		return nil, nil, err
	}

	cleanup := func() {
		_ = vr.Close()
	}
	return vr, cleanup, nil
}
