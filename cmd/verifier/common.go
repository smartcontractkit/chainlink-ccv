package verifier

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/grafana/pyroscope-go"
	"github.com/jmoiron/sqlx"
	"go.uber.org/zap/zapcore"

	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"

	ccvcommon "github.com/smartcontractkit/chainlink-ccv/common"
	verifier "github.com/smartcontractkit/chainlink-ccv/verifier/pkg"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/db"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vsecrets"
	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

const (
	// Database connection pool settings. Not operator-tunable: these were previously read from
	// CL_DATABASE_* env vars that no deployment ever set, so they are fixed constants. Pull them back
	// into config only when a deployment actually needs to override them.
	defaultMaxOpenConns    = 20
	defaultMaxIdleConns    = 10
	defaultConnMaxLifetime = 300 * time.Second
	defaultConnMaxIdleTime = 60 * time.Second
)

func SetupMonitoring(config verifier.MonitoringConfig, verifierServiceName string) verifier.Monitoring {
	// If monitoring is not enabled, return a fake monitoring implementation that does nothing.
	if !config.Beholder.Enabled {
		verifierMonitoring := monitoring.NewFakeVerifierMonitoring()
		return verifierMonitoring
	}

	beholderConfig := beholder.Config{
		InsecureConnection:       config.Beholder.InsecureConnection,
		CACertFile:               config.Beholder.CACertFile,
		OtelExporterHTTPEndpoint: config.Beholder.OtelExporterHTTPEndpoint,
		OtelExporterGRPCEndpoint: config.Beholder.OtelExporterGRPCEndpoint,
		LogStreamingEnabled:      config.Beholder.LogStreamingEnabled,
		LogLevel:                 zapcore.InfoLevel,
		LogBatchProcessor:        false,
		LogExportInterval:        time.Second * 10,
		MetricReaderInterval:     time.Second * time.Duration(config.Beholder.MetricReaderInterval),
		TraceSampleRatio:         config.Beholder.TraceSampleRatio,
		TraceBatchTimeout:        time.Second * time.Duration(config.Beholder.TraceBatchTimeout),
		// Note: due to OTEL spec, all histogram buckets must be defined when the beholder client is created.
		MetricViews: monitoring.MetricViews(),
	}

	// Create the beholder client
	beholderClient, err := beholder.NewClient(beholderConfig)
	if err != nil {
		panic(fmt.Sprintf("failed to create beholder client: %v", err))
	}

	// Set the beholder client and global otel providers
	beholder.SetClient(beholderClient)
	beholder.SetGlobalOtelProviders()
	verifierMonitoring, err := monitoring.InitMonitoring(verifierServiceName)
	if err != nil {
		panic(fmt.Sprintf("failed to initialize verifier monitoring: %v", err))
	}
	return verifierMonitoring
}

// ConnectToPostgresDB opens the verifier's application storage database. The connection URL is
// resolved from the verifier secrets file when present, otherwise from CL_DATABASE_URL (the file
// wins). A nil secrets argument is the env-only path. An empty URL leaves the DB
// unconfigured (returns a nil DataSource), preserving the existing "DB optional" behavior.
func ConnectToPostgresDB(lggr logger.Logger, secrets *vsecrets.VerifierSecrets) (sqlutil.DataSource, error) {
	dbURL := secrets.DatabaseURL()
	if dbURL == "" {
		return nil, nil
	}

	dbx, err := sql.Open("postgres", dbURL)
	if err != nil {
		return nil, fmt.Errorf("failed to open postgres database: %w", err)
	}

	dbx.SetMaxOpenConns(defaultMaxOpenConns)
	dbx.SetMaxIdleConns(defaultMaxIdleConns)
	dbx.SetConnMaxLifetime(defaultConnMaxLifetime)
	dbx.SetConnMaxIdleTime(defaultConnMaxIdleTime)

	if err := ccvcommon.EnsureDBConnection(lggr, dbx); err != nil {
		_ = dbx.Close()
		return nil, fmt.Errorf("failed to ping postgres database: %w", err)
	}

	sqlxDB := sqlx.NewDb(dbx, "postgres")

	if err := db.RunPostgresMigrations(sqlxDB); err != nil {
		_ = dbx.Close()
		return nil, fmt.Errorf("failed to run postgres migrations: %w", err)
	}

	lggr.Infow("Using PostgreSQL chain status storage",
		"maxOpenConns", defaultMaxOpenConns,
		"maxIdleConns", defaultMaxIdleConns,
		"connMaxLifetime", defaultConnMaxLifetime,
		"connMaxIdleTime", defaultConnMaxIdleTime,
	)

	return sqlxDB, nil
}

func StartPyroscope(lggr logger.Logger, pyroscopeAddress, serviceName string) (*pyroscope.Profiler, error) {
	profiler, err := pyroscope.Start(pyroscope.Config{
		ApplicationName: serviceName,
		ServerAddress:   pyroscopeAddress,
		Logger:          nil, // Disable pyroscope logging - so noisy
		ProfileTypes: []pyroscope.ProfileType{
			pyroscope.ProfileCPU,
			pyroscope.ProfileAllocObjects,
			pyroscope.ProfileAllocSpace,
			pyroscope.ProfileGoroutines,
			pyroscope.ProfileBlockDuration,
			pyroscope.ProfileMutexDuration,
		},
	})
	if err != nil {
		lggr.Errorw("Failed to start pyroscope", "error", err)
		return nil, fmt.Errorf("failed to start pyroscope: %w", err)
	}
	return profiler, nil
}
