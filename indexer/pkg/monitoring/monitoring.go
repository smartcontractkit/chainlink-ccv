package monitoring

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap/zapcore"

	ccvcommon "github.com/smartcontractkit/chainlink-ccv/common"
	commonmetrics "github.com/smartcontractkit/chainlink-ccv/common/metrics"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/common"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/config"
	zaplog "github.com/smartcontractkit/chainlink-ccv/protocol/common/logging"
	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/logger/otelzap"
	"github.com/smartcontractkit/chainlink-common/pkg/metrics"
)

var _ common.IndexerMonitoring = (*IndexerBeholderMonitoring)(nil)

type IndexerBeholderMonitoring struct {
	metrics common.IndexerMetricLabeler
	lggr    logger.Logger
	commonmetrics.ServiceMetrics
}

func InitMonitoring(indexerConfig *config.Config) (common.IndexerMonitoring, error) {
	if !indexerConfig.Monitoring.Enabled || indexerConfig.Monitoring.Type != "beholder" {
		return NewNoopIndexerMonitoring(), nil
	}
	client, err := newBeholderClient(indexerConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create beholder client: %w", err)
	}

	// Set the beholder client and global otel providers, so they don't have to be referenced elsewhere.
	beholder.SetClient(client)
	beholder.SetGlobalOtelProviders()

	// Initialize the indexer metrics
	indexerMetrics, err := InitMetrics()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize indexer metrics: %w", err)
	}

	// Initialize the indexer logger
	lggr, err := initLogger(indexerConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize logger: %w", err)
	}

	serviceMetrics, err := commonmetrics.NewServiceMetrics(metrics.NewLabeler(), "indexer")
	if err != nil {
		return nil, fmt.Errorf("failed to create service metrics: %w", err)
	}

	return &IndexerBeholderMonitoring{
		metrics:        NewIndexerMetricLabeler(metrics.NewLabeler(), indexerMetrics),
		lggr:           lggr,
		ServiceMetrics: serviceMetrics,
	}, nil
}

func newBeholderClient(indexerConfig *config.Config) (*beholder.Client, error) {
	beholderConfig := beholder.Config{
		InsecureConnection:       indexerConfig.Monitoring.Beholder.InsecureConnection,
		CACertFile:               indexerConfig.Monitoring.Beholder.CACertFile,
		OtelExporterHTTPEndpoint: indexerConfig.Monitoring.Beholder.OtelExporterHTTPEndpoint,
		OtelExporterGRPCEndpoint: indexerConfig.Monitoring.Beholder.OtelExporterGRPCEndpoint,
		MetricReaderInterval:     time.Second * time.Duration(indexerConfig.Monitoring.Beholder.MetricReaderInterval),
		TraceSampleRatio:         indexerConfig.Monitoring.Beholder.TraceSampleRatio,
		TraceBatchTimeout:        time.Second * time.Duration(indexerConfig.Monitoring.Beholder.TraceBatchTimeout),
	}
	if indexerConfig.Monitoring.Beholder.LogStreamingEnabled {
		logStreamingLevel, err := zapcore.ParseLevel(indexerConfig.Monitoring.Beholder.LogLevel)
		if err != nil {
			return nil, fmt.Errorf("error parsing streaming log level: %w", err)
		}
		beholderConfig.LogStreamingEnabled = true
		beholderConfig.LogLevel = logStreamingLevel
	}
	// Note: due to OTEL spec, all histogram buckets must be defined when the beholder client is created.
	beholderConfig.MetricViews = MetricViews()

	// Create the beholder client
	client, err := beholder.NewClient(beholderConfig)
	return client, err
}

func initLogger(indexerConfig *config.Config) (logger.Logger, error) {
	loggerCores := make([]zapcore.Core, 0, 2)
	baseLogLevel, err := zapcore.ParseLevel(indexerConfig.LogLevel)
	if err != nil {
		return nil, fmt.Errorf("error parsing base log level: %w", err)
	}
	baseCore, err := logger.NewCore(zaplog.GetLogProfile(baseLogLevel))
	if err != nil {
		return nil, fmt.Errorf("failed to initialize base core: %w", err)
	}
	loggerCores = append(loggerCores, baseCore)
	if indexerConfig.Monitoring.Enabled && indexerConfig.Monitoring.Beholder.LogStreamingEnabled {
		logStreamingLevel, err := zapcore.ParseLevel(indexerConfig.Monitoring.Beholder.LogLevel)
		if err != nil {
			return nil, fmt.Errorf("error parsing streaming log level: %w", err)
		}
		otelCore := otelzap.NewCore(beholder.GetLogger(), otelzap.WithLevel(logStreamingLevel))
		loggerCores = append(loggerCores, otelCore)
	}
	lggr := logger.NewWithCores(loggerCores...)
	lggr = logger.Named(lggr, "indexer")
	lggr = ccvcommon.WithService(lggr, "indexer")
	// Use SugaredLogger for better API
	lggr = logger.Sugared(lggr)
	return lggr, nil
}

func (i *IndexerBeholderMonitoring) Metrics() common.IndexerMetricLabeler {
	return i.metrics
}

func (i *IndexerBeholderMonitoring) Logger() logger.Logger {
	return i.lggr
}

// noopServiceMetrics implements commonmetrics.ServiceMetrics with no-op behavior for noop monitoring.
type noopServiceMetrics struct{}

func (noopServiceMetrics) RecordServiceStarted(context.Context) {}

// NewNoopIndexerMonitoring creates a new noop monitoring instance.
func NewNoopIndexerMonitoring() common.IndexerMonitoring {
	return &IndexerBeholderMonitoring{
		metrics:        NewNoopIndexerMetricLabeler(),
		lggr:           logger.Nop(),
		ServiceMetrics: noopServiceMetrics{},
	}
}
