package monitoring

import (
	"fmt"
	"time"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.uber.org/zap/zapcore"

	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
)

func SetupBeholder(config Config, metricViews []sdkmetric.View) error {
	if !config.Enabled || config.Type != "beholder" {
		return nil
	}

	var err error
	logLevel := zapcore.InfoLevel
	if config.Beholder.LogStreamingLevel != "" {
		logLevel, err = zapcore.ParseLevel(config.Beholder.LogStreamingLevel)
		if err != nil {
			return fmt.Errorf("failed to parse log level: %w", err)
		}
	}
	beholderConfig := beholder.Config{
		InsecureConnection:       config.Beholder.InsecureConnection,
		CACertFile:               config.Beholder.CACertFile,
		OtelExporterHTTPEndpoint: config.Beholder.OtelExporterHTTPEndpoint,
		OtelExporterGRPCEndpoint: config.Beholder.OtelExporterGRPCEndpoint,
		LogStreamingEnabled:      config.Beholder.LogStreamingEnabled,
		LogLevel:                 logLevel,
		MetricReaderInterval:     time.Second * time.Duration(config.Beholder.MetricReaderInterval),
		TraceSampleRatio:         config.Beholder.TraceSampleRatio,
		TraceBatchTimeout:        time.Second * time.Duration(config.Beholder.TraceBatchTimeout),
	}

	if len(config.Beholder.TelemetryAttributes) > 0 {
		attrs := make([]attribute.KeyValue, 0, len(config.Beholder.TelemetryAttributes))
		for k, v := range config.Beholder.TelemetryAttributes {
			attrs = append(attrs, attribute.String(k, v))
		}
		beholderConfig.ResourceAttributes = attrs
	}

	if len(metricViews) > 0 {
		// Note: due to OTEL spec, all histogram buckets must be defined when the beholder client is created.
		beholderConfig.MetricViews = metricViews
	}

	// Create the beholder client
	beholderClient, err := beholder.NewClient(beholderConfig)
	if err != nil {
		return fmt.Errorf("failed to create beholder client: %w", err)
	}

	// Set the beholder client and global otel providers
	beholder.SetClient(beholderClient)
	beholder.SetGlobalOtelProviders()

	return nil
}
