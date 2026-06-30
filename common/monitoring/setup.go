package monitoring

import (
	"fmt"
	"time"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.uber.org/zap/zapcore"

	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
)

func SetupBeholder(config Config, metricViews []sdkmetric.View) {
	if !config.Enabled || config.Type != "beholder" {
		return
	}
	logLevel, err := zapcore.ParseLevel(config.Beholder.LogStreamingLevel)
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
		// Note: due to OTEL spec, all histogram buckets must be defined when the beholder client is created.
		MetricViews: metricViews,
	}

	// Create the beholder client
	beholderClient, err := beholder.NewClient(beholderConfig)
	if err != nil {
		panic(fmt.Sprintf("failed to create beholder client: %v", err))
	}

	// Set the beholder client and global otel providers
	beholder.SetClient(beholderClient)
	beholder.SetGlobalOtelProviders()
}
