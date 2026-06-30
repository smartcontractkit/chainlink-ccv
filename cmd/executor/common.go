package executor

import (
	"fmt"
	"time"

	"github.com/grafana/pyroscope-go"
	"go.uber.org/zap/zapcore"

	"github.com/smartcontractkit/chainlink-ccv/executor"
	"github.com/smartcontractkit/chainlink-ccv/executor/pkg/monitoring"
	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// SetupMonitoring configures executor monitoring via Beholder or returns a noop implementation.
func SetupMonitoring(config executor.MonitoringConfig) executor.Monitoring {
	if !config.Enabled || config.Type != "beholder" {
		return monitoring.NewNoopExecutorMonitoring()
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
		MetricViews:              monitoring.MetricViews(),
	}

	beholderClient, err := beholder.NewClient(beholderConfig)
	if err != nil {
		panic(fmt.Sprintf("failed to create beholder client: %v", err))
	}

	beholder.SetClient(beholderClient)
	beholder.SetGlobalOtelProviders()

	executorMonitoring, err := monitoring.InitMonitoring()
	if err != nil {
		panic(fmt.Sprintf("failed to initialize executor monitoring: %v", err))
	}
	return executorMonitoring
}

// StartPyroscope starts the Pyroscope profiler for the executor service.
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
		return nil, err
	}
	return profiler, nil
}
