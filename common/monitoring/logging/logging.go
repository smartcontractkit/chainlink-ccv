package logging

import (
	"fmt"

	"go.uber.org/zap/zapcore"

	"github.com/smartcontractkit/chainlink-ccv/common/monitoring"
	zaplog "github.com/smartcontractkit/chainlink-ccv/protocol/common/logging"
	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/logger/otelzap"
)

// InitLogger creates a named logger with the base core and optional Beholder log streaming.
func InitLogger(name string, baseLogLevel zapcore.Level, config monitoring.Config) (logger.Logger, error) {
	loggerCores := make([]zapcore.Core, 0, 2)
	baseCore, err := logger.NewCore(zaplog.GetLogProfile(baseLogLevel))
	if err != nil {
		return nil, fmt.Errorf("failed to initialize base core: %w", err)
	}
	loggerCores = append(loggerCores, baseCore)
	if config.Enabled && config.Type == "beholder" && config.Beholder.LogStreamingEnabled {
		if config.Beholder.LogStreamingLevel == "" {
			config.Beholder.LogStreamingLevel = "info"
		}
		logStreamingLevel, err := zapcore.ParseLevel(config.Beholder.LogStreamingLevel)
		if err != nil {
			return nil, fmt.Errorf("error parsing streaming log level: %w", err)
		}
		otelCore := otelzap.NewCore(beholder.GetLogger(), otelzap.WithLevel(logStreamingLevel))
		loggerCores = append(loggerCores, otelCore)
	}
	lggr := logger.NewWithCores(loggerCores...)
	lggr = logger.Named(lggr, name)
	return lggr, nil
}

// WithService returns lggr with the "ccip_service" field set to name.
func WithService(lggr logger.Logger, name string) logger.Logger {
	// do not use the reserved "service" key.
	return logger.With(lggr, "ccip_service", name)
}
