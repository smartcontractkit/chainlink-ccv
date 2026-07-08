package monitoring

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/grafana/pyroscope-go"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.uber.org/zap/zapcore"

	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func SetupBeholder(config BeholderConfig, signer crypto.Signer, metricViews []sdkmetric.View) error {
	if !config.Enabled {
		return nil
	}

	var err error
	logLevel := zapcore.InfoLevel
	if config.LogStreamingLevel != "" {
		logLevel, err = zapcore.ParseLevel(config.LogStreamingLevel)
		if err != nil {
			return fmt.Errorf("failed to parse log level: %w", err)
		}
	}
	beholderConfig := beholder.Config{
		InsecureConnection:       config.InsecureConnection,
		CACertFile:               config.CACertFile,
		OtelExporterHTTPEndpoint: config.OtelExporterHTTPEndpoint,
		OtelExporterGRPCEndpoint: config.OtelExporterGRPCEndpoint,
		LogStreamingEnabled:      config.LogStreamingEnabled,
		LogLevel:                 logLevel,
		MetricReaderInterval:     time.Second * time.Duration(config.MetricReaderInterval),
		TraceSampleRatio:         config.TraceSampleRatio,
		TraceBatchTimeout:        time.Second * time.Duration(config.TraceBatchTimeout),
	}

	if signer != nil {
		authHeaders, err := beholder.NewAuthHeaders(signer)
		if err != nil {
			return fmt.Errorf("failed to create beholder auth headers: %w", err)
		}
		beholderConfig.AuthHeaders = authHeaders
		key, ok := signer.Public().(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("expected ed25519.PublicKey, got %T", signer.Public())
		}
		beholderConfig.AuthPublicKeyHex = hex.EncodeToString(key)
		beholderConfig.AuthKeySigner = newBeholderSigner(signer)
	}

	if len(config.TelemetryAttributes) > 0 {
		attrs := make([]attribute.KeyValue, 0, len(config.TelemetryAttributes))
		for k, v := range config.TelemetryAttributes {
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

var _ beholder.Signer = (*beholderSigner)(nil)

type beholderSigner struct {
	signer crypto.Signer
}

func (b *beholderSigner) Sign(_ context.Context, _ string, data []byte) ([]byte, error) {
	return b.signer.Sign(rand.Reader, data, crypto.Hash(0))
}

func newBeholderSigner(signer crypto.Signer) beholder.Signer {
	return &beholderSigner{signer: signer}
}

// SetupPyroscope starts the Pyroscope profiler.
func SetupPyroscope(lggr logger.Logger, name string, config PyroscopeConfig) (*pyroscope.Profiler, error) {
	if !config.Enabled {
		return nil, nil
	}
	return pyroscope.Start(pyroscope.Config{
		ApplicationName: name,
		ServerAddress:   config.URL,
		Logger:          lggr,
		ProfileTypes: []pyroscope.ProfileType{
			pyroscope.ProfileCPU,
			pyroscope.ProfileAllocObjects,
			pyroscope.ProfileAllocSpace,
			pyroscope.ProfileGoroutines,
			pyroscope.ProfileBlockDuration,
			pyroscope.ProfileMutexDuration,
		},
	})
}
