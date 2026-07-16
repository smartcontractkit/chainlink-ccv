package monitoring

import (
	"fmt"

	"go.uber.org/zap/zapcore"
)

// Config provides monitoring configuration for CCV services.
type Config struct {
	// LogLevel specifies the logging level for service logger
	LogLevel string `json:"logLevel" toml:"LogLevel"`
	// Pyroscope is the configuration for pyroscope performance monitoring tool
	Pyroscope PyroscopeConfig `json:"pyroscope" toml:"Pyroscope"`
	// Beholder is the configuration for the beholder client.
	Beholder BeholderConfig `json:"beholder" toml:"Beholder"`
}

type PyroscopeConfig struct {
	// Enabled enables the pyroscope telemetry.
	Enabled bool `json:"enabled" toml:"Enabled"`
	// URL specifies the remote endpoint of pyroscope service
	URL string `json:"url" toml:"URL"`
}

// BeholderConfig wraps OpenTelemetry configuration for the beholder client.
type BeholderConfig struct {
	// Enabled enables the beholder telemetry.
	Enabled bool `json:"enabled" toml:"Enabled"`
	// InsecureConnection disables TLS for the beholder client.
	InsecureConnection bool `json:"insecure_connection" toml:"InsecureConnection"`
	// CACertFile is the path to the CA certificate file for the beholder client.
	CACertFile string `json:"ca_cert_file" toml:"CACertFile"`
	// OtelExporterGRPCEndpoint is the endpoint for the beholder client to export to the collector.
	OtelExporterGRPCEndpoint string `json:"otel_exporter_grpc_endpoint" toml:"OtelExporterGRPCEndpoint"`
	// OtelExporterHTTPEndpoint is the endpoint for the beholder client to export to the collector.
	OtelExporterHTTPEndpoint string `json:"otel_exporter_http_endpoint" toml:"OtelExporterHTTPEndpoint"`
	// LogStreamingEnabled enables log streaming to the collector.
	LogStreamingEnabled bool `json:"log_streaming_enabled" toml:"LogStreamingEnabled"`
	// LogStreamingLevel specifies the level above which logs are streamed to beholder
	LogStreamingLevel string `json:"log_streaming_level" toml:"LogStreamingLevel"`
	// MetricReaderInterval is the interval to scrape metrics (in seconds).
	MetricReaderInterval int64 `json:"metric_reader_interval" toml:"MetricReaderInterval"`
	// TraceSampleRatio is the ratio of traces to sample.
	TraceSampleRatio float64 `json:"trace_sample_ratio" toml:"TraceSampleRatio"`
	// TraceBatchTimeout is the timeout for a batch of traces.
	TraceBatchTimeout int64 `json:"trace_batch_timeout" toml:"TraceBatchTimeout"`
	// TelemetryAttributes are additional labels that assigned during OTel transmission
	TelemetryAttributes map[string]string `json:"telemetry_attributes" toml:"TelemetryAttributes"`
}

// Validate performs validation on the monitoring configuration.
func (m *Config) Validate() error {
	if m.LogLevel != "" {
		_, err := zapcore.ParseLevel(m.LogLevel)
		if err != nil {
			return fmt.Errorf("monitoring log_level is invalid: %w", err)
		}
	}

	if m.Pyroscope.Enabled {
		if err := m.Pyroscope.Validate(); err != nil {
			return fmt.Errorf("pyroscope config validation failed: %w", err)
		}
	}

	if m.Beholder.Enabled {
		if err := m.Beholder.Validate(); err != nil {
			return fmt.Errorf("beholder config validation failed: %w", err)
		}
	}

	return nil
}

// Validate performs validation on the pyroscope configuration.
func (p *PyroscopeConfig) Validate() error {
	if len(p.URL) == 0 {
		return fmt.Errorf("url is missing")
	}

	return nil
}

// Validate performs validation on the beholder configuration.
func (b *BeholderConfig) Validate() error {
	if b.LogStreamingLevel != "" {
		_, err := zapcore.ParseLevel(b.LogStreamingLevel)
		if err != nil {
			return fmt.Errorf("beholder log_streaming_level is invalid: %w", err)
		}
	}

	if b.MetricReaderInterval <= 0 {
		return fmt.Errorf("metric_reader_interval must be positive, got %d", b.MetricReaderInterval)
	}

	if b.TraceSampleRatio < 0 || b.TraceSampleRatio > 1 {
		return fmt.Errorf("trace_sample_ratio must be between 0 and 1, got %f", b.TraceSampleRatio)
	}

	if b.TraceBatchTimeout <= 0 {
		return fmt.Errorf("trace_batch_timeout must be positive, got %d", b.TraceBatchTimeout)
	}

	return nil
}
