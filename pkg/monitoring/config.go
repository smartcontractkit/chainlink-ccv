package monitoring

import "fmt"

// Config provides monitoring configuration for CCV services.
type Config struct {
	// Enabled enables the monitoring system.
	Enabled bool `json:"enabled" toml:"Enabled"`
	// Type is the type of monitoring system to use (beholder, noop).
	Type string `json:"type" toml:"Type"`
	// Beholder is the configuration for the beholder client (Not required if type is noop).
	Beholder BeholderConfig `json:"beholder" toml:"Beholder"`
}

// BeholderConfig wraps OpenTelemetry configuration for the beholder client.
type BeholderConfig struct {
	// InsecureConnection disables TLS for the beholder client.
	InsecureConnection bool `json:"insecure_connection"         toml:"InsecureConnection"`
	// CACertFile is the path to the CA certificate file for the beholder client.
	CACertFile string `json:"ca_cert_file"                toml:"CACertFile"`
	// OtelExporterGRPCEndpoint is the endpoint for the beholder client to export to the collector.
	OtelExporterGRPCEndpoint string `json:"otel_exporter_grpc_endpoint" toml:"OtelExporterGRPCEndpoint"`
	// OtelExporterHTTPEndpoint is the endpoint for the beholder client to export to the collector.
	OtelExporterHTTPEndpoint string `json:"otel_exporter_http_endpoint" toml:"OtelExporterHTTPEndpoint"`
	// LogStreamingEnabled enables log streaming to the collector.
	LogStreamingEnabled bool `json:"log_streaming_enabled"       toml:"LogStreamingEnabled"`
	// MetricReaderInterval is the interval to scrape metrics (in seconds).
	MetricReaderInterval int64 `json:"metric_reader_interval"      toml:"MetricReaderInterval"`
	// TraceSampleRatio is the ratio of traces to sample.
	TraceSampleRatio float64 `json:"trace_sample_ratio"          toml:"TraceSampleRatio"`
	// TraceBatchTimeout is the timeout for a batch of traces.
	TraceBatchTimeout int64 `json:"trace_batch_timeout"         toml:"TraceBatchTimeout"`
}

// Validate performs validation on the monitoring configuration.
func (m *Config) Validate() error {
	if m.Enabled && m.Type == "" {
		return fmt.Errorf("monitoring type is required when monitoring is enabled")
	}

	if m.Enabled && m.Type == "beholder" {
		if err := m.Beholder.Validate(); err != nil {
			return fmt.Errorf("beholder config validation failed: %w", err)
		}
	}

	return nil
}

// Validate performs validation on the beholder configuration.
func (b *BeholderConfig) Validate() error {
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
