package config

import (
	"fmt"
	"os"

	"github.com/pelletier/go-toml/v2"
)

// Config provides all configuration for the indexer.
type Config struct {
	// Monitoring is the configuration for the monitoring system inside the indexer.
	Monitoring MonitoringConfig `toml:"Monitoring"`
	// Scanner is the configuration for the scanner inside the indexer.
	Scanner ScannerConfig `toml:"Scanner"`
	// Discovery is the configuration for the discovery system inside the indexer.
	Discovery DiscoveryConfig `toml:"Discovery"`
	// Storage is the configuration for the storage inside the indexer.
	Storage StorageConfig `toml:"Storage"`
}

// MonitoringConfig provides all configuration for the monitoring system inside the indexer.
type MonitoringConfig struct {
	// Enabled enables the monitoring system.
	Enabled bool `toml:"Enabled"`
	// Type is the type of monitoring system to use (beholder, noop).
	Type string `toml:"Type"`
	// Beholder is the configuration for the beholder client (Not required if type is noop).
	Beholder BeholderConfig `toml:"Beholder"`
}

// BeholderConfig wraps the beholder.Config struct to expose a minimal config for the indexer.
type BeholderConfig struct {
	// InsecureConnection disables TLS for the beholder client.
	InsecureConnection bool `toml:"InsecureConnection"`
	// CACertFile is the path to the CA certificate file for the beholder client.
	CACertFile string `toml:"CACertFile"`
	// OtelExporterGRPCEndpoint is the endpoint for the beholder client to export to the collector.
	OtelExporterGRPCEndpoint string `toml:"OtelExporterGRPCEndpoint"`
	// OtelExporterHTTPEndpoint is the endpoint for the beholder client to export to the collector.
	OtelExporterHTTPEndpoint string `toml:"OtelExporterHTTPEndpoint"`
	// LogStreamingEnabled enables log streaming to the collector.
	LogStreamingEnabled bool `toml:"LogStreamingEnabled"`
	// MetricReaderInterval is the interval to scrape metrics (in seconds).
	MetricReaderInterval int64 `toml:"MetricReaderInterval"`
	// TraceSampleRatio is the ratio of traces to sample.
	TraceSampleRatio float64 `toml:"TraceSampleRatio"`
	// TraceBatchTimeout is the timeout for a batch of traces.
	TraceBatchTimeout int64 `toml:"TraceBatchTimeout"`
}

// ScannerConfig provides all configuration for the scanner inside the indexer.
type ScannerConfig struct {
	// ScanInterval is the interval to read from each off-chain storage (in seconds).
	ScanInterval int64 `toml:"ScanInterval"`
}

// StorageConfig allows you to change the storage backend used by the indexer.
type StorageConfig struct {
	// Type is the type of storage to use (memory, postgres).
	Type StorageType `toml:"Type"`
}

// StorageType is the type of storage to use (memory, postgres).
type StorageType string

const (
	StorageTypeMemory StorageType = "memory"
)

// DiscoveryConfig allows you to change the discovery system used by the indexer.
type DiscoveryConfig struct {
	// Type is the type of discovery to use (static).
	Type DiscoveryType `toml:"Type"`
	// Static is the configuration for the static discovery system.
	Static StaticDiscoveryConfig `toml:"Static"`
}

// DiscoveryType is the type of discovery to use (static).
type DiscoveryType string

const (
	DiscoveryTypeStatic DiscoveryType = "static"
)

// StaticDiscoveryConfig allows you to change the static discovery system used by the indexer.
type StaticDiscoveryConfig struct {
	// Readers is the list of readers to use for the static discovery system.
	Readers []StaticDiscoveryReaderConfig `toml:"Readers"`
}

// StaticDiscoveryReaderConfig allows you to change the static discovery system used by the indexer.
type StaticDiscoveryReaderConfig struct {
	// Type is the type of reader to use (aggregator).
	Type ReaderType `toml:"type"`
	// Aggregator is the configuration for the aggregator reader.
	Aggregator AggregatorReaderConfig `toml:"Aggregator"`
}

// ReaderType is the type of reader to use (aggregator).
type ReaderType string

const (
	ReaderTypeAggregator ReaderType = "aggregator"
)

// AggregatorReaderConfig allows you to change the aggregator reader used by the indexer.
type AggregatorReaderConfig struct {
	// Address is the known grpc address of the aggregator.
	Address string `toml:"Address"`
	// Since is the unix timestamp in seconds to start reading from.
	Since int64 `toml:"Since"`
}

// LoadConfig loads configuration from a TOML file.
// It returns an error if the file cannot be read or parsed.
func LoadConfig() (*Config, error) {
	filepath, ok := os.LookupEnv("INDEXER_CONFIG_PATH")
	if !ok {
		filepath = "config.toml"
	}
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file config.toml: %w", err)
	}

	return LoadConfigFromBytes(data)
}

// LoadConfigFromBytes loads configuration from TOML bytes.
// It returns an error if the data cannot be parsed.
func LoadConfigFromBytes(data []byte) (*Config, error) {
	var config Config
	if err := toml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse TOML config: %w", err)
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return &config, nil
}

// Validate performs basic validation on the configuration.
// It returns an error if the configuration is invalid.
func (c *Config) Validate() error {
	if c.Scanner.ScanInterval <= 0 {
		return fmt.Errorf("scanner scan_interval must be positive, got %d", c.Scanner.ScanInterval)
	}

	if c.Storage.Type == "" {
		return fmt.Errorf("storage type is required")
	}

	if c.Discovery.Type == "" {
		return fmt.Errorf("discovery type is required")
	}

	if c.Monitoring.Enabled && c.Monitoring.Type == "" {
		return fmt.Errorf("monitoring type is required when monitoring is enabled")
	}

	// Validate beholder config if monitoring is enabled and type is beholder
	if c.Monitoring.Enabled && c.Monitoring.Type == "beholder" {
		if err := c.Monitoring.Beholder.Validate(); err != nil {
			return fmt.Errorf("beholder config validation failed: %w", err)
		}
	}

	// Validate discovery readers
	if c.Discovery.Type == "static" {
		if err := c.Discovery.Static.Validate(); err != nil {
			return fmt.Errorf("static discovery config validation failed: %w", err)
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

// Validate performs validation on the static discovery configuration.
func (s *StaticDiscoveryConfig) Validate() error {
	if len(s.Readers) == 0 {
		return fmt.Errorf("at least one reader is required for static discovery")
	}

	for i, reader := range s.Readers {
		if err := reader.Validate(i); err != nil {
			return err
		}
	}

	return nil
}

// Validate performs validation on the static discovery reader configuration.
func (r *StaticDiscoveryReaderConfig) Validate(index int) error {
	if r.Type == "" {
		return fmt.Errorf("reader %d type is required", index)
	}

	if r.Type == "aggregator" {
		if err := r.Aggregator.Validate(index); err != nil {
			return err
		}
	}

	return nil
}

// Validate performs validation on the aggregator reader configuration.
func (a *AggregatorReaderConfig) Validate(index int) error {
	if a.Address == "" {
		return fmt.Errorf("reader %d aggregator address is required", index)
	}

	if a.Since < 0 {
		return fmt.Errorf("reader %d aggregator since must be non-negative, got %d", index, a.Since)
	}

	return nil
}
