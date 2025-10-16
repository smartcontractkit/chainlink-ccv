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
	// API is the configuration for the API inside the indexer.
	API APIConfig `toml:"API"`
}

// APIConfig provides all configuration for the API inside the indexer.
type APIConfig struct {
	// RateLimit is the configuration for the rate limiting system inside the indexer.
	RateLimit RateLimitConfig `toml:"RateLimit"`
}

// RateLimitConfig provides all configuration for the rate limiting system inside the indexer.
type RateLimitConfig struct {
	// Enabled enables the rate limiting system inside the indexer.
	Enabled bool `toml:"Enabled"`
}

// ScannerConfig provides all configuration for the scanner inside the indexer.
type ScannerConfig struct {
	// ScanInterval is the interval to read from each off-chain storage (in seconds).
	ScanInterval int64 `toml:"ScanInterval"`
	// ReaderTimeout is the timeout for a single reader call (in seconds).
	ReaderTimeout int64 `toml:"ReaderTimeout"`
}

// StorageConfig allows you to change the storage strategy used by the indexer.
type StorageConfig struct {
	// Strategy is the storage strategy to use (single, sink).
	Strategy StorageStrategy `toml:"Strategy"`
	// Single is the configuration for a single storage backend (required if strategy is single).
	Single *SingleStorageConfig `toml:"Single"`
	// Sink is the configuration for multiple storage backends (required if strategy is sink).
	Sink *SinkStorageConfig `toml:"Sink"`
}

// StorageStrategy defines the storage strategy to use.
type StorageStrategy string

const (
	// StorageStrategySingle uses a single storage backend.
	StorageStrategySingle StorageStrategy = "single"
	// StorageStrategySink uses multiple storage backends with read conditions.
	StorageStrategySink StorageStrategy = "sink"
)

// SingleStorageConfig provides configuration for a single storage backend.
type SingleStorageConfig struct {
	// Type is the type of storage backend to use (memory, postgres).
	Type StorageBackendType `toml:"Type"`
	// Memory is the configuration for the in-memory storage backend (required if type is memory).
	Memory *InMemoryStorageConfig `toml:"Memory"`
	// Postgres is the configuration for the postgres storage backend (required if type is postgres).
	Postgres *PostgresConfig `toml:"Postgres"`
}

// SinkStorageConfig provides configuration for multiple storage backends.
type SinkStorageConfig struct {
	// Storages is the list of storage backends to use in the sink.
	// The order determines read and write priority.
	Storages []StorageBackendConfig `toml:"Storages"`
}

// StorageBackendConfig provides configuration for a single storage backend with read conditions.
type StorageBackendConfig struct {
	// Type is the type of storage backend to use (memory, postgres).
	Type StorageBackendType `toml:"Type"`
	// Memory is the configuration for the in-memory storage backend (required if type is memory).
	Memory *InMemoryStorageConfig `toml:"Memory"`
	// Postgres is the configuration for the postgres storage backend (required if type is postgres).
	Postgres *PostgresConfig `toml:"Postgres"`
	// ReadCondition is the read condition for this storage backend.
	ReadCondition ReadConditionConfig `toml:"ReadCondition"`
}

// InMemoryStorageConfig provides configuration for the in-memory storage backend.
type InMemoryStorageConfig struct {
	// TTL is the time-to-live for items in seconds. Items older than this will be evicted.
	// Set to 0 to disable TTL-based eviction.
	TTL int64 `toml:"TTL"`
	// MaxSize is the maximum number of items to keep in storage.
	// When exceeded, oldest items will be evicted.
	// Set to 0 to disable size-based eviction.
	MaxSize int `toml:"MaxSize"`
	// CleanupInterval is how often to run the background cleanup goroutine in seconds.
	// Defaults to 60 seconds if not set and TTL or MaxSize is enabled.
	CleanupInterval int64 `toml:"CleanupInterval"`
}

// PostgresConfig provides configuration for the postgres storage backend.
type PostgresConfig struct {
	// URI is the connection string for the postgres database.
	URI string `toml:"URI"`
	// MaxOpenConnections is the maximum number of open connections to the database.
	MaxOpenConnections int `toml:"MaxOpenConnections"`
	// MaxIdleConnections is the maximum number of idle connections to the database.
	MaxIdleConnections int `toml:"MaxIdleConnections"`
	// IdleInTxSessionTimeout is the idle_in_transaction_session_timeout in seconds.
	IdleInTxSessionTimeout int64 `toml:"IdleInTxSessionTimeout"`
	// LockTimeout is the lock_timeout in seconds.
	LockTimeout int64 `toml:"LockTimeout"`
}

// ReadConditionConfig provides configuration for storage read conditions.
type ReadConditionConfig struct {
	// Type is the type of read condition (always, never, time_range, recent).
	Type ReadConditionType `toml:"Type"`
	// StartUnix is the start of the time range this storage covers in unix timestamp.
	// Only used when Type is time_range. nil means no lower bound.
	StartUnix *int64 `toml:"StartUnix"`
	// EndUnix is the end of the time range this storage covers in unix timestamp.
	// Only used when Type is time_range. nil means no upper bound.
	EndUnix *int64 `toml:"EndUnix"`
	// LookbackWindowSeconds is the duration in seconds from now that this storage covers.
	// Only used when Type is recent.
	LookbackWindowSeconds *int64 `toml:"LookbackWindowSeconds"`
}

// ReadConditionType defines when a storage should be read from.
type ReadConditionType string

const (
	// ReadConditionAlways means the storage is always eligible for reads.
	ReadConditionAlways ReadConditionType = "always"
	// ReadConditionNever means the storage is never read from (write-only).
	ReadConditionNever ReadConditionType = "never"
	// ReadConditionTimeRange means the storage is only read when query time range matches.
	ReadConditionTimeRange ReadConditionType = "time_range"
	// ReadConditionRecent means the storage is only read for recent data.
	ReadConditionRecent ReadConditionType = "recent"
)

// StorageBackendType is the type of storage backend to use (memory, postgres).
type StorageBackendType string

const (
	StorageBackendTypeMemory   StorageBackendType = "memory"
	StorageBackendTypePostgres StorageBackendType = "postgres"
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
	// Type is the type of reader to use (aggregator, rest).
	Type ReaderType `toml:"type"`
	// Aggregator is the configuration for the aggregator reader.
	Aggregator AggregatorReaderConfig `toml:"Aggregator"`
	// Rest is the configuration for the rest reader.
	Rest RestReaderConfig `toml:"Rest"`
}

// ReaderType is the type of reader to use (aggregator).
type ReaderType string

const (
	ReaderTypeAggregator ReaderType = "aggregator"
	ReaderTypeRest       ReaderType = "rest"
)

// AggregatorReaderConfig allows you to change the aggregator reader used by the indexer.
type AggregatorReaderConfig struct {
	// Address is the known grpc address of the aggregator.
	Address string `toml:"Address"`
	// Since is the unix timestamp in seconds to start reading from.
	Since int64 `toml:"Since"`
}

// RestReaderConfig allows you to change the rest reader used by the indexer.
type RestReaderConfig struct {
	// BaseURL is the base URL for the rest reader.
	BaseURL string `toml:"BaseURL"`
	// Since is the unix timestamp in seconds to start reading from.
	Since int64 `toml:"Since"`
	// RequestTimeout is the timeout in seconds for the rest reader.
	RequestTimeout int64 `toml:"RequestTimeout"`
}

// LoadConfig loads configuration from a TOML file.
// It returns an error if the file cannot be read or parsed.
func LoadConfig() (*Config, error) {
	filepath, ok := os.LookupEnv("INDEXER_CONFIG_PATH")
	if !ok {
		filepath = "config.toml"
	}
	data, err := os.ReadFile(filepath) //nolint:gosec // file is either config.toml or set by user through env var
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

	// Validate storage config
	if err := c.Storage.Validate(); err != nil {
		return fmt.Errorf("storage config validation failed: %w", err)
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

// Validate performs validation on the storage configuration.
func (s *StorageConfig) Validate() error {
	if s.Strategy == "" {
		return fmt.Errorf("storage strategy is required")
	}

	switch s.Strategy {
	case StorageStrategySingle:
		if s.Single == nil {
			return fmt.Errorf("single storage config is required when strategy is single")
		}
		if err := s.Single.Validate(); err != nil {
			return fmt.Errorf("single storage config validation failed: %w", err)
		}
	case StorageStrategySink:
		if s.Sink == nil {
			return fmt.Errorf("sink storage config is required when strategy is sink")
		}
		if err := s.Sink.Validate(); err != nil {
			return fmt.Errorf("sink storage config validation failed: %w", err)
		}
	default:
		return fmt.Errorf("unknown storage strategy: %s (must be 'single' or 'sink')", s.Strategy)
	}

	return nil
}

// Validate performs validation on the single storage configuration.
func (s *SingleStorageConfig) Validate() error {
	if s.Type == "" {
		return fmt.Errorf("storage backend type is required")
	}

	switch s.Type {
	case StorageBackendTypeMemory:
		// Memory storage config is optional (can use defaults)
		if s.Memory != nil {
			if err := s.Memory.Validate(); err != nil {
				return fmt.Errorf("memory storage config validation failed: %w", err)
			}
		}
	case StorageBackendTypePostgres:
		if s.Postgres == nil {
			return fmt.Errorf("postgres storage config is required when type is postgres")
		}
		if err := s.Postgres.Validate(); err != nil {
			return fmt.Errorf("postgres storage config validation failed: %w", err)
		}
	default:
		return fmt.Errorf("unknown storage backend type: %s (must be 'memory' or 'postgres')", s.Type)
	}

	return nil
}

// Validate performs validation on the sink storage configuration.
func (s *SinkStorageConfig) Validate() error {
	if len(s.Storages) == 0 {
		return fmt.Errorf("at least one storage backend is required for sink strategy")
	}

	for i, storage := range s.Storages {
		if err := storage.Validate(i); err != nil {
			return err
		}
	}

	return nil
}

// Validate performs validation on the storage backend configuration.
func (s *StorageBackendConfig) Validate(index int) error {
	if s.Type == "" {
		return fmt.Errorf("storage[%d]: backend type is required", index)
	}

	switch s.Type {
	case StorageBackendTypeMemory:
		// Memory storage config is optional (can use defaults)
		if s.Memory != nil {
			if err := s.Memory.Validate(); err != nil {
				return fmt.Errorf("storage[%d]: memory storage config validation failed: %w", index, err)
			}
		}
	case StorageBackendTypePostgres:
		if s.Postgres == nil {
			return fmt.Errorf("storage[%d]: postgres storage config is required when type is postgres", index)
		}
		if err := s.Postgres.Validate(); err != nil {
			return fmt.Errorf("storage[%d]: postgres storage config validation failed: %w", index, err)
		}
	default:
		return fmt.Errorf("storage[%d]: unknown backend type: %s (must be 'memory' or 'postgres')", index, s.Type)
	}

	// Validate read condition
	return s.ReadCondition.Validate(index)
}

// Validate performs validation on the in-memory storage configuration.
func (i *InMemoryStorageConfig) Validate() error {
	if i.TTL < 0 {
		return fmt.Errorf("TTL must be non-negative, got %d", i.TTL)
	}

	if i.MaxSize < 0 {
		return fmt.Errorf("max_size must be non-negative, got %d", i.MaxSize)
	}

	if i.CleanupInterval < 0 {
		return fmt.Errorf("cleanup_interval must be non-negative, got %d", i.CleanupInterval)
	}

	return nil
}

// Validate performs validation on the read condition configuration.
func (r *ReadConditionConfig) Validate(index int) error {
	if r.Type == "" {
		return fmt.Errorf("storage[%d]: read condition type is required", index)
	}

	switch r.Type {
	case ReadConditionAlways, ReadConditionNever:
		// No additional validation needed
	case ReadConditionTimeRange:
		// StartUnix and EndUnix are optional (nil means no bound)
		// But if both are set, start must be <= end
		if r.StartUnix != nil && r.EndUnix != nil && *r.StartUnix > *r.EndUnix {
			return fmt.Errorf("storage[%d]: time_range start_unix (%d) must be <= end_unix (%d)", index, *r.StartUnix, *r.EndUnix)
		}
	case ReadConditionRecent:
		if r.LookbackWindowSeconds == nil || *r.LookbackWindowSeconds <= 0 {
			return fmt.Errorf("storage[%d]: recent read condition requires positive lookback_window_seconds", index)
		}
	default:
		return fmt.Errorf("storage[%d]: unknown read condition type: %s (must be 'always', 'never', 'time_range', or 'recent')", index, r.Type)
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

// Validate performs validation on the postgres configuration.
func (p *PostgresConfig) Validate() error {
	if p.URI == "" {
		return fmt.Errorf("postgres URI is required")
	}

	if p.MaxOpenConnections <= 0 {
		return fmt.Errorf("postgres max_open_connections must be positive, got %d", p.MaxOpenConnections)
	}

	if p.MaxIdleConnections < 0 {
		return fmt.Errorf("postgres max_idle_connections must be non-negative, got %d", p.MaxIdleConnections)
	}

	if p.MaxIdleConnections > p.MaxOpenConnections {
		return fmt.Errorf("postgres max_idle_connections (%d) cannot be greater than max_open_connections (%d)", p.MaxIdleConnections, p.MaxOpenConnections)
	}

	if p.IdleInTxSessionTimeout < 0 {
		return fmt.Errorf("postgres idle_in_tx_session_timeout must be non-negative, got %d", p.IdleInTxSessionTimeout)
	}

	if p.LockTimeout < 0 {
		return fmt.Errorf("postgres lock_timeout must be non-negative, got %d", p.LockTimeout)
	}

	return nil
}
