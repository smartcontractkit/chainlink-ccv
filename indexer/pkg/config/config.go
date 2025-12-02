package config

import (
	"errors"
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
)

// Config provides all configuration for the indexer.
type Config struct {
	// Monitoring is the configuration for the monitoring system inside the indexer.
	Monitoring MonitoringConfig `toml:"Monitoring"`
	// Discovery is the configuration for the discovery system inside the indexer.
	Discovery DiscoveryConfig `toml:"Discovery"`
	// Scheduler is the configuration for the scheduling component inside the indexer.
	Scheduler SchedulerConfig `toml:"Scheduler"`
	// Pool is the configuration for the worker pool within the indexer.
	Pool PoolConfig `toml:"Pool"`
	// Verifiers contains the configured verifiers known to the indexer.
	Verifiers []VerifierConfig `toml:"Verifier"`
	// Storage is the configuration for the storage inside the indexer.
	Storage StorageConfig `toml:"Storage"`
	// API is the configuration for the API inside the indexer.
	API APIConfig `toml:"API"`
}

type SchedulerConfig struct {
	// TickerInterval defines the number of milliseconds to wait before running the next scheduling loop.
	TickerInterval int `toml:"TickerInterval"`
	// VerificationVisibilityWindow defines the number of seconds before we will no longer attempt to retrieve verifications.
	VerificationVisibilityWindow int `toml:"VerificationVisibilityWindow"`
	// BaseDelay defines the minimum number of milliseconds to wait before retrying the message.
	BaseDelay int `toml:"BaseDelay"`
	// MaxDelay defines the maximum number of milliseconds to wait before retrying the message.
	MaxDelay int `toml:"MaxDelay"`
}

type PoolConfig struct {
	// ConcurrentWorkers is the maximum number of concurrent workers, equates to maximum number of concurrent messages being indexed.
	ConcurrentWorkers int `toml:"ConcurrentWorkers"`
	// WorkerTimeout is the number of seconds a worker can attempt to retrieve verifications for
	// Note: This value should always be higher then the maximum timeout on the slowest configured verifier.
	WorkerTimeout int `toml:"WorkerTimeout"`
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

// StorageBackendType is the type of storage backend to use (memory, postgres).
type StorageBackendType string

const (
	StorageBackendTypeMemory   StorageBackendType = "memory"
	StorageBackendTypePostgres StorageBackendType = "postgres"
)

// DiscoveryConfig allows you to change the discovery system used by the indexer.
type DiscoveryConfig struct {
	AggregatorReaderConfig
	PollInterval int    `toml:"PollInterval"`
	Timeout      int    `toml:"Timeout"`
	NtpServer    string `toml:"NtpServer"`
}

type VerifierConfig struct {
	Type            ReaderType `toml:"Type"`
	IssuerAddresses []string   `toml:"IssuerAddresses"`
	Name            string     `toml:"Name"`
	// BatchSize is the maximum batch size to send to the verifier.
	BatchSize int `toml:"BatchSize"`
	// MaxBatchWaitTime is the maximum time to wait in milliseconds before sending a batch to the verifier.
	MaxBatchWaitTime int `toml:"MaxBatchWaitTime"`
	AggregatorReaderConfig
	RestReaderConfig
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
	// APIKey is the client's API Key (UUID format)
	APIKey string `toml:"APIKey"`
	// Secret is the HMAC secret used to sign requests
	Secret string `toml:"Secret"`
}

// RestReaderConfig allows you to change the rest reader used by the indexer.
type RestReaderConfig struct {
	// BaseURL is the base URL for the rest reader.
	BaseURL string `toml:"BaseURL"`
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
	if err := c.Scheduler.Validate(); err != nil {
		return fmt.Errorf("scheduler config validation failed: %w", err)
	}

	if err := c.Discovery.Validate(0); err != nil {
		return fmt.Errorf("discovery config validation failed: %w", err)
	}

	// Validate storage config
	if err := c.Storage.Validate(); err != nil {
		return fmt.Errorf("storage config validation failed: %w", err)
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

	return nil
}

func (s *SchedulerConfig) Validate() error {
	if s.BaseDelay <= 0 {
		return fmt.Errorf("base delay must be greater than 0")
	}

	if s.MaxDelay <= s.BaseDelay {
		return fmt.Errorf("max delay must be greater than base delay")
	}

	if s.TickerInterval <= 20 {
		return fmt.Errorf("ticker interval must be greater than 20 milliseconds")
	}

	if s.VerificationVisibilityWindow <= (s.MaxDelay / 1000) {
		return fmt.Errorf("verification visability window must be greater than max delay after seconds conversion")
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

	return nil
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

func (v *VerifierConfig) Validate(index int) error {
	switch v.Type {
	case ReaderTypeAggregator:
		return v.AggregatorReaderConfig.Validate(index)
	case ReaderTypeRest:
		return v.RestReaderConfig.Validate(index)
	default:
		return errors.New("invalid verifier type")
	}
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

func (r *RestReaderConfig) Validate(index int) error {
	if r.BaseURL == "" {
		return fmt.Errorf("verifier %d base url is required", index)
	}

	if r.RequestTimeout <= 0 {
		return fmt.Errorf("verifier %d request timeout must be greater than 0", index)
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
