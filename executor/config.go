package executor

import (
	"fmt"
	"slices"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/integration/pkg/blockchain"
)

const (
	backoffDurationDefault   = 15 * time.Second
	lookbackWindowDefault    = 1 * time.Hour
	readerCacheExpiryDefault = 5 * time.Minute
	maxRetryDurationDefault  = 8 * time.Hour
	executionIntervalDefault = 1 * time.Minute
	ntpServerDefault         = "time.google.com"
	workerCountDefault       = 100
	IndexerQueryLimitDefault = 100
)

type ConfigWithBlockchainInfo struct {
	Configuration
	BlockchainInfos map[string]*blockchain.Info `toml:"blockchain_infos"`
}

// Configuration is the complete set of information an executor needs to operate normally.
// We can use time.Duration directly in this config because burntSushi can parse duration from strings.
type Configuration struct {
	// IndexerAddress is the list of indexer URLs to receive messages + verifications from.
	// The executor will use these for failover if one indexer becomes unavailable.
	IndexerAddress []string `toml:"indexer_address"`
	// BackoffDuration is the duration to back off after a failed request to the Indexer.
	// Defaults to 15 seconds.
	BackoffDuration time.Duration `toml:"source_backoff_duration"`
	// LookbackWindow is the window of time to look back for new messages when an Executor first starts up.
	// Defaults to 1 hour.
	LookbackWindow time.Duration `toml:"startup_lookback_window"`
	// IndexerQueryLimit is the maximum number of messages to query from the Indexer at once.
	// Defaults to 100.
	IndexerQueryLimit uint64 `toml:"indexer_query_limit"`
	// PyroscopeURL is the URL of the Pyroscope server to send metrics to.
	PyroscopeURL string `toml:"pyroscope_url"`
	// ExecutorID is the ID of this executor. This executorID should be present in the executor pool.
	ExecutorID string `toml:"executor_id"`
	// Monitoring is the configuration for how Executor emits metrics.
	Monitoring MonitoringConfig `toml:"Monitoring"`
	// ReaderCacheExpiry is the duration to cache CCV information for each destination chain.
	// Cached information includes the Verifier Quorum per receiver address.
	// Defaults to 5 minutes.
	ReaderCacheExpiry time.Duration `toml:"reader_cache_expiry"`
	// MaxRetryDuration is the maximum duration the executor cluster will retry a message before giving up.
	// Defaults to 8 hours.
	MaxRetryDuration time.Duration `toml:"max_retry_duration"`
	// NtpServer is the NTP server to use for time synchronization.
	// Defaults to time.google.com
	NtpServer string `toml:"ntp_server"`
	// ChainConfiguration is a map of chain selector to chain configuration.
	// This is used to configure the chain-specific configuration for each chain such as addresses, executor pool, and execution interval.
	ChainConfiguration map[string]ChainConfiguration `toml:"chain_configuration"`
	WorkerCount        int                           `toml:"worker_count"`
}

// ChainConfiguration is all the configuration an executor needs to know about a specific chain.
// This is separate from chain-specific RPC information in BlockchainInfos.
type ChainConfiguration struct {
	// RMN address is the address of the RMN contract to check for curse state.
	RmnAddress string `toml:"rmn_address"`
	// OffRamp address is the address of the offramp contract to send messages to.
	OffRampAddress string `toml:"off_ramp_address"`
	// Executor pool is the list of executor IDs used for turn taking. This executor's ID must be in the list.
	ExecutorPool []string `toml:"executor_pool"`
	// ExecutionInterval is how long each executor has to process a message before the next executor in the cluster takes over.
	ExecutionInterval time.Duration `toml:"execution_interval"`
	// DefaultExecutorAddress is the address of the default executor to check against the message receipts.
	DefaultExecutorAddress string `toml:"default_executor_address"`
}

func (c *Configuration) Validate() error {
	if c.ExecutorID == "" {
		return fmt.Errorf("this_executor_id must be configured")
	}

	if len(c.ChainConfiguration) == 0 {
		return fmt.Errorf("at least one chain must be configured")
	}

	// Validate indexer addresses - at least one must be provided
	if len(c.IndexerAddress) < 1 {
		return fmt.Errorf("at least one indexer address must be configured")
	}

	for chainSel, chainConfig := range c.ChainConfiguration {
		// can ignore nil check because len of nil slice is 0.
		if len(chainConfig.ExecutorPool) == 0 {
			return fmt.Errorf("executor_pool must be configured for chain %s", chainSel)
		}
		if !slices.Contains(chainConfig.ExecutorPool, c.ExecutorID) {
			return fmt.Errorf("this_executor_id '%s' not found in executor_pool for chain %s", c.ExecutorID, chainSel)
		}
	}

	return nil
}

// GetNormalizedConfig validates the configuration and applies defaults.
// It returns a copy of the Configuration where durations are parsed and defaults filled in as necessary.
func (c *Configuration) GetNormalizedConfig() (*Configuration, error) {
	normalized := *c // shallow copy

	// Validate first using the current Validate method.
	if err := normalized.Validate(); err != nil {
		return nil, err
	}

	if c.NtpServer == "" {
		normalized.NtpServer = ntpServerDefault
	}

	// Set default durations if missing or invalid.
	parseOrDefault := func(raw, defaultVal time.Duration) time.Duration {
		if raw == 0 {
			return defaultVal
		}
		return raw
	}

	// Copy base fields with defaults applied.
	normalized.BackoffDuration = parseOrDefault(c.BackoffDuration, backoffDurationDefault)
	normalized.LookbackWindow = parseOrDefault(c.LookbackWindow, lookbackWindowDefault)
	normalized.ReaderCacheExpiry = parseOrDefault(c.ReaderCacheExpiry, readerCacheExpiryDefault)
	normalized.MaxRetryDuration = parseOrDefault(c.MaxRetryDuration, maxRetryDurationDefault)
	if c.IndexerQueryLimit == 0 {
		normalized.IndexerQueryLimit = IndexerQueryLimitDefault
	}
	if c.WorkerCount == 0 {
		normalized.WorkerCount = workerCountDefault
	}

	// Process per-chain configuration: parse and normalize durations
	chainConfigs := make(map[string]ChainConfiguration, len(c.ChainConfiguration))
	for chainSel, updatedChain := range c.ChainConfiguration {
		updatedChain.ExecutionInterval = parseOrDefault(updatedChain.ExecutionInterval, executionIntervalDefault)
		chainConfigs[chainSel] = updatedChain
	}
	normalized.ChainConfiguration = chainConfigs

	return &normalized, nil
}

// MonitoringConfig provides monitoring configuration for executor.
type MonitoringConfig struct {
	// Enabled enables the monitoring system.
	Enabled bool `toml:"Enabled"`
	// Type is the type of monitoring system to use (beholder, noop).
	Type string `toml:"Type"`
	// Beholder is the configuration for the beholder client (Not required if type is noop).
	Beholder BeholderConfig `toml:"Beholder"`
}

// BeholderConfig wraps OpenTelemetry configuration for the beholder client.
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

// Validate performs validation on the monitoring configuration.
func (m *MonitoringConfig) Validate() error {
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
