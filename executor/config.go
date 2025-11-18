package executor

import (
	"fmt"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

type Configuration struct {
	// BlockchainInfos is a map of chain selector to RPC information for chain interactions.
	BlockchainInfos map[string]*protocol.BlockchainInfo `toml:"blockchain_infos"`
	// IndexerAddress is the URL of the indexer to receive messages + verifications from.
	IndexerAddress string `toml:"indexer_address"`
	// PollingInterval is the interval to poll the Indexer for messages.
	// todo: Remove polling interval from config, we should only use a 1s interval.
	PollingInterval string `toml:"source_polling_interval"`
	// BackoffDuration is the duration to back off after a failed request to the Indexer.
	// Defaults to 15 seconds.
	BackoffDuration string `toml:"source_backoff_duration"`
	// LookbackWindow is the window of time to look back for new messages when an Executor first starts up.
	// Defaults to 1 hour.
	LookbackWindow string `toml:"startup_lookback_window"`
	// IndexerQueryLimit is the maximum number of messages to query from the Indexer at once.
	// Defaults to 100.
	IndexerQueryLimit uint64 `toml:"indexer_query_limit"`
	// PyroscopeURL is the URL of the Pyroscope server to send metrics to.
	PyroscopeURL string `toml:"pyroscope_url"`
	// OffRampAddresses is a map of chain selector to offramp address for chain interactions.
	OffRampAddresses map[string]string `toml:"offramp_addresses"`
	// ExecutorPool is a list of executor IDs used for turn taking.
	// TODO: update this to enable a different pool per destination chain.
	ExecutorPool []string `toml:"executor_pool"`
	// ExecutorID is the ID of this executor. This executorID should be present in the executor pool.
	ExecutorID string `toml:"executor_id"`
	// ExecutionInterval is how long each executor has to process a message before the next executor in the cluster takes over.
	// Defaults to 30 seconds.
	ExecutionInterval string `toml:"execution_interval"`
	// MinWait is the minimum wait time before the first executor in the turn taking pool begins processing a message.
	// Defaults to 10 seconds.
	MinWait string `toml:"min_wait"`
	// Monitoring is the configuration for how Executor emits metrics.
	Monitoring MonitoringConfig `toml:"Monitoring"`
	// CcvInfoCacheExpiry is the duration to cache CCV information for each destination chain.
	// Cached information includes the Verifier Quorum per receiver address.
	// Defaults to 5 minutes.
	CcvInfoCacheExpiry string `toml:"ccv_info_cache_expiry"`
	// MaxRetryDuration is the maximum duration the executor cluster will retry a message before giving up.
	// Defaults to 8 hours.
	MaxRetryDuration string `toml:"max_retry_duration"`
}

func (c *Configuration) Validate() error {
	if len(c.BlockchainInfos) == 0 {
		return fmt.Errorf("no destination chains configured to read from")
	}
	if len(c.ExecutorPool) == 0 {
		return fmt.Errorf("executor_ids must be configured")
	}
	if c.ExecutorID == "" {
		return fmt.Errorf("this_executor_id must be configured")
	}

	// Check that this executor's ID is in the list of executor IDs
	found := false
	for _, id := range c.ExecutorPool {
		if id == c.ExecutorID {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("this_executor_id '%s' not found in executor_ids list", c.ExecutorID)
	}

	return nil
}

// TODO: update all these config getters to use a time.Duration, applyDefaults, and define constants
func (c *Configuration) GetBackoffDuration() time.Duration {
	d, err := time.ParseDuration(c.BackoffDuration)
	if err != nil {
		return 15 * time.Second
	}
	return d
}

func (c *Configuration) GetPollingInterval() time.Duration {
	d, err := time.ParseDuration(c.PollingInterval)
	if err != nil {
		return 1 * time.Second
	}
	return d
}

func (c *Configuration) GetIndexerQueryLimit() uint64 {
	limit := c.IndexerQueryLimit
	if limit == 0 {
		return 100
	}
	return limit
}

func (c *Configuration) GetLookbackWindow() time.Duration {
	d, err := time.ParseDuration(c.LookbackWindow)
	if err != nil {
		return 1 * time.Hour
	}
	return d
}

func (c *Configuration) GetExecutionInterval() time.Duration {
	d, err := time.ParseDuration(c.ExecutionInterval)
	if err != nil {
		return 30 * time.Second
	}
	return d
}

func (c *Configuration) GetMinWaitPeriod() time.Duration {
	d, err := time.ParseDuration(c.MinWait)
	if err != nil {
		return 10 * time.Second
	}
	return d
}

func (c *Configuration) GetMaxRetryDuration() time.Duration {
	d, err := time.ParseDuration(c.MaxRetryDuration)
	if err != nil {
		return 8 * time.Hour
	}
	return d
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

func (c *Configuration) GetCCVInfoCacheExpiry() time.Duration {
	d, err := time.ParseDuration(c.CcvInfoCacheExpiry)
	if err != nil {
		return 5 * time.Minute
	}
	return d
}
