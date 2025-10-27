package executor

import (
	"fmt"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

type Configuration struct {
	BlockchainInfos    map[string]*protocol.BlockchainInfo `toml:"blockchain_infos"`
	IndexerAddress     string                              `toml:"indexer_address"`
	PollingInterval    string                              `toml:"source_polling_interval"`
	BackoffDuration    string                              `toml:"source_backoff_duration"`
	LookbackWindow     string                              `toml:"startup_lookback_window"`
	IndexerQueryLimit  uint64                              `toml:"indexer_query_limit"`
	PyroscopeURL       string                              `toml:"pyroscope_url"`
	OffRampAddresses   map[string]string                   `toml:"offramp_addresses"`
	ExecutorAddresses  map[string]string                   `toml:"executor_addresses"`
	ExecutorPool       []string                            `toml:"executor_pool"`
	ExecutorID         string                              `toml:"executor_id"`
	ExecutionInterval  string                              `toml:"execution_interval"`
	MinWait            string                              `toml:"min_wait"`
	Monitoring         MonitoringConfig                    `toml:"Monitoring"`
	CcvInfoCacheExpiry string                              `toml:"ccv_info_cache_expiry"`
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
		return 5 * time.Second
	}
	return d
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
