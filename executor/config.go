package executor

import (
	"fmt"
	"net/url"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/pkg/monitoring"
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
	IndexerQueryLimitMax     = 10000
)

type ConfigWithBlockchainInfo[T any] struct {
	Configuration
	BlockchainInfos chainaccess.Infos[T] `toml:"blockchain_infos"`
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
	// ReaderCacheExpiry is the duration for the curse checker cache (RMN cursed state per chain).
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
	// DestinationChainConfig holds the off-ramp and RMN addresses. It is embedded so that the
	// TOML field paths (off_ramp_address, rmn_address) are identical to what the chainaccess
	// Registry reads via ExecutorConfig, allowing both to overlay the same config file.
	chainaccess.DestinationChainConfig
	// ExecutorPool is the list of executor IDs used for turn taking. This executor's ID must be in the list.
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

	if len(c.IndexerAddress) < 1 {
		return fmt.Errorf("at least one indexer address must be configured")
	}
	seen := make(map[string]struct{}, len(c.IndexerAddress))
	for _, addr := range c.IndexerAddress {
		u, err := url.Parse(addr)
		if err != nil {
			return fmt.Errorf("invalid indexer URL %q: %w", addr, err)
		}
		if u.Scheme == "" || u.Host == "" {
			return fmt.Errorf("indexer URL %q must have a scheme and host", addr)
		}
		if _, ok := seen[addr]; ok {
			return fmt.Errorf("duplicate indexer address: %q", addr)
		}
		seen[addr] = struct{}{}
	}

	if c.WorkerCount < 0 {
		return fmt.Errorf("worker_count must not be negative, got %d", c.WorkerCount)
	}
	if c.BackoffDuration < 0 {
		return fmt.Errorf("source_backoff_duration must not be negative")
	}
	if c.LookbackWindow < 0 {
		return fmt.Errorf("startup_lookback_window must not be negative")
	}
	if c.ReaderCacheExpiry < 0 {
		return fmt.Errorf("reader_cache_expiry must not be negative")
	}
	if c.MaxRetryDuration < 0 {
		return fmt.Errorf("max_retry_duration must not be negative")
	}
	if c.IndexerQueryLimit > IndexerQueryLimitMax {
		return fmt.Errorf("indexer_query_limit must not exceed %d, got %d", IndexerQueryLimitMax, c.IndexerQueryLimit)
	}

	if err := c.Monitoring.Validate(); err != nil {
		return fmt.Errorf("monitoring config validation failed: %w", err)
	}

	for chainSel, chainConfig := range c.ChainConfiguration {
		if chainConfig.RmnAddress == "" {
			return fmt.Errorf("rmn_address must be configured for chain %s", chainSel)
		}
		if chainConfig.OffRampAddress == "" {
			return fmt.Errorf("off_ramp_address must be configured for chain %s", chainSel)
		}
		if chainConfig.DefaultExecutorAddress == "" {
			return fmt.Errorf("default_executor_address must be configured for chain %s", chainSel)
		}
		if chainConfig.ExecutionInterval < 0 {
			return fmt.Errorf("execution_interval must not be negative for chain %s", chainSel)
		}
		if len(chainConfig.ExecutorPool) == 0 {
			return fmt.Errorf("executor_pool must be configured for chain %s", chainSel)
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

// Type aliases — canonical definitions live in pkg/monitoring.
type (
	MonitoringConfig = monitoring.Config
	BeholderConfig   = monitoring.BeholderConfig
)
