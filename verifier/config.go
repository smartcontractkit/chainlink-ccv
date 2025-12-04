package verifier

import (
	"fmt"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

type ConfigWithBlockchainInfos struct {
	Config
	BlockchainInfos map[string]*protocol.BlockchainInfo `toml:"blockchain_infos"`
}

type Config struct {
	VerifierID        string `toml:"verifier_id"`
	AggregatorAddress string `toml:"aggregator_address"`

	SignerAddress string `toml:"signer_address"`

	PyroscopeURL string `toml:"pyroscope_url"`
	// ChainStatusDBPath is the path to the SQLite database for persisting chain status.
	// If empty, chain status will default to "chain_status.db"
	ChainStatusDBPath string `toml:"chain_status_db_path"`
	// CommitteeVerifierAddresses is a map the addresses of the committee verifiers for each chain selector.
	CommitteeVerifierAddresses map[string]string `toml:"committee_verifier_addresses"`
	// OnRampAddresses is a map the addresses of the on ramps for each chain selector.
	OnRampAddresses map[string]string `toml:"on_ramp_addresses"`
	// DefaultExecutorOnRampAddresses is a map the addresses of the default executor on ramps for each chain selector.
	// The committee verifier will verify messages that specify the default executor even if they don't
	// specify the committee verifier.
	DefaultExecutorOnRampAddresses map[string]string `toml:"default_executor_on_ramp_addresses"`
	// RMNRemoteAddresses is a map of RMN Remote contract addresses for each chain selector.
	// Required for curse detection.
	RMNRemoteAddresses map[string]string `toml:"rmn_remote_addresses"`
	Monitoring         MonitoringConfig  `toml:"monitoring"`
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

func (c *Config) Validate() error {
	// Collect chain selectors as sets (map[string]struct{})
	onRampSet := make(map[string]struct{})
	for k := range c.OnRampAddresses {
		onRampSet[k] = struct{}{}
	}
	committeeVerifierSet := make(map[string]struct{})
	for k := range c.CommitteeVerifierAddresses {
		committeeVerifierSet[k] = struct{}{}
	}
	rmnRemoteSet := make(map[string]struct{})
	for k := range c.RMNRemoteAddresses {
		rmnRemoteSet[k] = struct{}{}
	}

	// Compare set lengths first
	if len(onRampSet) != len(committeeVerifierSet) ||
		len(onRampSet) != len(rmnRemoteSet) {
		return fmt.Errorf("invalid verifier configuration, mismatched chain selectors for onramp, committee verifier, and RMN Remote addresses")
	}

	// Compare set values (they should all be equal)
	for k := range onRampSet {
		if _, ok := committeeVerifierSet[k]; !ok {
			return fmt.Errorf("invalid verifier configuration, chain selector in onramp (%s) not in committee verifier addresses", k)
		}
		if _, ok := rmnRemoteSet[k]; !ok {
			return fmt.Errorf("invalid verifier configuration, chain selector in onramp (%s) not in RMN Remote addresses", k)
		}
	}
	for k := range committeeVerifierSet {
		if _, ok := onRampSet[k]; !ok {
			return fmt.Errorf("invalid verifier configuration, chain selector in committee verifier (%s) not in onramp addresses", k)
		}
		if _, ok := rmnRemoteSet[k]; !ok {
			return fmt.Errorf("invalid verifier configuration, chain selector in committee verifier (%s) not in RMN Remote addresses", k)
		}
	}
	for k := range rmnRemoteSet {
		if _, ok := onRampSet[k]; !ok {
			return fmt.Errorf("invalid verifier configuration, chain selector in RMN Remote (%s) not in onramp addresses", k)
		}
		if _, ok := committeeVerifierSet[k]; !ok {
			return fmt.Errorf("invalid verifier configuration, chain selector in RMN Remote (%s) not in committee verifier addresses", k)
		}
	}

	return nil
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
