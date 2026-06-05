package commit

import (
	"fmt"
	"strings"
	"time"

	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	verifier "github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vtypes"
)

// DefaultECDSASigningKeyName is the keystore key name for the ECDSA key used to sign verification results.
const DefaultECDSASigningKeyName = "bootstrap_default_ecdsa_signing_key"

type Config struct {
	VerifierID        string `toml:"verifier_id"`
	AggregatorAddress string `toml:"aggregator_address"`
	// InsecureAggregatorConnection disables TLS for the aggregator gRPC connection.
	// Only use this for testing when custom certificates cannot be injected.
	InsecureAggregatorConnection bool `toml:"insecure_aggregator_connection"`
	// AggregatorMaxSendMsgSizeBytes is the maximum gRPC message size for sending requests to the aggregator.
	// The batch-splitting logic uses this value to ensure outgoing batches don't exceed this limit.
	// Should match or be less than the aggregator's server maxRecvMsgSizeBytes setting.
	// If 0 or not set, defaults to 4MB.
	AggregatorMaxSendMsgSizeBytes int `toml:"aggregator_max_send_msg_size_bytes"`
	// AggregatorMaxRecvMsgSizeBytes is the maximum gRPC message size for receiving responses from the aggregator.
	// Should match or be less than the aggregator's server maxSendMsgSizeBytes setting.
	// If 0 or not set, defaults to 4MB.
	AggregatorMaxRecvMsgSizeBytes int `toml:"aggregator_max_recv_msg_size_bytes"`

	// MessageDisablementRulesPollInterval and MessageDisablementRulesClientTimeout are Go duration strings
	// (e.g. "2s", "500ms"). Empty means use the integration package default for that setting.
	//
	// They are stored as strings (not time.Duration) because the Chainlink node unmarshals
	// committeeVerifierConfig with github.com/pelletier/go-toml, which does not decode TOML
	// duration strings into time.Duration. Standalone / devenv decoding uses github.com/BurntSushi/toml,
	// which does support time.Duration; using string keeps both paths and changeset marshaling compatible.
	MessageDisablementRulesPollInterval  string `toml:"message_disablement_rules_poll_interval"`
	MessageDisablementRulesClientTimeout string `toml:"message_disablement_rules_client_timeout"`

	SignerAddress string `toml:"signer_address"`

	PyroscopeURL string `toml:"pyroscope_url"`
	// CommitteeVerifierAddresses is a map the addresses of the committee verifiers for each chain selector.
	CommitteeVerifierAddresses map[string]string `toml:"committee_verifier_addresses"`
	// DefaultExecutorOnRampAddresses is a map the addresses of the default executor on ramps for each chain selector.
	// The committee verifier will verify messages that specify the default executor even if they don't
	// specify the committee verifier.
	DefaultExecutorOnRampAddresses map[string]string `toml:"default_executor_on_ramp_addresses"`
	// DisableFinalityCheckers is a list of chain selectors for which the finality violation checker should be disabled.
	// The chain selectors are formatted as strings of the chain selector.
	DisableFinalityCheckers []string                  `toml:"disable_finality_checkers"`
	Monitoring              verifier.MonitoringConfig `toml:"monitoring"`

	// CommitteeConfig that is needed by the SourceReader and the application.
	chainaccess.CommitteeConfig
}

func parseOptionalDurationString(value, fieldName string) (time.Duration, error) {
	s := strings.TrimSpace(value)
	if s == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid %s %q: %w", fieldName, value, err)
	}
	return d, nil
}

// MessageDisablementRulesPollIntervalDuration returns the configured poll interval, or zero to use the integration default.
func (c *Config) MessageDisablementRulesPollIntervalDuration() (time.Duration, error) {
	return parseOptionalDurationString(c.MessageDisablementRulesPollInterval, "message_disablement_rules_poll_interval")
}

// MessageDisablementRulesClientTimeoutDuration returns the configured RPC timeout, or zero to use the integration default.
func (c *Config) MessageDisablementRulesClientTimeoutDuration() (time.Duration, error) {
	return parseOptionalDurationString(c.MessageDisablementRulesClientTimeout, "message_disablement_rules_client_timeout")
}

func (c *Config) Validate() error {
	// Compare map lengths first
	if len(c.OnRampAddresses) != len(c.CommitteeVerifierAddresses) ||
		len(c.OnRampAddresses) != len(c.RMNRemoteAddresses) {
		return fmt.Errorf(
			"invalid verifier configuration, mismatched lengths for onramp (%d), committee verifier (%d), and RMN Remote addresses (%d)",
			len(c.OnRampAddresses),
			len(c.CommitteeVerifierAddresses),
			len(c.RMNRemoteAddresses),
		)
	}

	// Compare map keys (they should all be equal)
	// Since lengths are equal, checking if all keys from one map exist in the others is sufficient.
	for k := range c.OnRampAddresses {
		if _, ok := c.CommitteeVerifierAddresses[k]; !ok {
			return fmt.Errorf("invalid verifier configuration, chain selector in onramp (%s) not in committee verifier addresses", k)
		}
		if _, ok := c.RMNRemoteAddresses[k]; !ok {
			return fmt.Errorf("invalid verifier configuration, chain selector in onramp (%s) not in RMN Remote addresses", k)
		}
	}

	if _, err := c.MessageDisablementRulesPollIntervalDuration(); err != nil {
		return err
	}
	if _, err := c.MessageDisablementRulesClientTimeoutDuration(); err != nil {
		return err
	}

	return nil
}
