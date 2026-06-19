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

// AggregatorConnection describes a single aggregator the verifier writes to, sends
// heartbeats to, and reads message-disablement rules from. A consolidated verifier job
// carries one of these per aggregator in Config.Aggregators.
type AggregatorConnection struct {
	// Name is an optional human-readable label used in logs and metric labels.
	// When empty it defaults to Address.
	Name string `toml:"name"`
	// Address is the aggregator gRPC endpoint (host:port). Required.
	Address string `toml:"address"`
	// InsecureConnection disables TLS for this aggregator's gRPC connection.
	// Only use this for testing when custom certificates cannot be injected.
	InsecureConnection bool `toml:"insecure_connection"`
	// MaxSendMsgSizeBytes is the maximum gRPC message size for sending requests to this
	// aggregator. The batch-splitting logic uses this to keep outgoing batches under the
	// limit. If 0 or not set, defaults to 4MB.
	MaxSendMsgSizeBytes int `toml:"max_send_msg_size_bytes"`
	// MaxRecvMsgSizeBytes is the maximum gRPC message size for receiving responses from
	// this aggregator. If 0 or not set, defaults to 4MB.
	MaxRecvMsgSizeBytes int `toml:"max_recv_msg_size_bytes"`
}

// Label returns the value used to identify this aggregator in logs and metrics:
// Name when set, otherwise Address.
func (a AggregatorConnection) Label() string {
	if strings.TrimSpace(a.Name) != "" {
		return a.Name
	}
	return a.Address
}

type Config struct {
	VerifierID string `toml:"verifier_id"`
	// AggregatorAddress configures a single aggregator. DEPRECATED in favor of Aggregators;
	// retained for backwards compatibility. It is mutually exclusive with Aggregators: setting
	// both is a configuration error. When Aggregators is empty, this address (together with the
	// legacy InsecureAggregatorConnection and AggregatorMax*MsgSizeBytes fields) is used to
	// synthesize a single-aggregator connection.
	AggregatorAddress string `toml:"aggregator_address"`
	// Aggregators is the list of aggregators a consolidated verifier job writes to. When
	// non-empty it is authoritative and the legacy AggregatorAddress field must be empty.
	Aggregators []AggregatorConnection `toml:"aggregators"`
	// InsecureAggregatorConnection disables TLS for the aggregator gRPC connection.
	// DEPRECATED: only applies to the legacy AggregatorAddress path; use
	// AggregatorConnection.InsecureConnection with Aggregators instead.
	// Only use this for testing when custom certificates cannot be injected.
	InsecureAggregatorConnection bool `toml:"insecure_aggregator_connection"`
	// AggregatorMaxSendMsgSizeBytes is the maximum gRPC message size for sending requests to the aggregator.
	// The batch-splitting logic uses this value to ensure outgoing batches don't exceed this limit.
	// Should match or be less than the aggregator's server maxRecvMsgSizeBytes setting.
	// If 0 or not set, defaults to 4MB.
	// DEPRECATED: only applies to the legacy AggregatorAddress path.
	AggregatorMaxSendMsgSizeBytes int `toml:"aggregator_max_send_msg_size_bytes"`
	// AggregatorMaxRecvMsgSizeBytes is the maximum gRPC message size for receiving responses from the aggregator.
	// Should match or be less than the aggregator's server maxSendMsgSizeBytes setting.
	// If 0 or not set, defaults to 4MB.
	// DEPRECATED: only applies to the legacy AggregatorAddress path.
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

// ResolvedAggregators returns the effective list of aggregators for this config, applying
// backwards-compatible fallback to the legacy single-aggregator fields.
//
// Precedence:
//   - If Aggregators is non-empty it is authoritative; setting the legacy AggregatorAddress
//     as well is an error (no silent ambiguity).
//   - If Aggregators is empty and AggregatorAddress is set, a single AggregatorConnection is
//     synthesized from the legacy AggregatorAddress / InsecureAggregatorConnection /
//     AggregatorMax*MsgSizeBytes fields.
//   - If neither is set, it is an error: at least one aggregator must be configured.
//
// The returned connections have Name defaulted to Address when unset. Message-size defaults
// (0 -> 4MB) are intentionally left to the aggregator writer constructor.
func (c *Config) ResolvedAggregators() ([]AggregatorConnection, error) {
	legacySet := strings.TrimSpace(c.AggregatorAddress) != ""
	listSet := len(c.Aggregators) > 0

	switch {
	case legacySet && listSet:
		return nil, fmt.Errorf("invalid verifier configuration: both aggregator_address and aggregators are set; " +
			"aggregator_address is deprecated, use only one")
	case !legacySet && !listSet:
		return nil, fmt.Errorf("invalid verifier configuration: no aggregator configured; set aggregators (or the deprecated aggregator_address)")
	}

	var resolved []AggregatorConnection
	if listSet {
		resolved = make([]AggregatorConnection, len(c.Aggregators))
		copy(resolved, c.Aggregators)
	} else {
		resolved = []AggregatorConnection{{
			Address:             c.AggregatorAddress,
			InsecureConnection:  c.InsecureAggregatorConnection,
			MaxSendMsgSizeBytes: c.AggregatorMaxSendMsgSizeBytes,
			MaxRecvMsgSizeBytes: c.AggregatorMaxRecvMsgSizeBytes,
		}}
	}

	seen := make(map[string]struct{}, len(resolved))
	for i := range resolved {
		addr := strings.TrimSpace(resolved[i].Address)
		if addr == "" {
			return nil, fmt.Errorf("invalid verifier configuration: aggregator at index %d has an empty address", i)
		}
		if _, dup := seen[addr]; dup {
			return nil, fmt.Errorf("invalid verifier configuration: duplicate aggregator address %q", addr)
		}
		seen[addr] = struct{}{}
		resolved[i].Name = resolved[i].Label()
	}

	return resolved, nil
}

func (c *Config) Validate() error {
	// Only validate aggregator wiring when something is configured. A config with neither
	// aggregator_address nor aggregators set has always passed Validate (the gRPC client is
	// created lazily), so we keep that lenient behavior; the strict "at least one aggregator"
	// requirement is enforced by ResolvedAggregators on the startup path.
	if strings.TrimSpace(c.AggregatorAddress) != "" || len(c.Aggregators) > 0 {
		if _, err := c.ResolvedAggregators(); err != nil {
			return err
		}
	}

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
