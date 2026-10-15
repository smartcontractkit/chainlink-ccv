package verifier

import (
	"fmt"

	"github.com/BurntSushi/toml"

	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/commit"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/policy"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/token/cctp"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/token/lombard"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/vtypes"
)

// Verifier entry types the unified verifier binary supports in [[verifiers]].
const (
	VerifierTypeCommittee = "committee"
	VerifierTypeCCTP      = "cctp"
	VerifierTypeLombard   = "lombard"
)

// unifiedHTTPListenPortMax mirrors commit's unexported httpListenPortMax: reject an invalid port
// at validation time instead of failing the listener bind in the HTTP server goroutine.
const unifiedHTTPListenPortMax = 65535

// UnifiedConfig is the app config of the unified verifier binary: service-level shared fields
// plus a [[verifiers]] list mixing at most one committee entry with any number of token
// (cctp/lombard) entries. Chain addresses (on_ramp_addresses) are shared by all entries.
type UnifiedConfig struct {
	// PyroscopeURL is the Pyroscope server URL for continuous profiling; empty disables it.
	PyroscopeURL string `toml:"pyroscope_url"`
	// HTTPListenPort is the port the verifier's HTTP server listens on. Defaults to 8100.
	HTTPListenPort int `toml:"http_listen_port,omitempty"`
	// DisableFinalityCheckers lists chain selectors, as strings, whose finality violation
	// checker is disabled. Mirrors commit.Config.DisableFinalityCheckers.
	DisableFinalityCheckers []string `toml:"disable_finality_checkers"`
	// Monitoring is consumed in local app-config mode; see token.Config.Monitoring.
	Monitoring vtypes.MonitoringConfig `toml:"monitoring"`
	// Verifiers is the list of verifier instances to run in this process.
	Verifiers []Entry `toml:"verifiers"`

	// CommitteeConfig carries the shared chain addresses needed by the SourceReaders.
	chainaccess.CommitteeConfig
}

// Entry is one [[verifiers]] entry. Exactly one flavor config is set, selected by Type.
// Flavor configs are embedded pointers (the token.VerifierConfig idiom) so TOML marshal/unmarshal
// is symmetric: their fields serialize inline next to type/verifier_id/version.
type Entry struct {
	Type       string `toml:"type"`
	VerifierID string `toml:"verifier_id"`
	Version    string `toml:"version,omitempty"` // token verifiers only

	*CommitteeEntryConfig
	*cctp.CCTPConfig
	*lombard.LombardConfig
}

// IsCCTP reports whether the entry is a CCTP token verifier.
func (e *Entry) IsCCTP() bool { return e.CCTPConfig != nil }

// IsLombard reports whether the entry is a Lombard token verifier.
func (e *Entry) IsLombard() bool { return e.LombardConfig != nil }

// IsCommittee reports whether the entry is a committee verifier.
func (e *Entry) IsCommittee() bool { return e.CommitteeEntryConfig != nil }

// UnmarshalTOML mirrors token.VerifierConfig.UnmarshalTOML: type and verifier_id are required;
// a committee entry decodes into CommitteeEntryConfig, anything else is dispatched to
// cctp.TryParsing / lombard.TryParsing (which also require version).
func (e *Entry) UnmarshalTOML(data any) error {
	castedData, ok := data.(map[string]any)
	if !ok {
		return fmt.Errorf("expected map[string]any, got %T", data)
	}

	e.VerifierID, ok = castedData["verifier_id"].(string)
	if !ok {
		return fmt.Errorf("verifier_id field is required for Entry")
	}

	e.Type, ok = castedData["type"].(string)
	if !ok {
		return fmt.Errorf("type field is required for Entry")
	}

	if e.Type == VerifierTypeCommittee {
		// The committee entry is a struct with TOML tags rather than a hand-parsed map, so
		// re-encode the entry map and decode it; unknown keys (type, verifier_id) are ignored.
		raw, err := toml.Marshal(castedData)
		if err != nil {
			return fmt.Errorf("failed to re-encode committee verifier entry: %w", err)
		}
		var committeeCfg CommitteeEntryConfig
		if err := toml.Unmarshal(raw, &committeeCfg); err != nil {
			return fmt.Errorf("failed to decode committee verifier entry: %w", err)
		}
		e.CommitteeEntryConfig = &committeeCfg
		return nil
	}

	e.Version, ok = castedData["version"].(string)
	if !ok {
		return fmt.Errorf("version field is required for Entry")
	}

	var err error
	e.CCTPConfig, err = cctp.TryParsing(e.Type, e.Version, castedData)
	if err == nil {
		return nil
	}

	e.LombardConfig, err = lombard.TryParsing(e.Type, e.Version, castedData)
	if err == nil {
		return nil
	}

	return fmt.Errorf("unsupported verifier type %s and version %s", e.Type, e.Version)
}

// CommitteeEntryConfig carries the committee-specific fields of a [[verifiers]] entry, with the
// same TOML tags as commit.Config. Shared fields (on_ramp_addresses, disable_finality_checkers,
// pyroscope_url, http_listen_port, monitoring) live on UnifiedConfig.
type CommitteeEntryConfig struct {
	AggregatorAddress                    string                        `toml:"aggregator_address"`
	Aggregators                          []commit.AggregatorConnection `toml:"aggregators"`
	InsecureAggregatorConnection         bool                          `toml:"insecure_aggregator_connection"`
	AggregatorMaxSendMsgSizeBytes        int                           `toml:"aggregator_max_send_msg_size_bytes"`
	AggregatorMaxRecvMsgSizeBytes        int                           `toml:"aggregator_max_recv_msg_size_bytes"`
	SignerAddress                        string                        `toml:"signer_address"`
	CommitteeVerifierAddresses           map[string]string             `toml:"committee_verifier_addresses"`
	DefaultExecutorOnRampAddresses       map[string]string             `toml:"default_executor_on_ramp_addresses"`
	MessageDisablementRulesPollInterval  string                        `toml:"message_disablement_rules_poll_interval"`
	MessageDisablementRulesClientTimeout string                        `toml:"message_disablement_rules_client_timeout"`
	PolicyHook                           *policy.Config                `toml:"policy_hook,omitempty"`
}

// ToCommitConfig builds the commit.Config for this entry, filling the shared fields from the
// service-level config, so commit.Config.Validate and ResolvedAggregators are reused unchanged.
// The caller sets VerifierID from the entry.
func (c *CommitteeEntryConfig) ToCommitConfig(shared UnifiedConfig) commit.Config {
	return commit.Config{
		AggregatorAddress:                    c.AggregatorAddress,
		Aggregators:                          c.Aggregators,
		InsecureAggregatorConnection:         c.InsecureAggregatorConnection,
		AggregatorMaxSendMsgSizeBytes:        c.AggregatorMaxSendMsgSizeBytes,
		AggregatorMaxRecvMsgSizeBytes:        c.AggregatorMaxRecvMsgSizeBytes,
		MessageDisablementRulesPollInterval:  c.MessageDisablementRulesPollInterval,
		MessageDisablementRulesClientTimeout: c.MessageDisablementRulesClientTimeout,
		SignerAddress:                        c.SignerAddress,
		PyroscopeURL:                         shared.PyroscopeURL,
		HTTPListenPort:                       shared.HTTPListenPort,
		CommitteeVerifierAddresses:           c.CommitteeVerifierAddresses,
		DefaultExecutorOnRampAddresses:       c.DefaultExecutorOnRampAddresses,
		DisableFinalityCheckers:              shared.DisableFinalityCheckers,
		Monitoring:                           shared.Monitoring,
		PolicyHook:                           c.PolicyHook,
		CommitteeConfig:                      shared.CommitteeConfig,
	}
}

// HasCommittee reports whether the config contains a committee entry.
func (c *UnifiedConfig) HasCommittee() bool {
	for i := range c.Verifiers {
		if c.Verifiers[i].Type == VerifierTypeCommittee {
			return true
		}
	}
	return false
}

// HasTokenVerifiers reports whether the config contains any token (cctp/lombard) entry.
func (c *UnifiedConfig) HasTokenVerifiers() bool {
	for i := range c.Verifiers {
		if c.Verifiers[i].IsCCTP() || c.Verifiers[i].IsLombard() {
			return true
		}
	}
	return false
}

// Validate checks the unified config: at least one entry, unique verifier IDs, at most one
// committee entry (one process has a single ECDSA signing key), a valid port, and each entry's
// own validation (committee entries via the derived commit.Config).
func (c *UnifiedConfig) Validate() error {
	if len(c.Verifiers) == 0 {
		return fmt.Errorf("invalid unified verifier configuration: at least one [[verifiers]] entry is required")
	}
	if c.HTTPListenPort < 0 {
		return fmt.Errorf("invalid unified verifier configuration, http_listen_port must not be negative, got %d", c.HTTPListenPort)
	}
	if c.HTTPListenPort > unifiedHTTPListenPortMax {
		return fmt.Errorf("invalid unified verifier configuration, http_listen_port must not exceed %d, got %d", unifiedHTTPListenPortMax, c.HTTPListenPort)
	}

	seen := make(map[string]struct{}, len(c.Verifiers))
	committeeEntries := 0
	for i := range c.Verifiers {
		entry := &c.Verifiers[i]
		if _, dup := seen[entry.VerifierID]; dup {
			return fmt.Errorf("duplicate verifier_id %q", entry.VerifierID)
		}
		seen[entry.VerifierID] = struct{}{}

		switch entry.Type {
		case VerifierTypeCommittee:
			committeeEntries++
			if entry.CommitteeEntryConfig == nil {
				return fmt.Errorf("verifier %q: committee entry is missing its configuration", entry.VerifierID)
			}
			commitCfg := entry.ToCommitConfig(*c)
			commitCfg.VerifierID = entry.VerifierID
			if err := commitCfg.Validate(); err != nil {
				return fmt.Errorf("verifier %q: %w", entry.VerifierID, err)
			}
		case VerifierTypeCCTP:
			if entry.CCTPConfig == nil {
				return fmt.Errorf("verifier %q: cctp entry is missing its configuration", entry.VerifierID)
			}
		case VerifierTypeLombard:
			if entry.LombardConfig == nil {
				return fmt.Errorf("verifier %q: lombard entry is missing its configuration", entry.VerifierID)
			}
		default:
			return fmt.Errorf("unknown verifier type %q for verifier %s", entry.Type, entry.VerifierID)
		}
	}

	// One process holds a single ECDSA signing key, so at most one committee entry can run.
	if committeeEntries > 1 {
		return fmt.Errorf("invalid unified verifier configuration: at most one committee entry is allowed, got %d", committeeEntries)
	}
	return nil
}
