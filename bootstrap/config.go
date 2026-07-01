package bootstrap

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap/keys"
	"github.com/smartcontractkit/chainlink-ccv/common/monitoring"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// JDConfig is the configuration for the Job Distributor.
type JDConfig struct {
	// ServerWSRPCURL is the URL of the Job Distributor server's WebSocket RPC endpoint.
	ServerWSRPCURL string `toml:"server_wsrpc_url"`
	// ServerCSAPublicKey is the public key of the Job Distributor server's CSA key.
	ServerCSAPublicKey string `toml:"server_csa_public_key"`
}

func (c *JDConfig) validate() error {
	if c.ServerWSRPCURL == "" {
		return fmt.Errorf("ServerWSRPCURL is required")
	}
	if c.ServerCSAPublicKey == "" {
		return fmt.Errorf("ServerCSAPublicKey is required")
	}
	if _, err := keys.DecodeEd25519PublicKey(c.ServerCSAPublicKey); err != nil {
		return fmt.Errorf("invalid ServerCSAPublicKey: %w", err)
	}
	return nil
}

// KeystoreConfig is the configuration for the keystore.
type KeystoreConfig struct {
	// Password is the password to the keystore.
	Password string `toml:"password"`
}

func (c *KeystoreConfig) validate() error {
	if c.Password == "" {
		return fmt.Errorf("field 'password' is required")
	}
	return nil
}

// DBConfig is the configuration for the bootstrap database.
type DBConfig struct {
	// URL is the URL to use for saving jobs and the keystore.
	URL string `toml:"url"`
}

func (c *DBConfig) validate() error {
	if c.URL == "" {
		return fmt.Errorf("field 'url' is required")
	}
	return nil
}

// ServerConfig is the configuration for the HTTP info server.
type ServerConfig struct {
	// ListenPort is the port the HTTP server listens on.
	ListenPort int `toml:"listen_port"`
}

func (c *ServerConfig) validate() error {
	if c.ListenPort == 0 {
		return fmt.Errorf("field 'listen_port' is required")
	}
	return nil
}

// ChainRegistration declares a chain for which the node has a signing identity.
// The bootstrapper uses these entries to publish the node's signing key to JD on connect.
type ChainRegistration struct {
	// Type is the chain family, e.g. "EVM", "SOLANA". Case-insensitive.
	Type string `toml:"type"`
	// ID is the chain identifier, e.g. "1" for Ethereum mainnet.
	ID string `toml:"id"`
}

// knownChainTypes is the set of chain type strings (upper-cased) for which signing address
// derivation is implemented. Extend this together with signingAddressFromPublicKey in bootstrap.go.
var knownChainTypes = map[string]struct{}{
	"EVM": {}, "SOLANA": {}, "APTOS": {}, "STELLAR": {}, "CANTON": {},
}

func (c ChainRegistration) validate() error {
	if c.Type == "" {
		return fmt.Errorf("field 'type' is required")
	}
	if c.ID == "" {
		return fmt.Errorf("field 'id' is required")
	}
	if _, ok := knownChainTypes[strings.ToUpper(c.Type)]; !ok {
		return fmt.Errorf("unknown chain type %q: must be one of EVM, SOLANA, APTOS", c.Type)
	}
	return nil
}

// Config is the configuration for the bootstrapper.
// Example config:
/*
	[jd]
	server_wsrpc_url = "ws://localhost:8080/ws"
	server_csa_public_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	[keystore]
	password = "password"

	[db]
	url = "postgres://localhost:5432/bootstrapper"

	[server]
	listen_port = 9988

	[[chains]]
	type = "EVM"
	id = "1"
*/
type Config struct {
	JD       JDConfig       `toml:"jd,omitempty"`
	Keystore KeystoreConfig `toml:"keystore,omitempty"`
	DB       DBConfig       `toml:"db,omitempty"`
	Server   ServerConfig   `toml:"server,omitempty"`
	// Chains declares the chains on which this node has a signing identity.
	// Each entry causes the bootstrapper to register the node's signing key for that chain in JD.
	// Optional: if empty, no signing key sync is performed.
	Chains []ChainRegistration `toml:"chains"`

	// Monitoring is the operator-provided monitoring configuration.
	// These are operator- and environment-specific (the OTel exporter endpoints point
	// at a collector deployed alongside the app, typically a k8s sidecar), so they belong in the
	// operator-provided bootstrap config rather than the JD-shipped app config.
	//
	// It is a pointer to distinguish "operator did not configure monitoring here" (nil) from "operator
	// explicitly configured it, possibly with Enabled=false" (non-nil). The apps that consume it (commit
	// verifier, executor) prefer this value and fall back to their deprecated app-config Monitoring field
	// only when it is nil. The token verifier is the exception: it loads no bootstrap config and keeps
	// monitoring in its (already operator-provided) mounted app config.
	Monitoring *monitoring.Config
}

// presentInfraSections returns the infra sections (jd, db, keystore, server) that appear in md,
// in declaration order and de-duplicated. Used only to warn when infra is present in static-TOML
// mode, where it is ignored; infra presence does not drive validation (see validate).
func presentInfraSections(md toml.MetaData) []string {
	seen := make(map[string]bool, 4)
	var out []string
	for _, key := range md.Keys() {
		switch section := key[0]; section {
		case "jd", "db", "keystore", "server":
			if !seen[section] {
				seen[section] = true
				out = append(out, section)
			}
		}
	}
	return out
}

// validateInfra validates the coupled infra bundle (jd/db/keystore/server/chains).
func (c *Config) validateInfra() []error {
	var errs []error
	if err := c.JD.validate(); err != nil {
		errs = append(errs, fmt.Errorf("failed to validate 'jd' section: %w", err))
	}
	if err := c.Keystore.validate(); err != nil {
		errs = append(errs, fmt.Errorf("failed to validate 'keystore' section: %w", err))
	}
	if err := c.DB.validate(); err != nil {
		errs = append(errs, fmt.Errorf("failed to validate 'db' section: %w", err))
	}
	if err := c.Server.validate(); err != nil {
		errs = append(errs, fmt.Errorf("failed to validate 'server' section: %w", err))
	}
	for i, chain := range c.Chains {
		if err := chain.validate(); err != nil {
			errs = append(errs, fmt.Errorf("invalid chain at index %d: %w", i, err))
		}
	}
	return errs
}

// validate checks the config for correctness. Validation is mode-driven, keyed on needsInfra —
// which the caller derives from the bootstrapper's mode (true in JD mode, false in static-TOML
// mode) — rather than inferred from which sections happen to be present in the file:
//
//   - needsInfra: the infra bundle (jd/db/keystore/server/chains) is required; a missing or
//     invalid section is an error naming that section. This lets a JD-mode app with a malformed
//     bootstrap file fail at load time with a precise message, instead of a downstream connection
//     failure that a present-driven check would allow through.
//   - !needsInfra: the infra bundle is ignored. Any infra section present in md is warned about
//     (it does nothing in static-TOML mode) but is not an error.
//
// Monitoring is always validated when non-nil, in both modes. md is used only to name the
// ignored sections in the static-mode warning.
func (c *Config) validate(lggr logger.Logger, md toml.MetaData, needsInfra bool) error {
	var errs []error
	if needsInfra {
		errs = append(errs, c.validateInfra()...)
	} else if present := presentInfraSections(md); len(present) > 0 {
		lggr.Warnw("ignoring infra sections present in static-TOML mode bootstrap config; "+
			"these belong in a JD-mode bootstrap config", "sections", present)
	}
	if c.Monitoring != nil {
		if err := c.Monitoring.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("failed to validate 'monitoring' section: %w", err))
		}
	}
	return errors.Join(errs...)
}

// LoadAndValidateConfig loads the configuration from a path to a TOML file, in strict mode.
// needsInfra selects mode-driven validation (see validate): pass true in JD mode, false in
// static-TOML mode.
func LoadAndValidateConfig(lggr logger.Logger, path string, cfg *Config, needsInfra bool) error {
	tomlBytes, err := os.ReadFile(path) //nolint:gosec // G304: path is provided by trusted caller
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	md, err := parseTOMLStrict(string(tomlBytes), cfg)
	if err != nil {
		return fmt.Errorf("failed to parse config: %w", err)
	}

	if err := cfg.validate(lggr, md, needsInfra); err != nil {
		return fmt.Errorf("config validation failed: %w", err)
	}
	return nil
}

func parseTOMLStrict[T any](tomlString string, out T) (toml.MetaData, error) {
	md, err := toml.Decode(tomlString, out)
	if err != nil {
		return toml.MetaData{}, fmt.Errorf("failed to decode toml: %w", err)
	}
	if len(md.Undecoded()) > 0 {
		return toml.MetaData{}, fmt.Errorf("strict decode failed, found undecoded fields: %+v", md.Undecoded())
	}
	return md, nil
}
