// Package admin implements the CCV admin console: a server-rendered UI over one
// verifier's recovery stores, wrapping the job-queue / recovery CLI semantics so
// operators can find, explain, and recover dropped messages without database access.
package admin

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"

	"github.com/BurntSushi/toml"
)

const (
	// DefaultListenAddress binds the console to loopback unless configured otherwise.
	DefaultListenAddress = "127.0.0.1:8105"
	// ConfigPathEnv overrides the default console config path.
	ConfigPathEnv = "CCV_ADMIN_CONFIG_PATH"
	// DefaultConfigPath is the console config file's default location. A present file
	// enables the console: the verifier factory serves it in-process alongside the job.
	DefaultConfigPath = "/etc/ccv-admin/config.toml"
)

// Config is the console configuration file schema. It carries no credentials and no
// database settings: the console administers the verifier it runs beside, sharing that
// verifier's application database (the action log lives there too) and its secrets file
// (basic auth comes from its [admin_ui] table).
type Config struct {
	// ListenAddress is the bind address; loopback by default.
	ListenAddress string `toml:"listen_address"`
	// AggregatorAddress (optional, host:port) overrides the aggregator used for
	// attestation freshness checks via the unauthenticated GetVerifierResultsForMessage.
	// Empty uses the verifier's own first configured aggregator.
	AggregatorAddress string `toml:"aggregator_address"`
	// TraceURL (optional) is a base URL to the operator's trace viewer — typically an
	// internal Grafana/Tempo or Jaeger — linked from the message detail page when set.
	TraceURL string `toml:"trace_url"`
	// Access configures how the console identifies who is acting.
	Access AccessConfig `toml:"access"`
}

type AccessConfig struct {
	// ActorHeader names the HTTP header carrying an authenticated identity from a
	// fronting proxy (shared hosting). Empty means self-hosted loopback: actor "local".
	// Non-loopback serving requires this header or [admin_ui] basic auth from the
	// verifier secrets file (validated at startup, when the secrets are loaded).
	ActorHeader string `toml:"actor_header"`
}

// LoadConfig reads and validates the console config. A missing file is an error: the
// factory treats file presence as the enable signal and loads only when it exists.
func LoadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // G304: path is operator-provided, trusted.
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("console config %q does not exist", path)
		}
		return nil, fmt.Errorf("failed to read console config %q: %w", path, err)
	}
	var cfg Config
	md, err := toml.Decode(string(raw), &cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to decode console config %q: %w", path, err)
	}
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		return nil, fmt.Errorf("console config %q has unknown keys: %+v", path, undecoded)
	}
	if cfg.ListenAddress == "" {
		cfg.ListenAddress = DefaultListenAddress
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid console config %q: %w", path, err)
	}
	return &cfg, nil
}

func (c *Config) Validate() error {
	if _, _, err := net.SplitHostPort(c.ListenAddress); err != nil {
		return fmt.Errorf("listen_address %q is not host:port: %w", c.ListenAddress, err)
	}
	// The non-loopback identity rule lives in ValidateAccessPolicy (server startup):
	// it needs the verifier secrets, which are not loaded here.
	return nil
}
