// Package admin implements the CCV admin console: a server-rendered UI over the
// verifier recovery stores, wrapping the job-queue / recovery CLI semantics so
// operators can find, explain, and recover dropped messages without node access.
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
	// ConfigPathEnv overrides the --config flag's default path.
	ConfigPathEnv      = "CCV_ADMIN_CONFIG_PATH"
	DefaultConfigPath  = "/etc/ccv-admin/config.toml"
	SecretsPathEnv     = "CCV_ADMIN_SECRETS_PATH"
	DefaultSecretsPath = "/etc/ccv-admin/secrets.toml"
)

// Config is the console configuration file schema. It carries no credentials: nodes
// reference their verifier secrets files by path and the console resolves them
// server-side.
type Config struct {
	// ListenAddress is the bind address; loopback by default.
	ListenAddress string `toml:"listen_address"`
	// Console configures the console's own state (action log). Its secrets file carries
	// [db].url; when absent, the console runs read-only.
	Console ConsoleConfig `toml:"console"`
	Access  AccessConfig  `toml:"access"`
	Nodes   []NodeConfig  `toml:"nodes"`
}

type ConsoleConfig struct {
	// SecretsPath is the console secrets file (same schema as the verifier secrets
	// file). Resolved from CCV_ADMIN_SECRETS_PATH / default when empty.
	SecretsPath string `toml:"secrets_path"`
}

type AccessConfig struct {
	// ActorHeader names the HTTP header carrying an authenticated identity from a
	// fronting proxy (shared hosting). Empty means self-hosted loopback: actor "local".
	ActorHeader string `toml:"actor_header"`
}

// NodeConfig is one verifier database the console administers. Nodes must belong to the
// same operator; each entry is one verifier's application database.
type NodeConfig struct {
	// Name is the display and action-log identity for this node.
	Name string `toml:"name"`
	// SecretsPath is this node's verifier secrets file, which carries its [db].url.
	SecretsPath string `toml:"secrets_path"`
	// AggregatorAddress (optional, host:port) enables attestation freshness checks via
	// the aggregator's unauthenticated GetVerifierResultsForMessage.
	AggregatorAddress string `toml:"aggregator_address"`
	// IndexerURL (optional base URL) enables the indexer's verification-result lookup.
	IndexerURL string `toml:"indexer_url"`
	// IndexerConfigPath (optional) points at an owned indexer's config file and enables
	// the indexer-data backfill workflow. Leave empty when the operator does not run the
	// indexer; the console then hides that workflow.
	IndexerConfigPath string `toml:"indexer_config_path"`
	// TraceURL (optional) is a base URL to the operator's trace viewer, linked from the
	// message detail page when set.
	TraceURL string `toml:"trace_url"`
}

// LoadConfig reads and validates the console config. A missing file is an error: the
// console is useless without at least one configured node, so failing fast beats a
// silently empty registry.
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
	host, _, _ := net.SplitHostPort(c.ListenAddress)
	if c.Access.ActorHeader == "" && host != "127.0.0.1" && host != "::1" && host != "localhost" {
		return fmt.Errorf("serving a page grants privileged actions: a non-loopback listen_address requires access.actor_header so actor identity comes from an authenticating proxy")
	}
	if len(c.Nodes) == 0 {
		return errors.New("at least one [[nodes]] entry is required")
	}
	seen := make(map[string]struct{}, len(c.Nodes))
	for i, n := range c.Nodes {
		if n.Name == "" {
			return fmt.Errorf("nodes[%d]: name is required", i)
		}
		if n.SecretsPath == "" {
			return fmt.Errorf("nodes[%d] (%s): secrets_path is required", i, n.Name)
		}
		if _, dup := seen[n.Name]; dup {
			return fmt.Errorf("nodes[%d]: duplicate node name %q", i, n.Name)
		}
		seen[n.Name] = struct{}{}
	}
	return nil
}

// ResolveConsoleSecretsPath applies the env/default resolution for the console secrets
// file when the config does not set one.
func (c *Config) ResolveConsoleSecretsPath() string {
	if c.Console.SecretsPath != "" {
		return c.Console.SecretsPath
	}
	if p := os.Getenv(SecretsPathEnv); p != "" {
		return p
	}
	return DefaultSecretsPath
}
