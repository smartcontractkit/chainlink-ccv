package evmconfig

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

const (
	EVMSecretsPathEnv     = "EVM_SECRETS_PATH"
	DefaultEVMSecretsPath = "/etc/evm/secrets.toml" //nolint:gosec // G101: this is a file path, not a credential
)

// Secrets is the secret half of the EVM config: the credential-bearing RPC endpoints, keyed by
// chain selector, and the database the EVM accessor keeps its own tables in. Node URLs often embed
// provider API keys, so they live here and never in Config.
//
// Example secrets file (secrets.toml):
/*
	[db]
	url = "postgres://localhost:5432/evm"

	[[chains."5009297550715157269".nodes]]
	name = "chainstack"
	http_url = "https://user:key@evm-rpc.example.com"
	ws_url = "wss://user:key@evm-rpc.example.com"
*/
type Secrets struct {
	// DB is the database for the EVM accessor's own tables. Required only when log_poller_enabled is on.
	DB *DBConfig `toml:"db,omitempty"`
	// Chains maps EVM chain selector (decimal string) to that chain's secret settings.
	Chains map[string]ChainSecrets `toml:"chains,omitempty"`
}

// DBConfig is the database the EVM accessor keeps its own tables in.
type DBConfig struct {
	// URL is the database connection URL. It is required.
	URL string `toml:"url"`
}

func (c *DBConfig) validate() error {
	if c.URL == "" {
		return fmt.Errorf("field 'url' is required")
	}
	return nil
}

// ChainSecrets is the secret configuration for a single EVM chain.
type ChainSecrets struct {
	// Nodes are the credential-bearing RPC endpoints, joined to Config nodes by name.
	Nodes []NodeSecrets `toml:"nodes"`
}

// NodeSecrets is one RPC endpoint's credential-bearing URLs.
type NodeSecrets struct {
	// Name is the join key back to the non-secret node of the same name. It is required.
	Name string `toml:"name"`
	// HTTPUrl is the JSON-RPC endpoint used for reads and transaction submission. It is required.
	HTTPUrl string `toml:"http_url"`
	// WSUrl is the optional WebSocket endpoint used for head subscriptions.
	WSUrl string `toml:"ws_url,omitempty"`
}

func (s *NodeSecrets) validate() error {
	var errs []error
	if strings.TrimSpace(s.Name) == "" {
		errs = append(errs, fmt.Errorf("field 'name' is required"))
	}
	if s.HTTPUrl == "" {
		errs = append(errs, fmt.Errorf("field 'http_url' is required"))
	}
	return errors.Join(errs...)
}

func (c *ChainSecrets) validate() error {
	if len(c.Nodes) == 0 {
		return fmt.Errorf("at least one node is required")
	}
	var errs []error
	seen := make(map[string]struct{}, len(c.Nodes))
	for i := range c.Nodes {
		if err := c.Nodes[i].validate(); err != nil {
			errs = append(errs, fmt.Errorf("failed to validate node %d: %w", i, err))
		}
		name := strings.TrimSpace(c.Nodes[i].Name)
		if _, dup := seen[name]; dup && name != "" {
			errs = append(errs, fmt.Errorf("duplicate node name %q", name))
		}
		seen[name] = struct{}{}
	}
	return errors.Join(errs...)
}

// Validate checks every chain's secrets, reporting all problems at once.
func (s *Secrets) Validate() error {
	selectors := make([]string, 0, len(s.Chains))
	for selector := range s.Chains {
		selectors = append(selectors, selector)
	}
	sort.Strings(selectors)

	var errs []error
	if s.DB != nil {
		if err := s.DB.validate(); err != nil {
			errs = append(errs, fmt.Errorf("failed to validate 'db' section: %w", err))
		}
	}
	for _, selector := range selectors {
		chain := s.Chains[selector]
		if err := chain.validate(); err != nil {
			errs = append(errs, fmt.Errorf("failed to validate chain %q: %w", selector, err))
		}
	}
	return errors.Join(errs...)
}

// ResolveSecretsPath returns the EVM secrets path: EVM_SECRETS_PATH, then the default mount point,
// but only if it points at an existing file. The file is optional, so absence returns "".
func ResolveSecretsPath() string {
	path := os.Getenv(EVMSecretsPathEnv)
	if path == "" {
		path = DefaultEVMSecretsPath
	}
	if _, err := os.Stat(path); err != nil { //nolint:gosec // G703: operator-provided path
		return ""
	}
	return path
}

// LoadSecretsFile reads and validates the EVM secrets file. An empty path means no secrets file
// and returns an empty Secrets.
func LoadSecretsFile(path string) (*Secrets, error) {
	if path == "" {
		return &Secrets{}, nil
	}
	data, err := os.ReadFile(path) //nolint:gosec // G304: operator-provided path
	if err != nil {
		return nil, fmt.Errorf("failed to read secrets file %s: %w", path, err)
	}
	var secrets Secrets
	md, err := toml.Decode(string(data), &secrets)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal secrets file %s: %w", path, err)
	}
	if len(md.Undecoded()) > 0 {
		return nil, fmt.Errorf("unknown fields in secrets file %s: %v", path, md.Undecoded())
	}
	if err := secrets.Validate(); err != nil {
		return nil, fmt.Errorf("invalid secrets file %s: %w", path, err)
	}
	return &secrets, nil
}
