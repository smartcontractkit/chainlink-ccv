package evmconfig

import (
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
)

const (
	EVMSecretsPathEnv     = "EVM_SECRETS_PATH"
	DefaultEVMSecretsPath = "/etc/evm/secrets.toml" //nolint:gosec // G101: this is a file path, not a credential
)

// Secrets is the secret half of the EVM config: the database the EVM accessor keeps its own tables in.
//
// Example secrets file (secrets.toml):
/*
	[db]
	url = "postgres://localhost:5432/evm"
*/
type Secrets struct {
	// DB is the database for the EVM accessor's own tables. Required when any chain sets log_poller_source_reader_enabled.
	DB *DBConfig `toml:"db,omitempty"`
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

// Validate checks the database section when it is present.
func (s *Secrets) Validate() error {
	if s.DB != nil {
		if err := s.DB.validate(); err != nil {
			return fmt.Errorf("failed to validate 'db' section: %w", err)
		}
	}
	return nil
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
