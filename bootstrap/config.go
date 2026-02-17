package bootstrap

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"

	"github.com/BurntSushi/toml"
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
	if err := c.validateJDServerCSAPublicKey(); err != nil {
		return fmt.Errorf("failed to validate ServerCSAPublicKey: %w", err)
	}
	return nil
}

func (c *JDConfig) validateJDServerCSAPublicKey() error {
	publicKey, err := hex.DecodeString(c.ServerCSAPublicKey)
	if err != nil {
		return fmt.Errorf("failed to decode ServerCSAPublicKey: %w", err)
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("ServerCSAPublicKey is not an ed25519 public key")
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
*/
type Config struct {
	JD       JDConfig
	Keystore KeystoreConfig
	DB       DBConfig
}

func (c *Config) validate() error {
	if err := c.JD.validate(); err != nil {
		return fmt.Errorf("failed to validate 'jd' section: %w", err)
	}
	if err := c.Keystore.validate(); err != nil {
		return fmt.Errorf("failed to validate 'keystore' section: %w", err)
	}
	if err := c.DB.validate(); err != nil {
		return fmt.Errorf("failed to validate 'db' section: %w", err)
	}
	return nil
}

// LoadConfig loads the configuration from a path to a TOML file, in strict mode.
func LoadConfig(path string) (Config, error) {
	var cfg Config
	md, err := toml.DecodeFile(path, &cfg)
	if err != nil {
		return Config{}, fmt.Errorf("failed to decode config: %w", err)
	}
	if len(md.Undecoded()) > 0 {
		return Config{}, fmt.Errorf("unknown fields in config: %v", md.Undecoded())
	}
	if err := cfg.validate(); err != nil {
		return Config{}, fmt.Errorf("config validation failed: %w", err)
	}
	return cfg, nil
}
