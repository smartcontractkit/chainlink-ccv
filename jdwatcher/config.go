package jdwatcher

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"

	"github.com/BurntSushi/toml"
)

type Config struct {
	// JDServerWSRPCURL is the URL of the Job Distributor server's WebSocket RPC endpoint.
	JDServerWSRPCURL string `toml:"jd_server_wsrpc_url"`
	// JDServerCSAPublicKey is the public key of the Job Distributor server's CSA key.
	JDServerCSAPublicKey string `toml:"jd_server_csa_public_key"`
	// JobStorePath is the path to the file to save jobs.
	JobStorePath string `toml:"job_store_path"`
	// ProcessBinaryPath is the path to the process binary to run.
	ProcessBinaryPath string `toml:"process_binary_path"`
	// ProcessConfigPathEnvVar is the env var name the process reads for its config file path (e.g. VERIFIER_CONFIG_PATH).
	ProcessConfigPathEnvVar string `toml:"process_config_path_env_var"`
	// KMDURL is the URL of the KMD server.
	KMDServerURL string `toml:"kmd_server_url"`
	// KMDCSAKeyName is the name of the KMD CSA key to use for JD communications.
	KMDCSAKeyName string `toml:"kmd_csa_key_name"`
}

func (c *Config) validateJDServerCSAPublicKey() error {
	publicKey, err := hex.DecodeString(c.JDServerCSAPublicKey)
	if err != nil {
		return fmt.Errorf("failed to decode JDServerCSAPublicKey: %w", err)
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("JDServerCSAPublicKey is not an ed25519 public key")
	}
	return nil
}

func (c *Config) validate() error {
	if c.JDServerWSRPCURL == "" {
		return fmt.Errorf("JDServerWSRPCURL is required")
	}
	if c.JDServerCSAPublicKey == "" {
		return fmt.Errorf("JDServerCSAPublicKey is required")
	}
	if err := c.validateJDServerCSAPublicKey(); err != nil {
		return fmt.Errorf("failed to validate JDServerCSAPublicKey: %w", err)
	}
	if c.JobStorePath == "" {
		return fmt.Errorf("JobStorePath is required")
	}
	if c.ProcessBinaryPath == "" {
		return fmt.Errorf("ProcessBinaryPath is required")
	}
	if c.ProcessConfigPathEnvVar == "" {
		return fmt.Errorf("ProcessConfigPathEnvVar is required")
	}
	if c.KMDServerURL == "" {
		return fmt.Errorf("KMDServerURL is required")
	}
	if c.KMDCSAKeyName == "" {
		return fmt.Errorf("KMDCSAKeyName is required")
	}
	return nil
}

// LoadConfig loads the configuration from a path to a TOML file, in strict mode.
func LoadConfig(path string) (*Config, error) {
	var cfg Config
	md, err := toml.DecodeFile(path, &cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to decode config: %w", err)
	}
	if len(md.Undecoded()) > 0 {
		return nil, fmt.Errorf("unknown fields in config: %v", md.Undecoded())
	}
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}
	return &cfg, nil
}
