package config

import (
	"fmt"
	"os"
	"strconv"

	"github.com/BurntSushi/toml"
)

// SecretsConfig represents the structure of secrets.toml
// Indexed entries like [Verifier.0] are parsed manually from the raw TOML.
// Verifier keys are string representations of indices (e.g., "0", "1", "2").
type SecretsConfig struct {
	Discoveries map[string]DiscoverySecrets `toml:"Discoveries"`
	Verifier    map[string]VerifierSecrets  `toml:"Verifier"`
	Storage     StorageSecrets              `toml:"Storage"`
}

// DiscoverySecrets contains secrets for the discovery aggregator connection.
type DiscoverySecrets struct {
	APIKey string `toml:"APIKey"`
	Secret string `toml:"Secret"`
}

// VerifierSecrets contains secrets for a verifier connection.
type VerifierSecrets struct {
	APIKey string `toml:"APIKey"`
	Secret string `toml:"Secret"`
}

// StorageSecrets contains secrets for storage backends.
type StorageSecrets struct {
	Single SingleStorageSecrets `toml:"Single"`
	Sink   SinkStorageSecrets   `toml:"Sink"`
}

// SingleStorageSecrets contains secrets for single storage strategy.
type SingleStorageSecrets struct {
	Postgres PostgresSecrets `toml:"Postgres"`
}

// SinkStorageSecrets contains secrets for sink storage strategy.
// Storages keys are string representations of indices (e.g., "0", "1", "2").
type SinkStorageSecrets struct {
	Storages map[string]StorageBackendSecrets `toml:"Storages"`
}

// StorageBackendSecrets contains secrets for a storage backend.
type StorageBackendSecrets struct {
	Postgres PostgresSecrets `toml:"Postgres"`
}

// PostgresSecrets contains the database connection URI.
type PostgresSecrets struct {
	URI string `toml:"URI"`
}

// LoadSecrets loads secrets from secrets.toml file.
// Returns nil if the file doesn't exist (secrets are optional).
// Returns an error if the file exists but cannot be read or parsed.
func LoadSecrets() (*SecretsConfig, error) {
	filepath, ok := os.LookupEnv("INDEXER_SECRETS_PATH")
	if !ok {
		filepath = "secrets.toml"
	}

	data, err := os.ReadFile(filepath) //nolint:gosec // file is either secrets.toml or a user defined file required for configuration
	if err != nil {
		if os.IsNotExist(err) {
			// Secrets file is optional, return nil if it doesn't exist
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read secrets file %s: %w", filepath, err)
	}

	return LoadSecretsFromBytes(data)
}

// LoadSecretsFromBytes loads secrets from TOML bytes.
// Unmarshals standard sections directly, then manually parses indexed keys.
func LoadSecretsFromBytes(data []byte) (*SecretsConfig, error) {
	var secrets SecretsConfig
	if err := toml.Unmarshal(data, &secrets); err != nil {
		return nil, fmt.Errorf("failed to parse TOML secrets: %w", err)
	}

	return &secrets, nil
}

// MergeSecrets merges secrets into the config, overwriting any existing values.
// This function modifies the config in place.
func MergeSecrets(cfg *Config, secrets *SecretsConfig) error {
	if secrets == nil {
		// No secrets to merge, return early
		return nil
	}

	// Merge Discovery secrets when present (optional: only overwrite if key exists)
	if secrets.Discoveries != nil {
		for i := range cfg.Discoveries {
			discSecrets, ok := secrets.Discoveries[strconv.Itoa(i)]
			if !ok {
				continue
			}
			if discSecrets.APIKey != "" {
				cfg.Discoveries[i].APIKey = discSecrets.APIKey
			}
			if discSecrets.Secret != "" {
				cfg.Discoveries[i].Secret = discSecrets.Secret
			}
		}
	}

	// Merge Verifier secrets
	// The map keys are string representations of indices (e.g., "0", "1", "2")
	for indexStr, verifierSecrets := range secrets.Verifier {
		index, err := strconv.Atoi(indexStr)
		if err != nil {
			return fmt.Errorf("invalid verifier index in secrets: %s (must be numeric)", indexStr)
		}

		if index < 0 || index >= len(cfg.Verifiers) {
			return fmt.Errorf("verifier index %d in secrets is out of range (config has %d verifiers)", index, len(cfg.Verifiers))
		}

		// Only merge secrets for aggregator-type verifiers
		if cfg.Verifiers[index].Type == ReaderTypeAggregator {
			if verifierSecrets.APIKey != "" {
				cfg.Verifiers[index].APIKey = verifierSecrets.APIKey
			}
			if verifierSecrets.Secret != "" {
				cfg.Verifiers[index].Secret = verifierSecrets.Secret
			}
		}
	}

	// Merge Storage secrets
	if err := mergeStorageSecrets(cfg, &secrets.Storage); err != nil {
		return fmt.Errorf("failed to merge storage secrets: %w", err)
	}

	return nil
}

// mergeStorageSecrets merges storage secrets into the config.
func mergeStorageSecrets(cfg *Config, storageSecrets *StorageSecrets) error {
	switch cfg.Storage.Strategy {
	case StorageStrategySingle:
		if cfg.Storage.Single != nil && cfg.Storage.Single.Type == StorageBackendTypePostgres {
			if cfg.Storage.Single.Postgres == nil {
				return fmt.Errorf("postgres config is nil for single storage")
			}
			if storageSecrets.Single.Postgres.URI != "" {
				cfg.Storage.Single.Postgres.URI = storageSecrets.Single.Postgres.URI
			}
		}

	case StorageStrategySink:
		if cfg.Storage.Sink == nil {
			return fmt.Errorf("sink storage config is nil")
		}

		// Merge secrets for each postgres storage backend
		// The map keys are string representations of indices (e.g., "0", "1", "2")
		for indexStr, backendSecrets := range storageSecrets.Sink.Storages {
			index, err := strconv.Atoi(indexStr)
			if err != nil {
				return fmt.Errorf("invalid storage index in secrets: %s (must be numeric)", indexStr)
			}

			if index < 0 || index >= len(cfg.Storage.Sink.Storages) {
				return fmt.Errorf("storage index %d in secrets is out of range (config has %d storage backends)", index, len(cfg.Storage.Sink.Storages))
			}

			// Only merge secrets for postgres-type storage backends
			if cfg.Storage.Sink.Storages[index].Type == StorageBackendTypePostgres {
				if cfg.Storage.Sink.Storages[index].Postgres == nil {
					return fmt.Errorf("postgres config is nil for storage backend %d", index)
				}
				if backendSecrets.Postgres.URI != "" {
					cfg.Storage.Sink.Storages[index].Postgres.URI = backendSecrets.Postgres.URI
				}
			}
		}
	}

	return nil
}
