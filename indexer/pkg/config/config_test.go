package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func validPostgresConfig() *PostgresConfig {
	return &PostgresConfig{
		URI:                    "postgresql://user:pass@localhost:5432/db?sslmode=disable",
		MaxOpenConnections:     20,
		MaxIdleConnections:     5,
		IdleInTxSessionTimeout: 60,
		LockTimeout:            30,
	}
}

func TestStorageConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		config  StorageConfig
		wantErr string
	}{
		{
			name: "single strategy with postgres is accepted",
			config: StorageConfig{
				Strategy: StorageStrategySingle,
				Single: &SingleStorageConfig{
					Type:     StorageBackendTypePostgres,
					Postgres: validPostgresConfig(),
				},
			},
		},
		{
			name: "single strategy with memory is rejected",
			config: StorageConfig{
				Strategy: StorageStrategySingle,
				Single: &SingleStorageConfig{
					Type: StorageBackendTypeMemory,
				},
			},
			wantErr: "unknown storage backend type: memory (must be 'postgres')",
		},
		{
			name: "sink strategy is rejected",
			config: StorageConfig{
				Strategy: StorageStrategySink,
				Sink: &SinkStorageConfig{
					Storages: []StorageBackendConfig{
						{Type: StorageBackendTypePostgres, Postgres: validPostgresConfig()},
					},
				},
			},
			wantErr: "sink storage strategy is not supported, only single strategy with postgres backend is supported",
		},
		{
			name:    "empty strategy is rejected",
			config:  StorageConfig{},
			wantErr: "storage strategy is required",
		},
		{
			name: "unknown strategy is rejected",
			config: StorageConfig{
				Strategy: "distributed",
			},
			wantErr: "unknown storage strategy",
		},
		{
			name: "single strategy without config is rejected",
			config: StorageConfig{
				Strategy: StorageStrategySingle,
			},
			wantErr: "single storage config is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
