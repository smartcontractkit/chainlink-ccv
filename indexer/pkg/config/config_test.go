package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateMaxResponseBytes(t *testing.T) {
	tests := []struct {
		name    string
		value   int
		wantErr bool
		errSub  string
	}{
		{"rejects negative value", -1, true, "non-negative"},
		{"rejects exceeding max allowed", MaxAllowedResponseBytes + 1, true, "must be <="},
		{"accepts zero", 0, false, ""},
		{"accepts 1 byte", 1, false, ""},
		{"accepts default", DefaultMaxResponseBytes, false, ""},
		{"accepts max allowed", MaxAllowedResponseBytes, false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateMaxResponseBytes(tt.value, "test")
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errSub)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestEffectiveMaxResponseBytes(t *testing.T) {
	tests := []struct {
		name     string
		input    int
		expected int
	}{
		{"returns default when zero", 0, DefaultMaxResponseBytes},
		{"returns default when negative", -5, DefaultMaxResponseBytes},
		{"returns configured value", 8 << 20, 8 << 20},
		{"returns 1 byte when set to 1", 1, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, EffectiveMaxResponseBytes(tt.input))
		})
	}
}

func TestVerifierConfigValidate_MaxResponseBytes(t *testing.T) {
	tests := []struct {
		name             string
		readerType       ReaderType
		maxResponseBytes int
		wantErr          bool
		errSub           string
	}{
		{"aggregator rejects negative", ReaderTypeAggregator, -1, true, "non-negative"},
		{"aggregator rejects exceeding max", ReaderTypeAggregator, MaxAllowedResponseBytes + 1, true, "must be <="},
		{"aggregator accepts zero", ReaderTypeAggregator, 0, false, ""},
		{"aggregator accepts valid value", ReaderTypeAggregator, DefaultMaxResponseBytes, false, ""},
		{"rest rejects negative", ReaderTypeRest, -1, true, "non-negative"},
		{"rest rejects exceeding max", ReaderTypeRest, MaxAllowedResponseBytes + 1, true, "must be <="},
		{"rest accepts zero", ReaderTypeRest, 0, false, ""},
		{"rest accepts valid value", ReaderTypeRest, DefaultMaxResponseBytes, false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := VerifierConfig{
				Type:             tt.readerType,
				MaxResponseBytes: tt.maxResponseBytes,
				AggregatorReaderConfig: AggregatorReaderConfig{
					Address: "localhost:50051",
				},
				RestReaderConfig: RestReaderConfig{
					BaseURL: "http://localhost:8080/v1",
				},
			}
			err := cfg.Validate(0)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errSub)
				assert.Contains(t, err.Error(), "verifier 0")
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestDiscoveryConfigValidate_MaxResponseBytes(t *testing.T) {
	tests := []struct {
		name             string
		maxResponseBytes int
		wantErr          bool
		errSub           string
	}{
		{"rejects negative", -1, true, "non-negative"},
		{"rejects exceeding max", MaxAllowedResponseBytes + 1, true, "must be <="},
		{"accepts zero", 0, false, ""},
		{"accepts valid value", DefaultMaxResponseBytes, false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DiscoveryConfig{
				AggregatorReaderConfig: AggregatorReaderConfig{
					Address: "localhost:50051",
				},
				PollInterval:     1,
				Timeout:          5,
				NtpServer:        "time.google.com",
				MaxResponseBytes: tt.maxResponseBytes,
			}
			err := cfg.Validate(0)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errSub)
				assert.Contains(t, err.Error(), "discovery[0]")
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestDiscoveryConfigValidate_Timeout(t *testing.T) {
	tests := []struct {
		name         string
		pollInterval int
		timeout      int
		wantErr      bool
		errSub       string
	}{
		{"timeout zero returns error with greater than 0 message", 1, 0, true, "timeout must be greater than 0"},
		{"timeout negative returns error with greater than 0 message", 1, -1, true, "timeout must be greater than 0"},
		{"timeout equals poll interval returns error with greater than poll interval message", 100, 100, true, "timeout must be greater than poll interval"},
		{"timeout greater than poll interval passes", 100, 101, false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DiscoveryConfig{
				AggregatorReaderConfig: AggregatorReaderConfig{Address: "localhost:50051"},
				PollInterval:           tt.pollInterval,
				Timeout:                tt.timeout,
				NtpServer:              "time.google.com",
			}
			err := cfg.Validate(0)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errSub)
				assert.Contains(t, err.Error(), "discovery[0]")
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestDiscoveryConfigValidate_NtpServer(t *testing.T) {
	tests := []struct {
		name      string
		ntpServer string
		wantErr   bool
		errSub    string
	}{
		{"empty NtpServer returns error", "", true, "NTP server address is required"},
		{"non-empty NtpServer passes", "time.google.com", false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DiscoveryConfig{
				AggregatorReaderConfig: AggregatorReaderConfig{Address: "localhost:50051"},
				PollInterval:           1,
				Timeout:                5,
				NtpServer:              tt.ntpServer,
			}
			err := cfg.Validate(0)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errSub)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestConfig_Validate_MergeBufferSize(t *testing.T) {
	validDiscovery := DiscoveryConfig{
		AggregatorReaderConfig: AggregatorReaderConfig{Address: "http://agg1", Since: 0},
		PollInterval:           100,
		Timeout:                200,
		NtpServer:              "time.google.com",
	}
	minimalValidConfig := func(mergeBufferSize int) *Config {
		return &Config{
			Scheduler: SchedulerConfig{
				TickerInterval:               100,
				VerificationVisibilityWindow: 120,
				BaseDelay:                    1000,
				MaxDelay:                     5000,
			},
			Discoveries:    []DiscoveryConfig{validDiscovery},
			MergeBufferSize: mergeBufferSize,
			Storage: StorageConfig{
				Strategy: StorageStrategySingle,
				Single: &SingleStorageConfig{
					Type:     StorageBackendTypePostgres,
					Postgres: validPostgresConfig(),
				},
			},
		}
	}
	t.Run("negative MergeBufferSize returns error", func(t *testing.T) {
		cfg := minimalValidConfig(-1)
		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "merge buffer size must be non-negative")
	})
	t.Run("zero MergeBufferSize passes", func(t *testing.T) {
		cfg := minimalValidConfig(0)
		require.NoError(t, cfg.Validate())
	})
	t.Run("positive MergeBufferSize passes", func(t *testing.T) {
		cfg := minimalValidConfig(1024)
		require.NoError(t, cfg.Validate())
	})
}

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
					Type: "memory",
				},
			},
			wantErr: "unknown storage backend type: memory (must be 'postgres')",
		},
		{
			name: "sink strategy is rejected",
			config: StorageConfig{
				Strategy: "sink",
			},
			wantErr: "unknown storage strategy: sink (must be 'single')",
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
