package model

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/auth"
	hmacutil "github.com/smartcontractkit/chainlink-ccv/protocol/common/hmac"
)

func createValidCommittee() *Committee {
	return &Committee{
		QuorumConfigs: map[string]*QuorumConfig{
			"1": {
				SourceVerifierAddress: "0x1234567890abcdef1234567890abcdef12345678",
				Signers: []Signer{
					{Address: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
					{Address: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
				},
				Threshold: 1,
			},
		},
		DestinationVerifiers: map[string]string{
			"2": "0xabcdef1234567890abcdef1234567890abcdef12",
		},
	}
}

func createMinimalValidConfig() *AggregatorConfig {
	return &AggregatorConfig{
		Committee: createValidCommittee(),
		Server: ServerConfig{
			RequestTimeoutSeconds: 10,
		},
	}
}

func TestRateLimiterStoreType_IsValid(t *testing.T) {
	tests := []struct {
		name     string
		storeTyp RateLimiterStoreType
		expected bool
	}{
		{"memory type is valid", RateLimiterStoreTypeMemory, true},
		{"redis type is valid", RateLimiterStoreTypeRedis, true},
		{"empty type is invalid", RateLimiterStoreType(""), false},
		{"unknown type is invalid", RateLimiterStoreType("unknown"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.storeTyp.IsValid())
		})
	}
}

func TestSetDefaults(t *testing.T) {
	t.Run("sets all default values on empty config", func(t *testing.T) {
		cfg := &AggregatorConfig{}
		cfg.SetDefaults()

		assert.Equal(t, 100, cfg.MaxMessageIDsPerBatch)
		assert.Equal(t, 100, cfg.MaxCommitVerifierNodeResultRequestsPerBatch)
		assert.Equal(t, 10, cfg.Aggregation.ChannelBufferSize)
		assert.Equal(t, 10, cfg.Aggregation.BackgroundWorkerCount)
		assert.NotNil(t, cfg.Storage)
		assert.Equal(t, 100, cfg.Storage.PageSize)
		assert.Equal(t, 25, cfg.Storage.MaxOpenConns)
		assert.Equal(t, 5, cfg.Storage.MaxIdleConns)
		assert.Equal(t, 3600, cfg.Storage.ConnMaxLifetime)
		assert.Equal(t, 300, cfg.Storage.ConnMaxIdleTime)
		assert.Equal(t, 300, cfg.OrphanRecovery.IntervalSeconds)
		assert.Equal(t, 168, cfg.OrphanRecovery.MaxAgeHours)
		assert.Equal(t, "8080", cfg.HealthCheck.Port)
		assert.Equal(t, 10, cfg.Server.RequestTimeoutSeconds)
		assert.Equal(t, 5*time.Second, cfg.Aggregation.CheckAggregationTimeout)
		assert.Equal(t, 5*time.Second, cfg.OrphanRecovery.CheckAggregationTimeout)
	})

	t.Run("does not override existing values", func(t *testing.T) {
		cfg := &AggregatorConfig{
			MaxMessageIDsPerBatch: 50,
			Storage: &StorageConfig{
				PageSize: 200,
			},
			Server: ServerConfig{
				RequestTimeoutSeconds: 30,
			},
		}
		cfg.SetDefaults()

		assert.Equal(t, 50, cfg.MaxMessageIDsPerBatch)
		assert.Equal(t, 200, cfg.Storage.PageSize)
		assert.Equal(t, 30, cfg.Server.RequestTimeoutSeconds)
	})
}

func TestValidateServerConfig(t *testing.T) {
	tests := []struct {
		name        string
		config      ServerConfig
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid config",
			config:      ServerConfig{RequestTimeoutSeconds: 10},
			expectError: false,
		},
		{
			name:        "zero request timeout fails",
			config:      ServerConfig{RequestTimeoutSeconds: 0},
			expectError: true,
			errorMsg:    "requestTimeoutSeconds must be greater than 0",
		},
		{
			name:        "negative request timeout fails",
			config:      ServerConfig{RequestTimeoutSeconds: -1},
			expectError: true,
			errorMsg:    "requestTimeoutSeconds must be greater than 0",
		},
		{
			name:        "negative connection timeout fails",
			config:      ServerConfig{RequestTimeoutSeconds: 10, ConnectionTimeoutSeconds: -1},
			expectError: true,
			errorMsg:    "connectionTimeoutSeconds cannot be negative",
		},
		{
			name:        "negative keepalive min time fails",
			config:      ServerConfig{RequestTimeoutSeconds: 10, KeepaliveMinTimeSeconds: -1},
			expectError: true,
			errorMsg:    "keepaliveMinTimeSeconds cannot be negative",
		},
		{
			name:        "negative keepalive time fails",
			config:      ServerConfig{RequestTimeoutSeconds: 10, KeepaliveTimeSeconds: -1},
			expectError: true,
			errorMsg:    "keepaliveTimeSeconds cannot be negative",
		},
		{
			name:        "negative keepalive timeout fails",
			config:      ServerConfig{RequestTimeoutSeconds: 10, KeepaliveTimeoutSeconds: -1},
			expectError: true,
			errorMsg:    "keepaliveTimeoutSeconds cannot be negative",
		},
		{
			name:        "negative max connection age fails",
			config:      ServerConfig{RequestTimeoutSeconds: 10, MaxConnectionAgeSeconds: -1},
			expectError: true,
			errorMsg:    "maxConnectionAgeSeconds cannot be negative",
		},
		{
			name:        "negative max recv msg size fails",
			config:      ServerConfig{RequestTimeoutSeconds: 10, MaxRecvMsgSizeBytes: -1},
			expectError: true,
			errorMsg:    "maxRecvMsgSizeBytes cannot be negative",
		},
		{
			name:        "max recv msg size exceeds limit fails",
			config:      ServerConfig{RequestTimeoutSeconds: 10, MaxRecvMsgSizeBytes: 101 * 1024 * 1024},
			expectError: true,
			errorMsg:    "maxRecvMsgSizeBytes cannot exceed 100MB",
		},
		{
			name:        "negative max send msg size fails",
			config:      ServerConfig{RequestTimeoutSeconds: 10, MaxSendMsgSizeBytes: -1},
			expectError: true,
			errorMsg:    "maxSendMsgSizeBytes cannot be negative",
		},
		{
			name:        "max send msg size exceeds limit fails",
			config:      ServerConfig{RequestTimeoutSeconds: 10, MaxSendMsgSizeBytes: 101 * 1024 * 1024},
			expectError: true,
			errorMsg:    "maxSendMsgSizeBytes cannot exceed 100MB",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &AggregatorConfig{Server: tt.config}
			err := cfg.ValidateServerConfig()

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateBatchConfig(t *testing.T) {
	tests := []struct {
		name        string
		config      *AggregatorConfig
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid config",
			config:      &AggregatorConfig{MaxMessageIDsPerBatch: 100, MaxCommitVerifierNodeResultRequestsPerBatch: 100},
			expectError: false,
		},
		{
			name:        "zero max message ids fails",
			config:      &AggregatorConfig{MaxMessageIDsPerBatch: 0, MaxCommitVerifierNodeResultRequestsPerBatch: 100},
			expectError: true,
			errorMsg:    "maxMessageIDsPerBatch must be greater than 0",
		},
		{
			name:        "negative max message ids fails",
			config:      &AggregatorConfig{MaxMessageIDsPerBatch: -1, MaxCommitVerifierNodeResultRequestsPerBatch: 100},
			expectError: true,
			errorMsg:    "maxMessageIDsPerBatch must be greater than 0",
		},
		{
			name:        "max message ids exceeds limit fails",
			config:      &AggregatorConfig{MaxMessageIDsPerBatch: 1001, MaxCommitVerifierNodeResultRequestsPerBatch: 100},
			expectError: true,
			errorMsg:    "maxMessageIDsPerBatch cannot exceed 1000",
		},
		{
			name:        "zero commit verifier requests fails",
			config:      &AggregatorConfig{MaxMessageIDsPerBatch: 100, MaxCommitVerifierNodeResultRequestsPerBatch: 0},
			expectError: true,
			errorMsg:    "maxCommitVerifierNodeResultRequestsPerBatch must be greater than 0",
		},
		{
			name:        "commit verifier requests exceeds limit fails",
			config:      &AggregatorConfig{MaxMessageIDsPerBatch: 100, MaxCommitVerifierNodeResultRequestsPerBatch: 1001},
			expectError: true,
			errorMsg:    "maxCommitVerifierNodeResultRequestsPerBatch cannot exceed 1000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.ValidateBatchConfig()

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateAggregationConfig(t *testing.T) {
	tests := []struct {
		name        string
		config      AggregationConfig
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid config",
			config:      AggregationConfig{ChannelBufferSize: 10, BackgroundWorkerCount: 10, CheckAggregationTimeout: 5 * time.Second},
			expectError: false,
		},
		{
			name:        "zero channel buffer size fails",
			config:      AggregationConfig{ChannelBufferSize: 0, BackgroundWorkerCount: 10, CheckAggregationTimeout: 5 * time.Second},
			expectError: true,
			errorMsg:    "channelBufferSize must be greater than 0",
		},
		{
			name:        "channel buffer size exceeds limit fails",
			config:      AggregationConfig{ChannelBufferSize: 100001, BackgroundWorkerCount: 10, CheckAggregationTimeout: 5 * time.Second},
			expectError: true,
			errorMsg:    "channelBufferSize cannot exceed 100000",
		},
		{
			name:        "zero worker count fails",
			config:      AggregationConfig{ChannelBufferSize: 10, BackgroundWorkerCount: 0, CheckAggregationTimeout: 5 * time.Second},
			expectError: true,
			errorMsg:    "backgroundWorkerCount must be greater than 0",
		},
		{
			name:        "worker count exceeds limit fails",
			config:      AggregationConfig{ChannelBufferSize: 10, BackgroundWorkerCount: 101, CheckAggregationTimeout: 5 * time.Second},
			expectError: true,
			errorMsg:    "backgroundWorkerCount cannot exceed 100",
		},
		{
			name:        "negative operation timeout fails",
			config:      AggregationConfig{ChannelBufferSize: 10, BackgroundWorkerCount: 10, OperationTimeoutSeconds: -1, CheckAggregationTimeout: 5 * time.Second},
			expectError: true,
			errorMsg:    "operationTimeoutSeconds cannot be negative",
		},
		{
			name:        "negative check aggregation timeout fails",
			config:      AggregationConfig{ChannelBufferSize: 10, BackgroundWorkerCount: 10, CheckAggregationTimeout: -1},
			expectError: true,
			errorMsg:    "aggregation.checkAggregationTimeout must be greater than 0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &AggregatorConfig{Aggregation: tt.config}
			err := cfg.ValidateAggregationConfig()

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateStorageConfig(t *testing.T) {
	tests := []struct {
		name        string
		config      *StorageConfig
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid config",
			config:      &StorageConfig{PageSize: 100, MaxOpenConns: 25, MaxIdleConns: 5},
			expectError: false,
		},
		{
			name:        "zero page size fails",
			config:      &StorageConfig{PageSize: 0, MaxOpenConns: 25, MaxIdleConns: 5},
			expectError: true,
			errorMsg:    "pageSize must be greater than 0",
		},
		{
			name:        "page size exceeds limit fails",
			config:      &StorageConfig{PageSize: 1001, MaxOpenConns: 25, MaxIdleConns: 5},
			expectError: true,
			errorMsg:    "pageSize cannot exceed 1000",
		},
		{
			name:        "negative max open conns fails",
			config:      &StorageConfig{PageSize: 100, MaxOpenConns: -1, MaxIdleConns: 5},
			expectError: true,
			errorMsg:    "maxOpenConns cannot be negative",
		},
		{
			name:        "negative max idle conns fails",
			config:      &StorageConfig{PageSize: 100, MaxOpenConns: 25, MaxIdleConns: -1},
			expectError: true,
			errorMsg:    "maxIdleConns cannot be negative",
		},
		{
			name:        "max idle exceeds max open fails",
			config:      &StorageConfig{PageSize: 100, MaxOpenConns: 5, MaxIdleConns: 10},
			expectError: true,
			errorMsg:    "maxIdleConns cannot exceed storage.maxOpenConns",
		},
		{
			name:        "negative conn max lifetime fails",
			config:      &StorageConfig{PageSize: 100, MaxOpenConns: 25, MaxIdleConns: 5, ConnMaxLifetime: -1},
			expectError: true,
			errorMsg:    "connMaxLifetime cannot be negative",
		},
		{
			name:        "negative conn max idle time fails",
			config:      &StorageConfig{PageSize: 100, MaxOpenConns: 25, MaxIdleConns: 5, ConnMaxIdleTime: -1},
			expectError: true,
			errorMsg:    "connMaxIdleTime cannot be negative",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &AggregatorConfig{Storage: tt.config}
			err := cfg.ValidateStorageConfig()

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateOrphanRecoveryConfig(t *testing.T) {
	tests := []struct {
		name        string
		config      OrphanRecoveryConfig
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid enabled config",
			config:      OrphanRecoveryConfig{Enabled: true, IntervalSeconds: 60, MaxAgeHours: 24, CheckAggregationTimeout: 5 * time.Second},
			expectError: false,
		},
		{
			name:        "disabled config skips validation",
			config:      OrphanRecoveryConfig{Enabled: false, IntervalSeconds: 0, MaxAgeHours: 0, CheckAggregationTimeout: 5 * time.Second},
			expectError: false,
		},
		{
			name:        "negative scan timeout fails",
			config:      OrphanRecoveryConfig{Enabled: false, ScanTimeoutSeconds: -1, CheckAggregationTimeout: 5 * time.Second},
			expectError: true,
			errorMsg:    "scanTimeoutSeconds cannot be negative",
		},
		{
			name:        "max age hours less than 1 fails when enabled",
			config:      OrphanRecoveryConfig{Enabled: true, IntervalSeconds: 60, MaxAgeHours: 0, CheckAggregationTimeout: 5 * time.Second},
			expectError: true,
			errorMsg:    "maxAgeHours must be at least 1",
		},
		{
			name:        "interval seconds less than 5 fails when enabled",
			config:      OrphanRecoveryConfig{Enabled: true, IntervalSeconds: 4, MaxAgeHours: 24, CheckAggregationTimeout: 5 * time.Second},
			expectError: true,
			errorMsg:    "intervalSeconds must be at least 5",
		},
		{
			name:        "negative check aggregation timeout fails",
			config:      OrphanRecoveryConfig{Enabled: true, IntervalSeconds: 60, MaxAgeHours: 24, CheckAggregationTimeout: -1},
			expectError: true,
			errorMsg:    "orphanRecovery.checkAggregationTimeout must be greater than 0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &AggregatorConfig{OrphanRecovery: tt.config}
			err := cfg.ValidateOrphanRecoveryConfig()

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateCommitteeConfig(t *testing.T) {
	tests := []struct {
		name        string
		committee   *Committee
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid committee",
			committee:   createValidCommittee(),
			expectError: false,
		},
		{
			name:        "nil committee fails",
			committee:   nil,
			expectError: true,
			errorMsg:    "committee configuration cannot be nil",
		},
		{
			name: "empty quorum configs fails",
			committee: &Committee{
				QuorumConfigs:        map[string]*QuorumConfig{},
				DestinationVerifiers: map[string]string{"1": "0x1234567890abcdef1234567890abcdef12345678"},
			},
			expectError: true,
			errorMsg:    "must have at least one quorum configuration",
		},
		{
			name: "empty destination verifiers fails",
			committee: &Committee{
				QuorumConfigs: map[string]*QuorumConfig{
					"1": {Signers: []Signer{{Address: "0xaaa"}}, Threshold: 1, SourceVerifierAddress: "0x1234567890abcdef1234567890abcdef12345678"},
				},
				DestinationVerifiers: map[string]string{},
			},
			expectError: true,
			errorMsg:    "must have at least one destination verifier",
		},
		{
			name: "empty destination selector fails",
			committee: &Committee{
				QuorumConfigs: map[string]*QuorumConfig{
					"1": {Signers: []Signer{{Address: "0xaaa"}}, Threshold: 1, SourceVerifierAddress: "0x1234567890abcdef1234567890abcdef12345678"},
				},
				DestinationVerifiers: map[string]string{"": "0x1234567890abcdef1234567890abcdef12345678"},
			},
			expectError: true,
			errorMsg:    "destination selector cannot be empty",
		},
		{
			name: "invalid destination selector fails",
			committee: &Committee{
				QuorumConfigs: map[string]*QuorumConfig{
					"1": {Signers: []Signer{{Address: "0xaaa"}}, Threshold: 1, SourceVerifierAddress: "0x1234567890abcdef1234567890abcdef12345678"},
				},
				DestinationVerifiers: map[string]string{"invalid": "0x1234567890abcdef1234567890abcdef12345678"},
			},
			expectError: true,
			errorMsg:    "must be a valid uint64 decimal string",
		},
		{
			name: "empty destination verifier address fails",
			committee: &Committee{
				QuorumConfigs: map[string]*QuorumConfig{
					"1": {Signers: []Signer{{Address: "0xaaa"}}, Threshold: 1, SourceVerifierAddress: "0x1234567890abcdef1234567890abcdef12345678"},
				},
				DestinationVerifiers: map[string]string{"2": ""},
			},
			expectError: true,
			errorMsg:    "destination verifier address cannot be empty",
		},
		{
			name: "invalid destination verifier address fails",
			committee: &Committee{
				QuorumConfigs: map[string]*QuorumConfig{
					"1": {Signers: []Signer{{Address: "0xaaa"}}, Threshold: 1, SourceVerifierAddress: "0x1234567890abcdef1234567890abcdef12345678"},
				},
				DestinationVerifiers: map[string]string{"2": "not-a-hex"},
			},
			expectError: true,
			errorMsg:    "invalid destination verifier address",
		},
		{
			name: "empty source selector fails",
			committee: &Committee{
				QuorumConfigs: map[string]*QuorumConfig{
					"": {Signers: []Signer{{Address: "0xaaa"}}, Threshold: 1, SourceVerifierAddress: "0x1234567890abcdef1234567890abcdef12345678"},
				},
				DestinationVerifiers: map[string]string{"2": "0x1234567890abcdef1234567890abcdef12345678"},
			},
			expectError: true,
			errorMsg:    "source selector cannot be empty",
		},
		{
			name: "invalid source selector fails",
			committee: &Committee{
				QuorumConfigs: map[string]*QuorumConfig{
					"abc": {Signers: []Signer{{Address: "0xaaa"}}, Threshold: 1, SourceVerifierAddress: "0x1234567890abcdef1234567890abcdef12345678"},
				},
				DestinationVerifiers: map[string]string{"2": "0x1234567890abcdef1234567890abcdef12345678"},
			},
			expectError: true,
			errorMsg:    "must be a valid uint64 decimal string",
		},
		{
			name: "nil quorum config fails",
			committee: &Committee{
				QuorumConfigs: map[string]*QuorumConfig{
					"1": nil,
				},
				DestinationVerifiers: map[string]string{"2": "0x1234567890abcdef1234567890abcdef12345678"},
			},
			expectError: true,
			errorMsg:    "quorum config cannot be nil",
		},
		{
			name: "zero threshold fails",
			committee: &Committee{
				QuorumConfigs: map[string]*QuorumConfig{
					"1": {Signers: []Signer{{Address: "0xaaa"}}, Threshold: 0, SourceVerifierAddress: "0x1234567890abcdef1234567890abcdef12345678"},
				},
				DestinationVerifiers: map[string]string{"2": "0x1234567890abcdef1234567890abcdef12345678"},
			},
			expectError: true,
			errorMsg:    "threshold must be greater than 0",
		},
		{
			name: "empty signers fails",
			committee: &Committee{
				QuorumConfigs: map[string]*QuorumConfig{
					"1": {Signers: []Signer{}, Threshold: 1, SourceVerifierAddress: "0x1234567890abcdef1234567890abcdef12345678"},
				},
				DestinationVerifiers: map[string]string{"2": "0x1234567890abcdef1234567890abcdef12345678"},
			},
			expectError: true,
			errorMsg:    "must have at least one signer",
		},
		{
			name: "threshold exceeds signers fails",
			committee: &Committee{
				QuorumConfigs: map[string]*QuorumConfig{
					"1": {Signers: []Signer{{Address: "0xaaa"}}, Threshold: 2, SourceVerifierAddress: "0x1234567890abcdef1234567890abcdef12345678"},
				},
				DestinationVerifiers: map[string]string{"2": "0x1234567890abcdef1234567890abcdef12345678"},
			},
			expectError: true,
			errorMsg:    "threshold (2) cannot exceed number of signers (1)",
		},
		{
			name: "empty source verifier address fails",
			committee: &Committee{
				QuorumConfigs: map[string]*QuorumConfig{
					"1": {Signers: []Signer{{Address: "0xaaa"}}, Threshold: 1, SourceVerifierAddress: ""},
				},
				DestinationVerifiers: map[string]string{"2": "0x1234567890abcdef1234567890abcdef12345678"},
			},
			expectError: true,
			errorMsg:    "source verifier address cannot be empty",
		},
		{
			name: "invalid source verifier address fails",
			committee: &Committee{
				QuorumConfigs: map[string]*QuorumConfig{
					"1": {Signers: []Signer{{Address: "0xaaa"}}, Threshold: 1, SourceVerifierAddress: "not-hex"},
				},
				DestinationVerifiers: map[string]string{"2": "0x1234567890abcdef1234567890abcdef12345678"},
			},
			expectError: true,
			errorMsg:    "invalid source verifier address",
		},
		{
			name: "empty signer address fails",
			committee: &Committee{
				QuorumConfigs: map[string]*QuorumConfig{
					"1": {Signers: []Signer{{Address: ""}}, Threshold: 1, SourceVerifierAddress: "0x1234567890abcdef1234567890abcdef12345678"},
				},
				DestinationVerifiers: map[string]string{"2": "0x1234567890abcdef1234567890abcdef12345678"},
			},
			expectError: true,
			errorMsg:    "signer address cannot be empty",
		},
		{
			name: "duplicate signer addresses fails",
			committee: &Committee{
				QuorumConfigs: map[string]*QuorumConfig{
					"1": {
						Signers: []Signer{
							{Address: "0xaaa"},
							{Address: "0xAAA"}, // same address different case
						},
						Threshold:             1,
						SourceVerifierAddress: "0x1234567890abcdef1234567890abcdef12345678",
					},
				},
				DestinationVerifiers: map[string]string{"2": "0x1234567890abcdef1234567890abcdef12345678"},
			},
			expectError: true,
			errorMsg:    "duplicate signer address",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &AggregatorConfig{Committee: tt.committee}
			err := cfg.ValidateCommitteeConfig()

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateCommitteeConfig_ParsesAddresses(t *testing.T) {
	cfg := &AggregatorConfig{Committee: createValidCommittee()}
	err := cfg.ValidateCommitteeConfig()
	require.NoError(t, err)

	destAddr, exists := cfg.Committee.GetDestinationVerifierAddress(2)
	assert.True(t, exists)
	assert.NotEmpty(t, destAddr)

	quorumCfg, exists := cfg.Committee.GetQuorumConfig(1)
	assert.True(t, exists)
	assert.NotNil(t, quorumCfg.GetSourceVerifierAddress())
}

func TestCommittee_GetQuorumConfig(t *testing.T) {
	committee := createValidCommittee()

	t.Run("returns config for existing selector", func(t *testing.T) {
		cfg, exists := committee.GetQuorumConfig(1)
		assert.True(t, exists)
		assert.NotNil(t, cfg)
	})

	t.Run("returns false for non-existing selector", func(t *testing.T) {
		cfg, exists := committee.GetQuorumConfig(999)
		assert.False(t, exists)
		assert.Nil(t, cfg)
	})
}

func TestCommittee_GetDestinationVerifierAddress(t *testing.T) {
	cfg := &AggregatorConfig{Committee: createValidCommittee()}
	require.NoError(t, cfg.ValidateCommitteeConfig())

	t.Run("returns address for existing selector", func(t *testing.T) {
		addr, exists := cfg.Committee.GetDestinationVerifierAddress(2)
		assert.True(t, exists)
		assert.NotEmpty(t, addr)
	})

	t.Run("returns false for non-existing selector", func(t *testing.T) {
		addr, exists := cfg.Committee.GetDestinationVerifierAddress(999)
		assert.False(t, exists)
		assert.Empty(t, addr)
	})
}

func TestValidate_IntegrationWithAllValidators(t *testing.T) {
	t.Run("valid config passes all validations", func(t *testing.T) {
		cfg := createMinimalValidConfig()
		err := cfg.Validate()
		require.NoError(t, err)
	})

	t.Run("invalid server config fails", func(t *testing.T) {
		cfg := createMinimalValidConfig()
		cfg.Server.RequestTimeoutSeconds = -1
		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "server configuration error")
	})

	t.Run("invalid committee config fails", func(t *testing.T) {
		cfg := createMinimalValidConfig()
		cfg.Committee = nil
		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "committee configuration error")
	})
}

func TestGetEffectiveLimit(t *testing.T) {
	tests := []struct {
		name           string
		config         RateLimitingConfig
		callerID       string
		method         string
		clientGroups   []string
		expectedLimit  *int
		expectedNilVal bool
	}{
		{
			name: "returns caller-specific limit when exists",
			config: RateLimitingConfig{
				Limits: map[string]map[string]RateLimitConfig{
					"caller1": {"method1": {LimitPerMinute: 100}},
				},
			},
			callerID:      "caller1",
			method:        "method1",
			expectedLimit: intPtr(100),
		},
		{
			name: "returns group limit when no caller limit",
			config: RateLimitingConfig{
				GroupLimits: map[string]map[string]RateLimitConfig{
					"group1": {"method1": {LimitPerMinute: 50}},
				},
			},
			callerID:      "caller1",
			method:        "method1",
			clientGroups:  []string{"group1"},
			expectedLimit: intPtr(50),
		},
		{
			name: "returns most restrictive group limit",
			config: RateLimitingConfig{
				GroupLimits: map[string]map[string]RateLimitConfig{
					"group1": {"method1": {LimitPerMinute: 100}},
					"group2": {"method1": {LimitPerMinute: 50}},
				},
			},
			callerID:      "caller1",
			method:        "method1",
			clientGroups:  []string{"group1", "group2"},
			expectedLimit: intPtr(50),
		},
		{
			name: "returns default limit when no caller or group limit",
			config: RateLimitingConfig{
				DefaultLimits: map[string]RateLimitConfig{
					"method1": {LimitPerMinute: 25},
				},
			},
			callerID:      "caller1",
			method:        "method1",
			expectedLimit: intPtr(25),
		},
		{
			name:           "returns nil when no limit configured",
			config:         RateLimitingConfig{},
			callerID:       "caller1",
			method:         "method1",
			expectedNilVal: true,
		},
		{
			name: "caller limit takes priority over group limit",
			config: RateLimitingConfig{
				Limits: map[string]map[string]RateLimitConfig{
					"caller1": {"method1": {LimitPerMinute: 200}},
				},
				GroupLimits: map[string]map[string]RateLimitConfig{
					"group1": {"method1": {LimitPerMinute: 50}},
				},
			},
			callerID:      "caller1",
			method:        "method1",
			clientGroups:  []string{"group1"},
			expectedLimit: intPtr(200),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var client auth.ClientConfig
			if len(tt.clientGroups) > 0 {
				client = &mockClientConfig{groups: tt.clientGroups}
			}

			result := tt.config.GetEffectiveLimit(tt.callerID, tt.method, client)

			if tt.expectedNilVal {
				assert.Nil(t, result)
			} else {
				require.NotNil(t, result)
				assert.Equal(t, *tt.expectedLimit, result.LimitPerMinute)
			}
		})
	}
}

type mockClientConfig struct {
	clientID string
	groups   []string
	enabled  bool
}

func (m *mockClientConfig) GetClientID() string { return m.clientID }
func (m *mockClientConfig) GetGroups() []string { return m.groups }
func (m *mockClientConfig) IsEnabled() bool     { return m.enabled }

func intPtr(i int) *int {
	return &i
}

func TestGetClientByAPIKey(t *testing.T) {
	creds := hmacutil.MustGenerateCredentials()

	t.Run("finds client by API key", func(t *testing.T) {
		t.Setenv("TEST_API_KEY", creds.APIKey)
		t.Setenv("TEST_SECRET", creds.Secret)

		cfg := &AggregatorConfig{
			APIClients: []*ClientConfig{
				{
					ClientID: "client1",
					APIKeyPairs: []*APIKeyPairEnv{
						{APIKeyEnvVar: "TEST_API_KEY", SecretEnvVar: "TEST_SECRET"},
					},
				},
			},
		}

		client, pair, found := cfg.GetClientByAPIKey(creds.APIKey)
		assert.True(t, found)
		assert.NotNil(t, client)
		assert.NotNil(t, pair)
		assert.Equal(t, "client1", client.GetClientID())
	})

	t.Run("returns false for unknown API key", func(t *testing.T) {
		cfg := &AggregatorConfig{}
		client, pair, found := cfg.GetClientByAPIKey("unknown")
		assert.False(t, found)
		assert.Nil(t, client)
		assert.Nil(t, pair)
	})
}

func TestGetClientByClientID(t *testing.T) {
	t.Run("finds client by ID", func(t *testing.T) {
		cfg := &AggregatorConfig{
			APIClients: []*ClientConfig{
				{ClientID: "client1"},
				{ClientID: "client2"},
			},
		}

		client, found := cfg.GetClientByClientID("client2")
		assert.True(t, found)
		assert.NotNil(t, client)
		assert.Equal(t, "client2", client.GetClientID())
	})

	t.Run("returns false for unknown client ID", func(t *testing.T) {
		cfg := &AggregatorConfig{}
		client, found := cfg.GetClientByClientID("unknown")
		assert.False(t, found)
		assert.Nil(t, client)
	})
}

func TestAPIKeyPairEnv_Validate(t *testing.T) {
	creds := hmacutil.MustGenerateCredentials()

	tests := []struct {
		name        string
		setupEnv    func()
		pair        APIKeyPairEnv
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid API key pair",
			setupEnv: func() {
				os.Setenv("VALID_API_KEY", creds.APIKey)
				os.Setenv("VALID_SECRET", creds.Secret)
			},
			pair:        APIKeyPairEnv{APIKeyEnvVar: "VALID_API_KEY", SecretEnvVar: "VALID_SECRET"},
			expectError: false,
		},
		{
			name:        "empty API key env var fails",
			setupEnv:    func() {},
			pair:        APIKeyPairEnv{APIKeyEnvVar: "", SecretEnvVar: "SECRET"},
			expectError: true,
			errorMsg:    "apiKeyEnvVar cannot be empty",
		},
		{
			name:        "empty secret env var fails",
			setupEnv:    func() {},
			pair:        APIKeyPairEnv{APIKeyEnvVar: "KEY", SecretEnvVar: ""},
			expectError: true,
			errorMsg:    "secretEnvVar cannot be empty",
		},
		{
			name:        "missing API key env var fails",
			setupEnv:    func() {},
			pair:        APIKeyPairEnv{APIKeyEnvVar: "MISSING_KEY", SecretEnvVar: "SECRET"},
			expectError: true,
			errorMsg:    "environment variable MISSING_KEY not found",
		},
		{
			name: "invalid API key format fails",
			setupEnv: func() {
				os.Setenv("INVALID_API_KEY", "too-short")
				os.Setenv("VALID_SECRET_2", creds.Secret)
			},
			pair:        APIKeyPairEnv{APIKeyEnvVar: "INVALID_API_KEY", SecretEnvVar: "VALID_SECRET_2"},
			expectError: true,
			errorMsg:    "invalid API key",
		},
		{
			name: "missing secret env var fails",
			setupEnv: func() {
				os.Setenv("VALID_API_KEY_3", creds.APIKey)
			},
			pair:        APIKeyPairEnv{APIKeyEnvVar: "VALID_API_KEY_3", SecretEnvVar: "MISSING_SECRET"},
			expectError: true,
			errorMsg:    "environment variable MISSING_SECRET not found",
		},
		{
			name: "invalid secret format fails",
			setupEnv: func() {
				os.Setenv("VALID_API_KEY_4", creds.APIKey)
				os.Setenv("INVALID_SECRET", "too-short")
			},
			pair:        APIKeyPairEnv{APIKeyEnvVar: "VALID_API_KEY_4", SecretEnvVar: "INVALID_SECRET"},
			expectError: true,
			errorMsg:    "invalid secret",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Clearenv()
			tt.setupEnv()

			err := tt.pair.Validate()

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestClientConfig_Validate(t *testing.T) {
	creds := hmacutil.MustGenerateCredentials()

	tests := []struct {
		name        string
		setupEnv    func()
		config      ClientConfig
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid client config",
			setupEnv: func() {
				os.Setenv("VALID_KEY", creds.APIKey)
				os.Setenv("VALID_SEC", creds.Secret)
			},
			config: ClientConfig{
				ClientID:    "client1",
				APIKeyPairs: []*APIKeyPairEnv{{APIKeyEnvVar: "VALID_KEY", SecretEnvVar: "VALID_SEC"}},
			},
			expectError: false,
		},
		{
			name: "empty client ID fails",
			setupEnv: func() {
				os.Setenv("KEY", creds.APIKey)
				os.Setenv("SEC", creds.Secret)
			},
			config: ClientConfig{
				ClientID:    "",
				APIKeyPairs: []*APIKeyPairEnv{{APIKeyEnvVar: "KEY", SecretEnvVar: "SEC"}},
			},
			expectError: true,
			errorMsg:    "clientId cannot be empty",
		},
		{
			name:        "empty API key pairs fails",
			setupEnv:    func() {},
			config:      ClientConfig{ClientID: "client1", APIKeyPairs: []*APIKeyPairEnv{}},
			expectError: true,
			errorMsg:    "apiKeyPair cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Clearenv()
			tt.setupEnv()

			err := tt.config.Validate()

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestClientConfig_Getters(t *testing.T) {
	cfg := &ClientConfig{
		ClientID: "test-client",
		Groups:   []string{"group1", "group2"},
		Enabled:  true,
	}

	assert.Equal(t, "test-client", cfg.GetClientID())
	assert.Equal(t, []string{"group1", "group2"}, cfg.GetGroups())
	assert.True(t, cfg.IsEnabled())
}

func TestLoadFromEnvironment(t *testing.T) {
	t.Run("loads postgres connection URL", func(t *testing.T) {
		t.Setenv("AGGREGATOR_STORAGE_CONNECTION_URL", "postgres://localhost:5432/test")

		cfg := &AggregatorConfig{
			Storage: &StorageConfig{StorageType: StorageTypePostgreSQL},
		}
		err := cfg.LoadFromEnvironment()
		require.NoError(t, err)
		assert.Equal(t, "postgres://localhost:5432/test", cfg.Storage.ConnectionURL)
	})

	t.Run("fails when postgres URL missing", func(t *testing.T) {
		cfg := &AggregatorConfig{
			Storage: &StorageConfig{StorageType: StorageTypePostgreSQL},
		}
		err := cfg.LoadFromEnvironment()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "AGGREGATOR_STORAGE_CONNECTION_URL")
	})

	t.Run("loads redis config when rate limiting enabled", func(t *testing.T) {
		t.Setenv("AGGREGATOR_REDIS_ADDRESS", "localhost:6379")
		t.Setenv("AGGREGATOR_REDIS_PASSWORD", "secret")
		t.Setenv("AGGREGATOR_REDIS_DB", "1")

		cfg := &AggregatorConfig{
			Storage: &StorageConfig{},
			RateLimiting: RateLimitingConfig{
				Enabled: true,
				Storage: RateLimiterStoreConfig{Type: RateLimiterStoreTypeRedis},
			},
		}
		err := cfg.LoadFromEnvironment()
		require.NoError(t, err)
		assert.Equal(t, "localhost:6379", cfg.RateLimiting.Storage.Redis.Address)
		assert.Equal(t, "secret", cfg.RateLimiting.Storage.Redis.Password)
		assert.Equal(t, 1, cfg.RateLimiting.Storage.Redis.DB)
	})

	t.Run("fails when redis address missing", func(t *testing.T) {
		cfg := &AggregatorConfig{
			Storage: &StorageConfig{},
			RateLimiting: RateLimitingConfig{
				Enabled: true,
				Storage: RateLimiterStoreConfig{Type: RateLimiterStoreTypeRedis},
			},
		}
		err := cfg.LoadFromEnvironment()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "AGGREGATOR_REDIS_ADDRESS")
	})

	t.Run("fails with invalid redis DB value", func(t *testing.T) {
		t.Setenv("AGGREGATOR_REDIS_ADDRESS", "localhost:6379")
		t.Setenv("AGGREGATOR_REDIS_DB", "not-a-number")

		cfg := &AggregatorConfig{
			Storage: &StorageConfig{},
			RateLimiting: RateLimitingConfig{
				Enabled: true,
				Storage: RateLimiterStoreConfig{Type: RateLimiterStoreTypeRedis},
			},
		}
		err := cfg.LoadFromEnvironment()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid AGGREGATOR_REDIS_DB value")
	})
}

func TestQuorumConfig_GetSourceVerifierAddress(t *testing.T) {
	cfg := &AggregatorConfig{Committee: createValidCommittee()}
	require.NoError(t, cfg.ValidateCommitteeConfig())

	quorumCfg, exists := cfg.Committee.GetQuorumConfig(1)
	require.True(t, exists)

	addr := quorumCfg.GetSourceVerifierAddress()
	assert.NotEmpty(t, addr)
}

func TestAPIKeyPairEnv_Getters(t *testing.T) {
	t.Setenv("TEST_KEY", "test-api-key")
	t.Setenv("TEST_SEC", "test-secret")

	pair := &APIKeyPairEnv{APIKeyEnvVar: "TEST_KEY", SecretEnvVar: "TEST_SEC"}

	assert.Equal(t, "test-api-key", pair.GetAPIKey())
	assert.Equal(t, "test-secret", pair.GetSecret())
}
