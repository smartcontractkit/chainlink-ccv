package executor

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func validChainConfig() ChainConfiguration {
	return ChainConfiguration{
		RmnAddress:     "0x1234567890abcdef",
		OffRampAddress: "0xabcdef1234567890",
		ExecutorPool:   []string{"executor-1", "executor-2"},
	}
}

func validConfig() Configuration {
	return Configuration{
		ExecutorID:     "executor-1",
		IndexerAddress: []string{"http://indexer1:8100"},
		ChainConfiguration: map[string]ChainConfiguration{
			"1": validChainConfig(),
		},
	}
}

func TestConfiguration_Validate(t *testing.T) {
	cases := []struct {
		name            string
		config          Configuration
		wantErrContains string
	}{
		{
			name:   "valid_with_single_indexer_address",
			config: validConfig(),
		},
		{
			name: "valid_with_multiple_indexer_addresses",
			config: func() Configuration {
				c := validConfig()
				c.IndexerAddress = []string{"http://indexer1:8100", "http://indexer2:8100", "http://indexer3:8100"}
				return c
			}(),
		},
		{
			name: "missing_executor_id_fails",
			config: func() Configuration {
				c := validConfig()
				c.ExecutorID = ""
				return c
			}(),
			wantErrContains: "this_executor_id must be configured",
		},
		{
			name: "missing_indexer_address_fails",
			config: func() Configuration {
				c := validConfig()
				c.IndexerAddress = nil
				return c
			}(),
			wantErrContains: "at least one indexer address must be configured",
		},
		{
			name: "empty_indexer_address_slice_fails",
			config: func() Configuration {
				c := validConfig()
				c.IndexerAddress = []string{}
				return c
			}(),
			wantErrContains: "at least one indexer address must be configured",
		},
		{
			name: "empty_string_in_indexer_address_fails",
			config: func() Configuration {
				c := validConfig()
				c.IndexerAddress = []string{"http://indexer1:8100", ""}
				return c
			}(),
			wantErrContains: "indexer address must not be empty",
		},
		{
			name: "empty_executor_pool_fails",
			config: func() Configuration {
				c := validConfig()
				cc := validChainConfig()
				cc.ExecutorPool = []string{}
				c.ChainConfiguration = map[string]ChainConfiguration{"1": cc}
				return c
			}(),
			wantErrContains: "executor_pool must be configured",
		},
		{
			name: "executor_not_in_pool_fails",
			config: func() Configuration {
				c := validConfig()
				c.ExecutorID = "executor-3"
				return c
			}(),
			wantErrContains: "not found in executor_pool",
		},
		{
			name: "invalid_with_no_configurations",
			config: func() Configuration {
				c := validConfig()
				c.ChainConfiguration = map[string]ChainConfiguration{}
				return c
			}(),
			wantErrContains: "at least one chain must be configured",
		},
		{
			name: "negative_worker_count_fails",
			config: func() Configuration {
				c := validConfig()
				c.WorkerCount = -1
				return c
			}(),
			wantErrContains: "worker_count must not be negative",
		},
		{
			name: "negative_backoff_duration_fails",
			config: func() Configuration {
				c := validConfig()
				c.BackoffDuration = -1 * time.Second
				return c
			}(),
			wantErrContains: "source_backoff_duration must not be negative",
		},
		{
			name: "negative_lookback_window_fails",
			config: func() Configuration {
				c := validConfig()
				c.LookbackWindow = -1 * time.Second
				return c
			}(),
			wantErrContains: "startup_lookback_window must not be negative",
		},
		{
			name: "indexer_query_limit_exceeds_max_fails",
			config: func() Configuration {
				c := validConfig()
				c.IndexerQueryLimit = IndexerQueryLimitMax + 1
				return c
			}(),
			wantErrContains: "indexer_query_limit must not exceed",
		},
		{
			name: "missing_rmn_address_fails",
			config: func() Configuration {
				c := validConfig()
				cc := validChainConfig()
				cc.RmnAddress = ""
				c.ChainConfiguration = map[string]ChainConfiguration{"1": cc}
				return c
			}(),
			wantErrContains: "rmn_address must be configured",
		},
		{
			name: "missing_offramp_address_fails",
			config: func() Configuration {
				c := validConfig()
				cc := validChainConfig()
				cc.OffRampAddress = ""
				c.ChainConfiguration = map[string]ChainConfiguration{"1": cc}
				return c
			}(),
			wantErrContains: "off_ramp_address must be configured",
		},
		{
			name: "monitoring_enabled_without_type_fails",
			config: func() Configuration {
				c := validConfig()
				c.Monitoring = MonitoringConfig{Enabled: true, Type: ""}
				return c
			}(),
			wantErrContains: "monitoring type is required",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.config.Validate()

			if tc.wantErrContains != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.wantErrContains)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestConfiguration_GetNormalizedConfig(t *testing.T) {
	cases := []struct {
		name                    string
		config                  Configuration
		wantErr                 bool
		wantErrContains         string
		wantIndexerAddressCount int
		wantBackoffDuration     time.Duration
		wantLookbackWindow      time.Duration
		wantReaderCacheExpiry   time.Duration
		wantMaxRetryDuration    time.Duration
		wantExecutionInterval   time.Duration
		wantNtpServer           string
		wantWorkerCount         int
		wantIndexerQueryLimit   uint64
	}{
		{
			name:                    "single_indexer_address_with_defaults",
			config:                  validConfig(),
			wantErr:                 false,
			wantIndexerAddressCount: 1,
			wantBackoffDuration:     backoffDurationDefault,
			wantLookbackWindow:      lookbackWindowDefault,
			wantReaderCacheExpiry:   readerCacheExpiryDefault,
			wantMaxRetryDuration:    maxRetryDurationDefault,
			wantExecutionInterval:   executionIntervalDefault,
			wantNtpServer:           ntpServerDefault,
			wantWorkerCount:         workerCountDefault,
			wantIndexerQueryLimit:   IndexerQueryLimitDefault,
		},
		{
			name: "multiple_indexer_addresses",
			config: func() Configuration {
				c := validConfig()
				c.IndexerAddress = []string{"http://indexer1:8100", "http://indexer2:8100"}
				return c
			}(),
			wantErr:                 false,
			wantIndexerAddressCount: 2,
			wantBackoffDuration:     backoffDurationDefault,
			wantLookbackWindow:      lookbackWindowDefault,
			wantReaderCacheExpiry:   readerCacheExpiryDefault,
			wantMaxRetryDuration:    maxRetryDurationDefault,
			wantExecutionInterval:   executionIntervalDefault,
			wantNtpServer:           ntpServerDefault,
			wantWorkerCount:         workerCountDefault,
			wantIndexerQueryLimit:   IndexerQueryLimitDefault,
		},
		{
			name: "custom_values_preserved",
			config: func() Configuration {
				c := validConfig()
				c.IndexerAddress = []string{"http://indexer:8100"}
				c.BackoffDuration = 30 * time.Second
				c.LookbackWindow = 2 * time.Hour
				c.ReaderCacheExpiry = 10 * time.Minute
				c.MaxRetryDuration = 12 * time.Hour
				c.NtpServer = "custom.ntp.com"
				c.WorkerCount = 200
				c.IndexerQueryLimit = 500
				cc := validChainConfig()
				cc.ExecutorPool = []string{"executor-1"}
				cc.ExecutionInterval = 2 * time.Minute
				c.ChainConfiguration = map[string]ChainConfiguration{"1": cc}
				return c
			}(),
			wantErr:                 false,
			wantIndexerAddressCount: 1,
			wantBackoffDuration:     30 * time.Second,
			wantLookbackWindow:      2 * time.Hour,
			wantReaderCacheExpiry:   10 * time.Minute,
			wantMaxRetryDuration:    12 * time.Hour,
			wantExecutionInterval:   2 * time.Minute,
			wantNtpServer:           "custom.ntp.com",
			wantWorkerCount:         200,
			wantIndexerQueryLimit:   500,
		},
		{
			name: "defaults_applied_when_zero",
			config: func() Configuration {
				c := validConfig()
				cc := validChainConfig()
				cc.ExecutorPool = []string{"executor-1"}
				c.ChainConfiguration = map[string]ChainConfiguration{"1": cc}
				return c
			}(),
			wantErr:                 false,
			wantIndexerAddressCount: 1,
			wantBackoffDuration:     backoffDurationDefault,
			wantLookbackWindow:      lookbackWindowDefault,
			wantReaderCacheExpiry:   readerCacheExpiryDefault,
			wantMaxRetryDuration:    maxRetryDurationDefault,
			wantExecutionInterval:   executionIntervalDefault,
			wantNtpServer:           ntpServerDefault,
			wantWorkerCount:         workerCountDefault,
			wantIndexerQueryLimit:   IndexerQueryLimitDefault,
		},
		{
			name: "validation_errors_propagated",
			config: func() Configuration {
				c := validConfig()
				c.ExecutorID = ""
				return c
			}(),
			wantErr:         true,
			wantErrContains: "this_executor_id must be configured",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			normalized, err := tc.config.GetNormalizedConfig()

			if tc.wantErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.wantErrContains)
				require.Nil(t, normalized)
			} else {
				require.NoError(t, err)
				require.NotNil(t, normalized)
				require.Equal(t, tc.wantIndexerAddressCount, len(normalized.IndexerAddress))
				require.Equal(t, tc.wantBackoffDuration, normalized.BackoffDuration)
				require.Equal(t, tc.wantLookbackWindow, normalized.LookbackWindow)
				require.Equal(t, tc.wantReaderCacheExpiry, normalized.ReaderCacheExpiry)
				require.Equal(t, tc.wantMaxRetryDuration, normalized.MaxRetryDuration)
				require.Equal(t, tc.wantNtpServer, normalized.NtpServer)
				require.Equal(t, tc.wantWorkerCount, normalized.WorkerCount)
				require.Equal(t, tc.wantIndexerQueryLimit, normalized.IndexerQueryLimit)

				for _, chainConfig := range normalized.ChainConfiguration {
					require.Equal(t, tc.wantExecutionInterval, chainConfig.ExecutionInterval)
				}
			}
		})
	}
}
