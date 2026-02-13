package executor

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestConfiguration_Validate(t *testing.T) {
	cases := []struct {
		name            string
		config          Configuration
		wantErr         bool
		wantErrContains string
	}{
		{
			name: "valid_with_single_indexer_address",
			config: Configuration{
				ExecutorID:     "executor-1",
				IndexerAddress: []string{"http://indexer1:8100"},
				ChainConfiguration: map[string]ChainConfiguration{
					"1": {
						ExecutorPool: []string{"executor-1", "executor-2"},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid_with_multiple_indexer_addresses",
			config: Configuration{
				ExecutorID:     "executor-1",
				IndexerAddress: []string{"http://indexer1:8100", "http://indexer2:8100", "http://indexer3:8100"},
				ChainConfiguration: map[string]ChainConfiguration{
					"1": {
						ExecutorPool: []string{"executor-1", "executor-2"},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "missing_executor_id_fails",
			config: Configuration{
				IndexerAddress: []string{"http://indexer:8100"},
				ChainConfiguration: map[string]ChainConfiguration{
					"1": {
						ExecutorPool: []string{"executor-1", "executor-2"},
					},
				},
			},
			wantErr:         true,
			wantErrContains: "this_executor_id must be configured",
		},
		{
			name: "missing_indexer_address_fails",
			config: Configuration{
				ExecutorID: "executor-1",
				ChainConfiguration: map[string]ChainConfiguration{
					"1": {
						ExecutorPool: []string{"executor-1", "executor-2"},
					},
				},
			},
			wantErr:         true,
			wantErrContains: "at least one indexer address must be configured",
		},
		{
			name: "empty_indexer_address_slice_fails",
			config: Configuration{
				ExecutorID:     "executor-1",
				IndexerAddress: []string{},
				ChainConfiguration: map[string]ChainConfiguration{
					"1": {
						ExecutorPool: []string{"executor-1", "executor-2"},
					},
				},
			},
			wantErr:         true,
			wantErrContains: "at least one indexer address must be configured",
		},
		{
			name: "empty_executor_pool_fails",
			config: Configuration{
				ExecutorID:     "executor-1",
				IndexerAddress: []string{"http://indexer:8100"},
				ChainConfiguration: map[string]ChainConfiguration{
					"1": {
						ExecutorPool: []string{},
					},
				},
			},
			wantErr:         true,
			wantErrContains: "executor_pool must be configured",
		},
		{
			name: "executor_not_in_pool_fails",
			config: Configuration{
				ExecutorID:     "executor-3",
				IndexerAddress: []string{"http://indexer:8100"},
				ChainConfiguration: map[string]ChainConfiguration{
					"1": {
						ExecutorPool: []string{"executor-1", "executor-2"},
					},
				},
			},
			wantErr:         true,
			wantErrContains: "not found in executor_pool",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.config.Validate()

			if tc.wantErr {
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
		name                      string
		config                    Configuration
		wantErr                   bool
		wantErrContains           string
		wantIndexerAddressCount   int
		wantBackoffDuration       time.Duration
		wantLookbackWindow        time.Duration
		wantReaderCacheExpiry     time.Duration
		wantMaxRetryDuration      time.Duration
		wantExecutionInterval     time.Duration
		wantNtpServer             string
		wantWorkerCount           int
		wantIndexerQueryLimit     uint64
	}{
		{
			name: "single_indexer_address_with_defaults",
			config: Configuration{
				ExecutorID:     "executor-1",
				IndexerAddress: []string{"http://indexer:8100"},
				ChainConfiguration: map[string]ChainConfiguration{
					"1": {
						ExecutorPool: []string{"executor-1"},
					},
				},
			},
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
			config: Configuration{
				ExecutorID:     "executor-1",
				IndexerAddress: []string{"http://indexer1:8100", "http://indexer2:8100"},
				ChainConfiguration: map[string]ChainConfiguration{
					"1": {
						ExecutorPool: []string{"executor-1"},
					},
				},
			},
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
			config: Configuration{
				ExecutorID:        "executor-1",
				IndexerAddress:    []string{"http://indexer:8100"},
				BackoffDuration:   30 * time.Second,
				LookbackWindow:    2 * time.Hour,
				ReaderCacheExpiry: 10 * time.Minute,
				MaxRetryDuration:  12 * time.Hour,
				NtpServer:         "custom.ntp.com",
				WorkerCount:       200,
				IndexerQueryLimit: 500,
				ChainConfiguration: map[string]ChainConfiguration{
					"1": {
						ExecutorPool:      []string{"executor-1"},
						ExecutionInterval: 2 * time.Minute,
					},
				},
			},
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
			config: Configuration{
				ExecutorID:     "executor-1",
				IndexerAddress: []string{"http://indexer:8100"},
				ChainConfiguration: map[string]ChainConfiguration{
					"1": {
						ExecutorPool: []string{"executor-1"},
					},
				},
			},
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
			config: Configuration{
				ExecutorID:     "", // Invalid: missing executor ID
				IndexerAddress: []string{"http://indexer:8100"},
				ChainConfiguration: map[string]ChainConfiguration{
					"1": {
						ExecutorPool: []string{"executor-1"},
					},
				},
			},
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

				// Check execution interval for chain config
				for _, chainConfig := range normalized.ChainConfiguration {
					require.Equal(t, tc.wantExecutionInterval, chainConfig.ExecutionInterval)
				}
			}
		})
	}
}

