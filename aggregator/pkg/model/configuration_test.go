package model

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAggregationConfig_SetDefaults(t *testing.T) {
	config := &AggregatorConfig{}
	config.SetDefaults()

	// Test aggregation defaults
	require.Equal(t, 1000, config.Aggregation.MessageChannelSize)
	require.Equal(t, 5, config.Aggregation.OrphanRecoveryIntervalMinutes)

	// Test other defaults are still set
	require.Equal(t, 1000, config.Checkpoints.MaxCheckpointsPerRequest)
	require.Equal(t, 1000, config.APIKeys.MaxAPIKeyLength)
	require.NotNil(t, config.APIKeys.Clients)
}

func TestAggregationConfig_ValidateAggregationConfig(t *testing.T) {
	testCases := []struct {
		name        string
		config      AggregationConfig
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid configuration",
			config: AggregationConfig{
				MessageChannelSize:            1000,
				OrphanRecoveryIntervalMinutes: 5,
			},
			expectError: false,
		},
		{
			name: "zero channel size",
			config: AggregationConfig{
				MessageChannelSize:            0,
				OrphanRecoveryIntervalMinutes: 5,
			},
			expectError: true,
			errorMsg:    "aggregation.messageChannelSize must be greater than 0",
		},
		{
			name: "negative channel size",
			config: AggregationConfig{
				MessageChannelSize:            -1,
				OrphanRecoveryIntervalMinutes: 5,
			},
			expectError: true,
			errorMsg:    "aggregation.messageChannelSize must be greater than 0",
		},
		{
			name: "zero recovery interval",
			config: AggregationConfig{
				MessageChannelSize:            1000,
				OrphanRecoveryIntervalMinutes: 0,
			},
			expectError: true,
			errorMsg:    "aggregation.orphanRecoveryIntervalMinutes must be greater than 0",
		},
		{
			name: "negative recovery interval",
			config: AggregationConfig{
				MessageChannelSize:            1000,
				OrphanRecoveryIntervalMinutes: -1,
			},
			expectError: true,
			errorMsg:    "aggregation.orphanRecoveryIntervalMinutes must be greater than 0",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			aggregatorConfig := &AggregatorConfig{
				Aggregation: tc.config,
			}

			err := aggregatorConfig.ValidateAggregationConfig()

			if tc.expectError {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.errorMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestAggregatorConfig_Validate_WithAggregationConfig(t *testing.T) {
	config := &AggregatorConfig{
		Aggregation: AggregationConfig{
			MessageChannelSize:            -1, // Invalid negative value (won't be overridden by defaults)
			OrphanRecoveryIntervalMinutes: 5,
		},
	}

	err := config.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), "aggregation configuration error")
	require.Contains(t, err.Error(), "aggregation.messageChannelSize must be greater than 0")
}

func TestAggregationConfig_CustomValues(t *testing.T) {
	// Test that custom values are preserved and not overridden by defaults
	config := &AggregatorConfig{
		Aggregation: AggregationConfig{
			MessageChannelSize:            2000,
			OrphanRecoveryIntervalMinutes: 10,
		},
	}

	config.SetDefaults()

	// Custom values should be preserved
	require.Equal(t, 2000, config.Aggregation.MessageChannelSize)
	require.Equal(t, 10, config.Aggregation.OrphanRecoveryIntervalMinutes)

	// Should pass validation
	err := config.ValidateAggregationConfig()
	require.NoError(t, err)
}
