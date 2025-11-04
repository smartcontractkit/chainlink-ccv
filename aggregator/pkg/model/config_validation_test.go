package model

import (
	"testing"
)

func TestAggregatorConfig_Validate_ErrorScenarios(t *testing.T) {
	tests := []struct {
		name            string
		mutate          func(c *AggregatorConfig)
		wantErrContains string
	}{
		{
			name:            "chainStatuses must be >0",
			mutate:          func(c *AggregatorConfig) { c.ChainStatuses.MaxChainStatusesPerRequest = -1 },
			wantErrContains: "chain status configuration error",
		},
		{
			name:            "batch size must be >0",
			mutate:          func(c *AggregatorConfig) { c.MaxMessageIDsPerBatch = -1 },
			wantErrContains: "batch configuration error",
		},
		{
			name:            "batch size cannot exceed 1000",
			mutate:          func(c *AggregatorConfig) { c.MaxMessageIDsPerBatch = 2000 },
			wantErrContains: "batch configuration error",
		},
		{
			name:            "aggregation.channelBufferSize must be >0",
			mutate:          func(c *AggregatorConfig) { c.Aggregation.ChannelBufferSize = -1 },
			wantErrContains: "aggregation configuration error",
		},
		{
			name:            "aggregation.backgroundWorkerCount must be >0",
			mutate:          func(c *AggregatorConfig) { c.Aggregation.BackgroundWorkerCount = -1 },
			wantErrContains: "aggregation configuration error",
		},
		{
			name:            "storage.pageSize must be >0",
			mutate:          func(c *AggregatorConfig) { c.Storage.PageSize = -1 },
			wantErrContains: "storage configuration error",
		},
		{
			name: "invalid API key empty id",
			mutate: func(c *AggregatorConfig) {
				c.APIKeys.Clients["abc"] = &APIClient{ClientID: ""}
			},
			wantErrContains: "api key configuration error",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &AggregatorConfig{
				Storage:               &StorageConfig{PageSize: 10},
				APIKeys:               APIKeyConfig{Clients: map[string]*APIClient{}},
				ChainStatuses:         ChainStatusConfig{MaxChainStatusesPerRequest: 1},
				Aggregation:           AggregationConfig{ChannelBufferSize: 1, BackgroundWorkerCount: 1},
				MaxMessageIDsPerBatch: 1,
			}
			tc.mutate(cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatalf("expected error containing %q", tc.wantErrContains)
			}
		})
	}
}

func TestAggregatorConfig_Validate_Success(t *testing.T) {
	cfg := &AggregatorConfig{
		Storage:               &StorageConfig{PageSize: 10},
		APIKeys:               APIKeyConfig{Clients: map[string]*APIClient{"key1": {ClientID: "client1"}}},
		ChainStatuses:         ChainStatusConfig{MaxChainStatusesPerRequest: 1},
		Aggregation:           AggregationConfig{ChannelBufferSize: 10, BackgroundWorkerCount: 2},
		MaxMessageIDsPerBatch: 10,
		RateLimiting:          RateLimitingConfig{GroupLimits: map[string]map[string]RateLimitConfig{}},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}
