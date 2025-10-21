package services_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/devenv/services"
)

func TestServiceAggregator(t *testing.T) {
	out, err := services.NewAggregator(&services.AggregatorInput{
		SourceCodePath: "../../../aggregator",
		RootPath:       "../../../../",
		Env: &services.AggregatorEnvConfig{
			StorageConnectionURL: "postgresql://aggregator:aggregator@aggregator-db:5432/aggregator?sslmode=disable",
			RedisAddress:         "aggregator-redis:6379",
			RedisPassword:        "",
			RedisDB:              "0",
			APIKeysJSON: `{
  "clients": {
    "test-api-key": {
      "clientId": "test-client",
      "description": "Test client",
      "enabled": true,
      "groups": ["verifiers"],
      "secrets": {
        "primary": "test-secret"
      }
    }
  }
}`,
		},
	})
	require.NoError(t, err)
	t.Run("test #1", func(t *testing.T) {
		_ = out
		// use the data from output, connect HTTP, gRPC clients etc and do the testing
	})
}
