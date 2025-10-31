package services_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/devenv/services"
)

func TestServiceAggregator(t *testing.T) {
	out, err := services.NewAggregator(&services.AggregatorInput{
		CommitteeName:  "default",
		Image:          "aggregator:dev",
		HostPort:       8103,
		SourceCodePath: "../../../aggregator",
		RootPath:       "../../../../",
		DB: &services.AggregatorDBInput{
			Image:    "postgres:16-alpine",
			HostPort: 7432,
		},
		Redis: &services.AggregatorRedisInput{
			Image:    "redis:7-alpine",
			HostPort: 6379,
		},
		Env: &services.AggregatorEnvConfig{
			StorageConnectionURL: fmt.Sprintf("postgresql://%s:%s@default-aggregator-db:5432/%s?sslmode=disable",
				services.DefaultAggregatorDBUsername,
				services.DefaultAggregatorDBPassword,
				services.DefaultAggregatorDBName,
			),
			RedisAddress:  "default-aggregator-redis:6379",
			RedisPassword: "",
			RedisDB:       "0",
			Clients: map[string]services.ClientCredentials{
				"verifier_1": {
					KeyPairEnvVars: []services.ClientEnvVarPair{
						{
							APIKeyEnv:   "AGGREGATOR_VERIFIER_1_API_KEY",
							SecretEnv:   "AGGREGATOR_VERIFIER_1_SECRET",
							APIKeyValue: "dev-api-key-verifier-1",
							SecretValue: "dev-secret-verifier-1",
						},
					},
				},
				"verifier_2": {
					KeyPairEnvVars: []services.ClientEnvVarPair{
						{
							APIKeyEnv:   "AGGREGATOR_VERIFIER_2_API_KEY",
							SecretEnv:   "AGGREGATOR_VERIFIER_2_SECRET",
							APIKeyValue: "dev-api-key-verifier-2",
							SecretValue: "dev-secret-verifier-2",
						},
					},
				},
				"monitoring": {
					KeyPairEnvVars: []services.ClientEnvVarPair{
						{
							APIKeyEnv:   "AGGREGATOR_MONITORING_API_KEY",
							SecretEnv:   "AGGREGATOR_MONITORING_SECRET",
							APIKeyValue: "dev-monitoring-api-key",
							SecretValue: "dev-monitoring-secret",
						},
					},
				},
			},
		},
	})
	require.NoError(t, err)
	t.Run("test #1", func(t *testing.T) {
		_ = out
		// use the data from output, connect HTTP, gRPC clients etc and do the testing
	})
}
