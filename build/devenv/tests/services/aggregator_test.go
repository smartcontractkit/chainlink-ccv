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
			APIKeysJSON:   `{"clients":{"test-key":{"clientId":"test","enabled":true,"groups":[],"secrets":{"primary":"test-secret"}}}}`,
		},
	})
	require.NoError(t, err)
	t.Run("test #1", func(t *testing.T) {
		_ = out
		// use the data from output, connect HTTP, gRPC clients etc and do the testing
	})
}
