package services_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/devenv/services"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/config"
)

func TestServiceIndexer(t *testing.T) {
	out, err := services.NewIndexer(&services.IndexerInput{
		SourceCodePath: "../../../indexer",
		RootPath:       "../../../../",
		IndexerConfig: &config.Config{
			LogLevel: "debug",
			Scheduler: config.SchedulerConfig{
				TickerInterval:               100,
				VerificationVisibilityWindow: 3600,
				BaseDelay:                    100,
				MaxDelay:                     1000,
			},
			Pool: config.PoolConfig{
				ConcurrentWorkers: 5,
				WorkerTimeout:     30,
			},
			Discoveries: []config.DiscoveryConfig{
				{
					AggregatorReaderConfig: config.AggregatorReaderConfig{
						Address:            "aggregator:9090",
						InsecureConnection: true,
					},
					PollInterval: 1000,
					Timeout:      5000,
				},
			},
			Storage: config.StorageConfig{
				Strategy: config.StorageStrategySink,
				Sink: &config.SinkStorageConfig{
					Storages: []config.StorageBackendConfig{
						{Type: config.StorageBackendTypeMemory},
						{
							Type: config.StorageBackendTypePostgres,
							Postgres: &config.PostgresConfig{
								MaxOpenConnections: 10,
								MaxIdleConnections: 5,
							},
						},
					},
				},
			},
		},
		GeneratedCfg: &config.GeneratedConfig{
			Verifier: []config.GeneratedVerifierConfig{
				{Name: "CommiteeVerifier (Primary)", IssuerAddresses: []string{"0x9A676e781A523b5d0C0e43731313A708CB607508"}},
			},
		},
	})
	require.NoError(t, err)
	t.Run("test #1", func(t *testing.T) {
		_ = out
		// use the data from output, connect HTTP, gRPC clients etc and do the testing
	})
}
