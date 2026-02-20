package ccv

import (
	"fmt"
	"testing"

	"github.com/Masterminds/semver/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/deployments"
	"github.com/smartcontractkit/chainlink-ccv/devenv/services"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/config"
)

func TestExpandForHA(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Cfg
		assert  func(t *testing.T, cfg *Cfg)
		wantErr string
	}{
		{
			name: "HA disabled is a no-op",
			cfg: Cfg{
				HighAvailability: false,
				Aggregator: []*services.AggregatorInput{
					{
						CommitteeName:        "default",
						HostPort:             50051,
						RedundantAggregators: 2,
						DB:                   &services.AggregatorDBInput{HostPort: 7432},
						Redis:                &services.AggregatorRedisInput{HostPort: 6379},
					},
				},
				Indexer: []*services.IndexerInput{
					{
						Port:              8104,
						RedundantIndexers: 0,
						DB:                &services.DBInput{HostPort: 6432},
					},
				},
			},
			assert: func(t *testing.T, cfg *Cfg) {
				assert.Len(t, cfg.Aggregator, 1, "aggregators should not be expanded")
				assert.Len(t, cfg.Indexer, 1, "indexers should not be expanded")
			},
		},
		{
			name: "single committee single redundant aggregator",
			cfg: buildCfg(
				withAggregator("default", 50051, 7432, 6379, 1),
				withTopologyCommittee("default", "default", true),
				withIndexer(8104, 6432, 0),
				withTopologyIndexerAddresses("http://indexer-1:8100"),
			),
			assert: func(t *testing.T, cfg *Cfg) {
				require.Len(t, cfg.Aggregator, 2)

				orig := cfg.Aggregator[0]
				clone := cfg.Aggregator[1]

				assert.Equal(t, "default", orig.CommitteeName)
				assert.Equal(t, "default-ha-1", clone.Name)
				assert.Equal(t, "default", clone.CommitteeName)
				assert.Equal(t, 50052, clone.HostPort)
				assert.Equal(t, 7433, clone.DB.HostPort)
				assert.Equal(t, 6380, clone.Redis.HostPort)
				assert.Equal(t, orig.Image, clone.Image)
				assert.Equal(t, orig.SourceCodePath, clone.SourceCodePath)

				// Verify topology was updated
				committee := cfg.EnvironmentTopology.NOPTopology.Committees["default"]
				require.Len(t, committee.Aggregators, 2)
				assert.Equal(t, "default", committee.Aggregators[0].Name)
				assert.Equal(t, "default-ha-1", committee.Aggregators[1].Name)
				assert.Equal(t, "default-ha-1-aggregator:50051", committee.Aggregators[1].Address)
				assert.True(t, committee.Aggregators[1].InsecureAggregatorConnection)

				// Verify env config
				assert.Contains(t, clone.Env.StorageConnectionURL, "default-ha-1-aggregator-db")
				assert.Contains(t, clone.Env.RedisAddress, "default-ha-1-aggregator-redis")
			},
		},
		{
			name: "multi committee expansion",
			cfg: buildCfg(
				withAggregator("default", 50051, 7432, 6379, 1),
				withAggregator("secondary", 50052, 7433, 6380, 1),
				withTopologyCommittee("default", "default", true),
				withTopologyCommittee("secondary", "secondary", true),
				withIndexer(8104, 6432, 0),
				withTopologyIndexerAddresses("http://indexer-1:8100"),
			),
			assert: func(t *testing.T, cfg *Cfg) {
				require.Len(t, cfg.Aggregator, 4)

				assert.Equal(t, "default", cfg.Aggregator[0].CommitteeName)
				assert.Equal(t, "secondary", cfg.Aggregator[1].CommitteeName)
				assert.Equal(t, "default-ha-1", cfg.Aggregator[2].Name)
				assert.Equal(t, "secondary-ha-1", cfg.Aggregator[3].Name)

				// Ports should be sequential starting from max+1
				assert.Equal(t, 50053, cfg.Aggregator[2].HostPort)
				assert.Equal(t, 50054, cfg.Aggregator[3].HostPort)
				assert.Equal(t, 7434, cfg.Aggregator[2].DB.HostPort)
				assert.Equal(t, 7435, cfg.Aggregator[3].DB.HostPort)
				assert.Equal(t, 6381, cfg.Aggregator[2].Redis.HostPort)
				assert.Equal(t, 6382, cfg.Aggregator[3].Redis.HostPort)

				// Each committee in topology should have 2 aggregators
				for _, name := range []string{"default", "secondary"} {
					committee := cfg.EnvironmentTopology.NOPTopology.Committees[name]
					assert.Len(t, committee.Aggregators, 2, "committee %s", name)
				}
			},
		},
		{
			name: "mixed redundancy — some committees expanded, some not",
			cfg: buildCfg(
				withAggregator("default", 50051, 7432, 6379, 1),
				withAggregator("secondary", 50052, 7433, 6380, 0),
				withAggregator("tertiary", 50053, 7434, 6381, 2),
				withTopologyCommittee("default", "default", true),
				withTopologyCommittee("secondary", "secondary", true),
				withTopologyCommittee("tertiary", "tertiary", false),
				withIndexer(8104, 6432, 0),
				withTopologyIndexerAddresses("http://indexer-1:8100"),
			),
			assert: func(t *testing.T, cfg *Cfg) {
				// 3 original + 1 (default) + 0 (secondary) + 2 (tertiary) = 6
				require.Len(t, cfg.Aggregator, 6)

				defaultComm := cfg.EnvironmentTopology.NOPTopology.Committees["default"]
				assert.Len(t, defaultComm.Aggregators, 2, "default: 1 orig + 1 clone")

				secondaryComm := cfg.EnvironmentTopology.NOPTopology.Committees["secondary"]
				assert.Len(t, secondaryComm.Aggregators, 1, "secondary: no expansion")

				tertiaryComm := cfg.EnvironmentTopology.NOPTopology.Committees["tertiary"]
				assert.Len(t, tertiaryComm.Aggregators, 3, "tertiary: 1 orig + 2 clones")

				// Verify tertiary clones inherited insecure=false from original topology entry
				assert.False(t, tertiaryComm.Aggregators[1].InsecureAggregatorConnection)
				assert.False(t, tertiaryComm.Aggregators[2].InsecureAggregatorConnection)
			},
		},
		{
			name: "API clients are deep copied",
			cfg: buildCfg(
				withAggregatorWithClients("default", 50051, 7432, 6379, 1,
					[]*services.AggregatorClientConfig{
						{ClientID: "verifier-1", Enabled: true, Groups: []string{"verifiers"},
							APIKeyPairs: []*services.AggregatorAPIKeyPair{{APIKey: "key1", Secret: "sec1"}}},
						{ClientID: "indexer", Enabled: true, Groups: []string{"indexer"}},
					}),
				withTopologyCommittee("default", "default", true),
				withIndexer(8104, 6432, 0),
				withTopologyIndexerAddresses("http://indexer-1:8100"),
			),
			assert: func(t *testing.T, cfg *Cfg) {
				require.Len(t, cfg.Aggregator, 2)
				clone := cfg.Aggregator[1]

				require.Len(t, clone.APIClients, 2)
				assert.Equal(t, "verifier-1", clone.APIClients[0].ClientID)
				assert.Equal(t, "indexer", clone.APIClients[1].ClientID)

				// Mutating the clone's clients must not affect the original
				clone.APIClients[0].ClientID = "mutated"
				assert.Equal(t, "verifier-1", cfg.Aggregator[0].APIClients[0].ClientID)

				clone.APIClients[0].Groups[0] = "mutated"
				assert.Equal(t, "verifiers", cfg.Aggregator[0].APIClients[0].Groups[0])
			},
		},
		{
			name: "indexer expansion with address generation",
			cfg: buildCfg(
				withAggregator("default", 50051, 7432, 6379, 0),
				withTopologyCommittee("default", "default", true),
				withIndexerFull(8104, 6432, 1, "indexer:dev", "../indexer",
					map[string]string{"CV": "default"}),
				withTopologyIndexerAddresses("http://indexer-1:8100"),
			),
			assert: func(t *testing.T, cfg *Cfg) {
				require.Len(t, cfg.Indexer, 2)

				orig := cfg.Indexer[0]
				clone := cfg.Indexer[1]

				assert.Equal(t, 8105, clone.Port)
				assert.Equal(t, 6433, clone.DB.HostPort)
				assert.Equal(t, orig.Image, clone.Image)
				assert.Equal(t, orig.SourceCodePath, clone.SourceCodePath)

				// Qualifier maps should be deep copies
				require.NotNil(t, clone.CommitteeVerifierNameToQualifier)
				assert.Equal(t, "default", clone.CommitteeVerifierNameToQualifier["CV"])
				clone.CommitteeVerifierNameToQualifier["CV"] = "mutated"
				assert.Equal(t, "default", orig.CommitteeVerifierNameToQualifier["CV"])

				// Topology should have 2 indexer addresses
				require.Len(t, cfg.EnvironmentTopology.IndexerAddress, 2)
				assert.Equal(t, "http://indexer-1:8100", cfg.EnvironmentTopology.IndexerAddress[0])
				assert.Equal(t, fmt.Sprintf("http://indexer-2:%d", services.DefaultIndexerInternalPort),
					cfg.EnvironmentTopology.IndexerAddress[1])
			},
		},
		{
			name: "indexer config storage pointers are independent",
			cfg: buildCfg(
				withAggregator("default", 50051, 7432, 6379, 0),
				withTopologyCommittee("default", "default", true),
				withIndexerWithConfig(8104, 6432, 1),
				withTopologyIndexerAddresses("http://indexer-1:8100"),
			),
			assert: func(t *testing.T, cfg *Cfg) {
				require.Len(t, cfg.Indexer, 2)
				orig := cfg.Indexer[0]
				clone := cfg.Indexer[1]

				require.NotNil(t, clone.IndexerConfig)
				require.NotNil(t, clone.IndexerConfig.Storage.Single)
				require.NotNil(t, clone.IndexerConfig.Storage.Single.Postgres)

				// Mutating the clone's postgres URI must not affect the original
				clone.IndexerConfig.Storage.Single.Postgres.URI = "mutated"
				assert.NotEqual(t, "mutated", orig.IndexerConfig.Storage.Single.Postgres.URI)
			},
		},
		{
			name: "port allocation across multiple redundancies",
			cfg: buildCfg(
				withAggregator("default", 50051, 7432, 6379, 2),
				withTopologyCommittee("default", "default", true),
				withIndexer(8104, 6432, 0),
				withTopologyIndexerAddresses("http://indexer-1:8100"),
			),
			assert: func(t *testing.T, cfg *Cfg) {
				require.Len(t, cfg.Aggregator, 3)

				// Verify sequential port allocation
				assert.Equal(t, 50052, cfg.Aggregator[1].HostPort)
				assert.Equal(t, 50053, cfg.Aggregator[2].HostPort)
				assert.Equal(t, 7433, cfg.Aggregator[1].DB.HostPort)
				assert.Equal(t, 7434, cfg.Aggregator[2].DB.HostPort)
				assert.Equal(t, 6380, cfg.Aggregator[1].Redis.HostPort)
				assert.Equal(t, 6381, cfg.Aggregator[2].Redis.HostPort)

				// Verify names
				assert.Equal(t, "default-ha-1", cfg.Aggregator[1].Name)
				assert.Equal(t, "default-ha-2", cfg.Aggregator[2].Name)

				// Topology should have 3 aggregators
				committee := cfg.EnvironmentTopology.NOPTopology.Committees["default"]
				require.Len(t, committee.Aggregators, 3)
			},
		},
		{
			name: "nil topology is safe for aggregator expansion",
			cfg: Cfg{
				HighAvailability: true,
				Aggregator: []*services.AggregatorInput{
					{CommitteeName: "default", RedundantAggregators: 1},
				},
				Indexer: []*services.IndexerInput{
					{Port: 8104, DB: &services.DBInput{HostPort: 6432}},
				},
			},
			assert: func(t *testing.T, cfg *Cfg) {
				assert.Len(t, cfg.Aggregator, 1, "no expansion without topology")
			},
		},
		{
			name: "committee not found in topology returns error",
			cfg: buildCfg(
				withAggregator("nonexistent", 50051, 7432, 6379, 1),
				withTopologyCommittee("default", "default", true),
				withIndexer(8104, 6432, 0),
				withTopologyIndexerAddresses("http://indexer-1:8100"),
			),
			wantErr: `committee "nonexistent" not found in topology`,
		},
		{
			name: "aggregator with custom Name uses Name for clone prefix",
			cfg: func() Cfg {
				c := buildCfg(
					withTopologyCommittee("default", "default", true),
					withIndexer(8104, 6432, 0),
					withTopologyIndexerAddresses("http://indexer-1:8100"),
				)
				c.Aggregator = []*services.AggregatorInput{
					{
						Name:                 "my-agg",
						CommitteeName:        "default",
						HostPort:             50051,
						RedundantAggregators: 1,
						DB:                   &services.AggregatorDBInput{Image: "pg", HostPort: 7432},
						Redis:                &services.AggregatorRedisInput{Image: "redis", HostPort: 6379},
						Env:                  &services.AggregatorEnvConfig{RedisDB: "0"},
					},
				}
				return c
			}(),
			assert: func(t *testing.T, cfg *Cfg) {
				require.Len(t, cfg.Aggregator, 2)
				assert.Equal(t, "my-agg-ha-1", cfg.Aggregator[1].Name)
			},
		},
		{
			name: "indexer expansion without topology does not panic",
			cfg: Cfg{
				HighAvailability: true,
				Indexer: []*services.IndexerInput{
					{Port: 8104, RedundantIndexers: 1, DB: &services.DBInput{HostPort: 6432}},
				},
			},
			assert: func(t *testing.T, cfg *Cfg) {
				assert.Len(t, cfg.Indexer, 2, "should still expand indexers")
			},
		},
		{
			name: "multiple indexers with different redundancies",
			cfg: buildCfg(
				withAggregator("default", 50051, 7432, 6379, 0),
				withTopologyCommittee("default", "default", true),
				withIndexer(8104, 6432, 2),
				withIndexer(8105, 6433, 1),
				withTopologyIndexerAddresses("http://indexer-1:8100", "http://indexer-2:8100"),
			),
			assert: func(t *testing.T, cfg *Cfg) {
				// 2 original + 2 + 1 = 5
				require.Len(t, cfg.Indexer, 5)

				// Ports should be sequential from max (8105) + 1
				assert.Equal(t, 8106, cfg.Indexer[2].Port)
				assert.Equal(t, 8107, cfg.Indexer[3].Port)
				assert.Equal(t, 8108, cfg.Indexer[4].Port)

				// DB ports sequential from max (6433) + 1
				assert.Equal(t, 6434, cfg.Indexer[2].DB.HostPort)
				assert.Equal(t, 6435, cfg.Indexer[3].DB.HostPort)
				assert.Equal(t, 6436, cfg.Indexer[4].DB.HostPort)

				// Topology should have 5 indexer addresses
				require.Len(t, cfg.EnvironmentTopology.IndexerAddress, 5)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.cfg
			err := cfg.expandForHA()
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			if tt.assert != nil {
				tt.assert(t, &cfg)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test helpers – functional options to build a Cfg for table-driven tests.
// ---------------------------------------------------------------------------

type cfgOption func(*Cfg)

func buildCfg(opts ...cfgOption) Cfg {
	c := Cfg{
		HighAvailability: true,
		EnvironmentTopology: &deployments.EnvironmentTopology{
			NOPTopology: &deployments.NOPTopology{
				NOPs: []deployments.NOPConfig{
					{Alias: "nop-1", Name: "nop-1"},
				},
				Committees: make(map[string]deployments.CommitteeConfig),
			},
		},
	}
	for _, opt := range opts {
		opt(&c)
	}
	return c
}

func withAggregator(committee string, hostPort, dbPort, redisPort, redundancy int) cfgOption {
	return func(c *Cfg) {
		c.Aggregator = append(c.Aggregator, &services.AggregatorInput{
			Image:                "aggregator:dev",
			CommitteeName:        committee,
			HostPort:             hostPort,
			SourceCodePath:       "../aggregator",
			RootPath:             "../../",
			RedundantAggregators: redundancy,
			DB:                   &services.AggregatorDBInput{Image: "postgres:16-alpine", HostPort: dbPort},
			Redis:                &services.AggregatorRedisInput{Image: "redis:7-alpine", HostPort: redisPort},
			Env:                  &services.AggregatorEnvConfig{RedisDB: "0"},
		})
	}
}

func withAggregatorWithClients(committee string, hostPort, dbPort, redisPort, redundancy int, clients []*services.AggregatorClientConfig) cfgOption {
	return func(c *Cfg) {
		c.Aggregator = append(c.Aggregator, &services.AggregatorInput{
			Image:                "aggregator:dev",
			CommitteeName:        committee,
			HostPort:             hostPort,
			SourceCodePath:       "../aggregator",
			RootPath:             "../../",
			RedundantAggregators: redundancy,
			DB:                   &services.AggregatorDBInput{Image: "postgres:16-alpine", HostPort: dbPort},
			Redis:                &services.AggregatorRedisInput{Image: "redis:7-alpine", HostPort: redisPort},
			Env:                  &services.AggregatorEnvConfig{RedisDB: "0"},
			APIClients:           clients,
		})
	}
}

func withTopologyCommittee(name, qualifier string, insecure bool) cfgOption {
	return func(c *Cfg) {
		c.EnvironmentTopology.NOPTopology.Committees[name] = deployments.CommitteeConfig{
			Qualifier:       qualifier,
			VerifierVersion: semver.MustParse("1.7.0"),
			Aggregators: []deployments.AggregatorConfig{
				{
					Name:                         "default",
					Address:                      fmt.Sprintf("%s-aggregator:50051", name),
					InsecureAggregatorConnection: insecure,
				},
			},
			ChainConfigs: map[string]deployments.ChainCommitteeConfig{
				"3379446385462418246": {
					NOPAliases: []string{"nop-1"},
					Threshold:  1,
				},
			},
		}
	}
}

func withIndexer(port, dbPort, redundancy int) cfgOption {
	return func(c *Cfg) {
		c.Indexer = append(c.Indexer, &services.IndexerInput{
			Image:             "indexer:dev",
			Port:              port,
			SourceCodePath:    "../indexer",
			RootPath:          "../../",
			RedundantIndexers: redundancy,
			DB:                &services.DBInput{Image: "postgres:16-alpine", HostPort: dbPort},
		})
	}
}

func withIndexerFull(port, dbPort, redundancy int, image, srcPath string, qualifiers map[string]string) cfgOption {
	return func(c *Cfg) {
		c.Indexer = append(c.Indexer, &services.IndexerInput{
			Image:                            image,
			Port:                             port,
			SourceCodePath:                   srcPath,
			RootPath:                         "../../",
			RedundantIndexers:                redundancy,
			DB:                               &services.DBInput{Image: "postgres:16-alpine", HostPort: dbPort},
			CommitteeVerifierNameToQualifier: qualifiers,
		})
	}
}

func withIndexerWithConfig(port, dbPort, redundancy int) cfgOption {
	return func(c *Cfg) {
		c.Indexer = append(c.Indexer, &services.IndexerInput{
			Image:             "indexer:dev",
			Port:              port,
			RedundantIndexers: redundancy,
			DB:                &services.DBInput{Image: "postgres:16-alpine", HostPort: dbPort},
			IndexerConfig: &config.Config{
				Storage: config.StorageConfig{
					Strategy: config.StorageStrategySingle,
					Single: &config.SingleStorageConfig{
						Type: config.StorageBackendTypePostgres,
						Postgres: &config.PostgresConfig{
							URI: "postgresql://orig:orig@orig-db:5432/orig",
						},
					},
				},
			},
		})
	}
}

func withTopologyIndexerAddresses(addrs ...string) cfgOption {
	return func(c *Cfg) {
		c.EnvironmentTopology.IndexerAddress = addrs
	}
}
