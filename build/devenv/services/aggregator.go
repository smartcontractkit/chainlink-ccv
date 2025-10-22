package services

import (
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/go-connections/nat"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/smartcontractkit/chainlink-testing-framework/framework"
)

const (
	DefaultAggregatorName  = "aggregator"
	DefaultAggregatorImage = "aggregator:dev"
	DefaultAggregatorPort  = 8103

	// Redis constants.
	DefaultAggregatorRedisName  = "aggregator-redis"
	DefaultAggregatorRedisImage = "redis:7-alpine"
	DefaultAggregatorRedisPort  = 6379

	// PostgreSQL constants.
	DefaultAggregatorDBName  = "aggregator-db"
	DefaultAggregatorDBPort  = 7432
	DefaultAggregatorSQLInit = "init.sql"

	DefaultAggregatorDBImage = "postgres:16-alpine"
)

var DefaultAggregatorDBConnectionString = fmt.Sprintf("postgresql://%s:%s@%s:5432/%s?sslmode=disable",
	DefaultAggregatorName, DefaultAggregatorName, DefaultAggregatorDBName, DefaultAggregatorName)

type AggregatorDBInput struct {
	Image string `toml:"image"`
}

type AggregatorEnvConfig struct {
	StorageConnectionURL string `toml:"storage_connection_url"`
	RedisAddress         string `toml:"redis_address"`
	RedisPassword        string `toml:"redis_password"`
	RedisDB              string `toml:"redis_db"`
	APIKeysJSON          string `toml:"api_keys_json"`
}

type AggregatorInput struct {
	Image          string               `toml:"image"`
	Port           int                  `toml:"port"`
	SourceCodePath string               `toml:"source_code_path"`
	RootPath       string               `toml:"root_path"`
	DB             *DBInput             `toml:"db"`
	ContainerName  string               `toml:"container_name"`
	UseCache       bool                 `toml:"use_cache"`
	Out            *AggregatorOutput    `toml:"-"`
	Env            *AggregatorEnvConfig `toml:"env"`
}

type DynamoDBTablesConfig struct {
	CommitVerificationRecords string `toml:"commit_verification_records"`
	AggregatedReports         string `toml:"aggregated_reports"`
	Checkpoints               string `toml:"checkpoints"`
}

type AggregatorOutput struct {
	UseCache           bool   `toml:"use_cache"`
	ContainerName      string `toml:"container_name"`
	Address            string `toml:"address"`
	DBURL              string `toml:"db_url"`
	DBConnectionString string `toml:"db_connection_string"`
}

type Signer struct {
	ParticipantID string   `toml:"participantID"`
	Addresses     []string `toml:"addresses"`
}

// QuorumConfig represents the configuration for a quorum of signers.
type QuorumConfig struct {
	CommitteeVerifierAddress string   `toml:"committeeVerifierAddress"`
	Signers                  []Signer `toml:"signers"`
	Threshold                uint8    `toml:"threshold"`
}

// Committee represents a group of signers participating in the commit verification process.
type Committee struct {
	// QuorumConfigs stores a QuorumConfig for each chain selector
	// there is a commit verifier for.
	// The aggregator uses this to verify signatures from each chain's
	// commit verifier set.
	QuorumConfigs           map[string]*QuorumConfig `toml:"quorumConfigs"`
	SourceVerifierAddresses map[string]string        `toml:"sourceVerifierAddresses"`
}

// StorageConfig represents the configuration for the storage backend.
type StorageConfig struct {
	StorageType   string `toml:"type"`
	ConnectionURL string `toml:"connectionURL,omitempty"`
}

// ServerConfig represents the configuration for the server.
type ServerConfig struct {
	Address string `toml:"address"`
}

func aggregatorDefaults(in *AggregatorInput) {
	if in.Image == "" {
		in.Image = DefaultAggregatorImage
	}
	if in.Port == 0 {
		in.Port = DefaultAggregatorPort
	}
	if in.ContainerName == "" {
		in.ContainerName = DefaultAggregatorName
	}
	if in.DB == nil {
		in.DB = &DBInput{
			Image: DefaultAggregatorDBImage,
		}
	}
}

func NewAggregator(in *AggregatorInput) (*AggregatorOutput, error) {
	if in == nil {
		return nil, nil
	}
	if in.Out != nil && in.Out.UseCache {
		return in.Out, nil
	}
	ctx := context.Background()
	aggregatorDefaults(in)
	p, err := CwdSourcePath(in.SourceCodePath)
	if err != nil {
		return in.Out, err
	}

	/* Database */
	_, err = postgres.Run(ctx,
		in.DB.Image,
		postgres.WithDatabase(DefaultAggregatorName),
		postgres.WithUsername(DefaultAggregatorName),
		postgres.WithPassword(DefaultAggregatorName),
		postgres.WithInitScripts(filepath.Join(p, DefaultAggregatorSQLInit)),
		testcontainers.CustomizeRequest(testcontainers.GenericContainerRequest{
			ContainerRequest: testcontainers.ContainerRequest{
				Name:         DefaultAggregatorDBName,
				ExposedPorts: []string{"5432/tcp"},
				Networks:     []string{framework.DefaultNetworkName},
				NetworkAliases: map[string][]string{
					framework.DefaultNetworkName: {DefaultAggregatorDBName},
				},
				Labels: framework.DefaultTCLabels(),
				HostConfigModifier: func(h *container.HostConfig) {
					h.PortBindings = nat.PortMap{
						"5432/tcp": []nat.PortBinding{
							{HostPort: strconv.Itoa(DefaultAggregatorDBPort)},
						},
					}
				},
			},
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create Postgres container: %w", err)
	}

	// Allow some time for DynamoDB Local to initialize
	time.Sleep(5 * time.Second)

	// Create Redis container for rate limiting
	redisReq := testcontainers.ContainerRequest{
		Image:        DefaultAggregatorRedisImage,
		Name:         DefaultAggregatorRedisName,
		ExposedPorts: []string{"6379/tcp"},
		Networks:     []string{framework.DefaultNetworkName},
		NetworkAliases: map[string][]string{
			framework.DefaultNetworkName: {DefaultAggregatorRedisName},
		},
		Labels: framework.DefaultTCLabels(),
		HostConfigModifier: func(h *container.HostConfig) {
			h.PortBindings = nat.PortMap{
				"6379/tcp": []nat.PortBinding{
					{HostPort: strconv.Itoa(DefaultAggregatorRedisPort)},
				},
			}
		},
		WaitingFor: wait.ForLog("Ready to accept connections"),
	}

	_, err = testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: redisReq,
		Started:          true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create Redis container: %w", err)
	}

	// Build environment variables from config
	envVars := make(map[string]string)

	if in.Env != nil {
		// Use explicit configuration from env.toml
		if in.Env.StorageConnectionURL == "" {
			return nil, fmt.Errorf("AGGREGATOR_STORAGE_CONNECTION_URL is required in env config")
		}
		envVars["AGGREGATOR_STORAGE_CONNECTION_URL"] = in.Env.StorageConnectionURL

		if in.Env.APIKeysJSON == "" {
			return nil, fmt.Errorf("AGGREGATOR_API_KEYS_JSON is required in env config")
		}
		envVars["AGGREGATOR_API_KEYS_JSON"] = in.Env.APIKeysJSON

		if in.Env.RedisAddress == "" {
			return nil, fmt.Errorf("AGGREGATOR_REDIS_ADDRESS is required in env config")
		}
		envVars["AGGREGATOR_REDIS_ADDRESS"] = in.Env.RedisAddress

		envVars["AGGREGATOR_REDIS_PASSWORD"] = in.Env.RedisPassword
		envVars["AGGREGATOR_REDIS_DB"] = in.Env.RedisDB
	} else {
		// Inject default environment variables for testing
		envVars["AGGREGATOR_STORAGE_CONNECTION_URL"] = DefaultAggregatorDBConnectionString
		envVars["AGGREGATOR_REDIS_ADDRESS"] = fmt.Sprintf("%s:%d", DefaultAggregatorRedisName, DefaultAggregatorRedisPort)
		envVars["AGGREGATOR_REDIS_PASSWORD"] = ""
		envVars["AGGREGATOR_REDIS_DB"] = "0"
		// Minimal API keys for testing
		envVars["AGGREGATOR_API_KEYS_JSON"] = `{"clients":{"test-key":{"clientId":"test","enabled":true,"groups":[],"secrets":{"primary":"test-secret"}}}}`
	}

	/* Service */
	req := testcontainers.ContainerRequest{
		Image:    in.Image,
		Name:     in.ContainerName,
		Labels:   framework.DefaultTCLabels(),
		Networks: []string{framework.DefaultNetworkName},
		NetworkAliases: map[string][]string{
			framework.DefaultNetworkName: {in.ContainerName},
		},
		Env: envVars,
		// add more internal ports here with /tcp suffix, ex.: 9222/tcp
		ExposedPorts: []string{"50051/tcp", "8080/tcp"},
		HostConfigModifier: func(h *container.HostConfig) {
			h.PortBindings = nat.PortMap{
				// add more internal/external pairs here, ex.: 9222/tcp as a key and HostPort is the exposed port (no /tcp prefix!)
				"50051/tcp": []nat.PortBinding{
					{HostPort: strconv.Itoa(in.Port)},
				},
			}
		},
		WaitingFor: wait.ForHTTP("/health/live").WithPort("8080/tcp"),
	}

	if in.SourceCodePath != "" {
		req.Mounts = testcontainers.Mounts()
		req.Mounts = append(req.Mounts, GoSourcePathMounts(in.RootPath, AppPathInsideContainer)...)
		req.Mounts = append(req.Mounts, GoCacheMounts()...)
		framework.L.Info().
			Str("Service", in.ContainerName).
			Str("Source", p).Msg("Using source code path, hot-reload mode")
	}

	_, err = testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to start container: %w", err)
	}
	in.Out = &AggregatorOutput{
		ContainerName: in.ContainerName,
		Address:       fmt.Sprintf("%s:%d", in.ContainerName, in.Port),
	}
	return in.Out, nil
}
