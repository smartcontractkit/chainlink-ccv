package services

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/go-connections/nat"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/smartcontractkit/chainlink-testing-framework/framework"
)

const (
	AggregatorContainerNameSuffix = "aggregator"

	// Redis constants.
	AggregatorRedisContainerNameSuffix = "aggregator-redis"
	DefaultRedisContainerPort          = "6379/tcp"

	// PostgreSQL constants.
	AggregatorDBContainerNameSuffix = "aggregator-db"
	DefaultAggregatorDBUsername     = "aggregator"
	DefaultAggregatorDBPassword     = "aggregator"
	DefaultAggregatorDBName         = "aggregator"
	DefaultDBContainerPort          = "5432/tcp"
	DefaultAggregatorSQLInit        = "init.sql"
)

type AggregatorDBInput struct {
	Image string `toml:"image"`
	// HostPort is the port on the host machine that the database will be exposed on.
	// This should be unique across all containers.
	HostPort int `toml:"host_port"`
}

type AggregatorRedisInput struct {
	Image string `toml:"image"`
	// HostPort is the port on the host machine that the redis will be exposed on.
	// This should be unique across all containers.
	HostPort int `toml:"host_port"`
}

type AggregatorEnvConfig struct {
	StorageConnectionURL string `toml:"storage_connection_url"`
	RedisAddress         string `toml:"redis_address"`
	RedisPassword        string `toml:"redis_password"`
	RedisDB              string `toml:"redis_db"`
	APIKeysJSON          string `toml:"api_keys_json"`
}

type AggregatorInput struct {
	Image string `toml:"image"`
	// HostPort is the port on the host machine that the aggregator will be exposed on.
	// This should be unique across all containers.
	HostPort       int                   `toml:"host_port"`
	SourceCodePath string                `toml:"source_code_path"`
	RootPath       string                `toml:"root_path"`
	DB             *AggregatorDBInput    `toml:"db"`
	Redis          *AggregatorRedisInput `toml:"redis"`
	Out            *AggregatorOutput     `toml:"-"`
	Env            *AggregatorEnvConfig  `toml:"env"`
	CommitteeName  string                `toml:"committee_name"`
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

func validateAggregatorInput(in *AggregatorInput) error {
	if in.Image == "" {
		return fmt.Errorf("image is required for aggregator")
	}
	if in.HostPort == 0 {
		return fmt.Errorf("host port is required for aggregator")
	}
	if in.CommitteeName == "" {
		return fmt.Errorf("committee name is required for aggregator")
	}
	if in.SourceCodePath == "" {
		return fmt.Errorf("source code path is required for aggregator")
	}
	if in.RootPath == "" {
		return fmt.Errorf("root path is required for aggregator")
	}
	if in.DB == nil {
		return fmt.Errorf("explicit database configuration is required for aggregator")
	}
	if in.DB.HostPort == 0 || in.DB.Image == "" {
		return fmt.Errorf("invalid database configuration for aggregator, both of 'host_port' and 'image' must be set, got: %+v", in.DB)
	}
	if in.Redis == nil {
		return fmt.Errorf("explicit Redis configuration is required for aggregator")
	}
	if in.Redis.HostPort == 0 || in.Redis.Image == "" {
		return fmt.Errorf("invalid Redis configuration for aggregator, both of 'host_port' and 'image' must be set, got: %+v", in.Redis)
	}
	if in.Env == nil {
		return fmt.Errorf("explicit environment configuration is required for aggregator")
	}
	if in.Env.StorageConnectionURL == "" {
		return fmt.Errorf("storage connection URL is required for aggregator")
	}
	if in.Env.RedisAddress == "" {
		return fmt.Errorf("redis address is required for aggregator")
	}
	// Note: redis password can be empty.
	if in.Env.RedisDB == "" {
		return fmt.Errorf("redis DB is required for aggregator")
	}
	return nil
}

func NewAggregator(in *AggregatorInput) (*AggregatorOutput, error) {
	if in == nil {
		return nil, nil
	}
	if in.Out != nil && in.Out.UseCache {
		return in.Out, nil
	}
	if err := validateAggregatorInput(in); err != nil {
		return nil, err
	}
	ctx := context.Background()
	p, err := CwdSourcePath(in.SourceCodePath)
	if err != nil {
		return in.Out, err
	}

	// Start the aggregator postgres database container
	_, err = postgres.Run(ctx,
		in.DB.Image,
		// The container name should be scoped by the committee name.
		testcontainers.WithName(fmt.Sprintf("%s-%s", in.CommitteeName, AggregatorDBContainerNameSuffix)),
		// Database names don't have to be, its probably simpler we keep them the same across all containers
		// in case some debugging or some introspection is required.
		postgres.WithDatabase(DefaultAggregatorDBName),
		postgres.WithUsername(DefaultAggregatorDBUsername),
		postgres.WithPassword(DefaultAggregatorDBPassword),
		postgres.WithInitScripts(filepath.Join(p, DefaultAggregatorSQLInit)),
		testcontainers.CustomizeRequest(testcontainers.GenericContainerRequest{
			ContainerRequest: testcontainers.ContainerRequest{
				Name: fmt.Sprintf("%s-%s", in.CommitteeName, AggregatorDBContainerNameSuffix),
				// This is the container port, not the host port, so it can be the same across different containers.
				ExposedPorts: []string{DefaultDBContainerPort},
				Networks:     []string{framework.DefaultNetworkName},
				NetworkAliases: map[string][]string{
					framework.DefaultNetworkName: {fmt.Sprintf("%s-%s", in.CommitteeName, AggregatorDBContainerNameSuffix)},
				},
				Labels: framework.DefaultTCLabels(),
				HostConfigModifier: func(h *container.HostConfig) {
					h.PortBindings = nat.PortMap{
						DefaultDBContainerPort: []nat.PortBinding{
							// The host port must be unique across all containers.
							{HostPort: strconv.Itoa(in.DB.HostPort)},
						},
					}
				},
				WaitingFor: wait.ForLog("database system is ready to accept connections"),
			},
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create Postgres container: %w", err)
	}

	// Start the aggregator redis container for rate limiting
	redisReq := testcontainers.ContainerRequest{
		Image: in.Redis.Image,
		Name:  fmt.Sprintf("%s-%s", in.CommitteeName, AggregatorRedisContainerNameSuffix),
		// This is the container port, not the host port, so it can be the same across different containers.
		ExposedPorts: []string{DefaultRedisContainerPort},
		Networks:     []string{framework.DefaultNetworkName},
		NetworkAliases: map[string][]string{
			framework.DefaultNetworkName: {fmt.Sprintf("%s-%s", in.CommitteeName, AggregatorRedisContainerNameSuffix)},
		},
		Labels: framework.DefaultTCLabels(),
		HostConfigModifier: func(h *container.HostConfig) {
			h.PortBindings = nat.PortMap{
				DefaultRedisContainerPort: []nat.PortBinding{
					// The host port must be unique across all containers.
					{HostPort: strconv.Itoa(in.Redis.HostPort)},
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
	}

	// Start the aggregator container
	aggregatorContainerName := fmt.Sprintf("%s-%s", in.CommitteeName, AggregatorContainerNameSuffix)
	req := testcontainers.ContainerRequest{
		Image:    in.Image,
		Name:     aggregatorContainerName,
		Labels:   framework.DefaultTCLabels(),
		Networks: []string{framework.DefaultNetworkName},
		NetworkAliases: map[string][]string{
			framework.DefaultNetworkName: {aggregatorContainerName},
		},
		Env: envVars,
		// add more internal ports here with /tcp suffix, ex.: 9222/tcp
		ExposedPorts: []string{"50051/tcp", "8080/tcp"},
		HostConfigModifier: func(h *container.HostConfig) {
			h.PortBindings = nat.PortMap{
				// add more internal/external pairs here, ex.: 9222/tcp as a key and HostPort is the exposed port (no /tcp prefix!)
				"50051/tcp": []nat.PortBinding{
					{HostPort: strconv.Itoa(in.HostPort)},
				},
			}
		},
		WaitingFor: wait.ForHTTP("/health/live").WithPort("8080/tcp"),
	}

	if in.SourceCodePath != "" {
		cwd, err := os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("failed to get working directory: %w", err)
		}

		req.Mounts = testcontainers.Mounts()
		req.Mounts = append(req.Mounts, GoSourcePathMounts(in.RootPath, AppPathInsideContainer)...)
		req.Mounts = append(req.Mounts, GoCacheMounts()...)

		// TODO: Generate config file, write it to a local path, and mount it here.
		req.Mounts = append(req.Mounts, testcontainers.BindMount( //nolint:staticcheck // we're still using it...
			filepath.Join(cwd, "configs", "aggregator", in.CommitteeName, "aggregator.toml"),
			// aggregator.DefaultConfigFile,
			"/etc/config.toml",
		))
		framework.L.Info().
			Str("Service", aggregatorContainerName).
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
		ContainerName: aggregatorContainerName,
		Address:       fmt.Sprintf("%s:%d", aggregatorContainerName, in.HostPort),
	}
	return in.Out, nil
}
